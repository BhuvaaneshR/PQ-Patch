"""Structured model calls: one place that sends messages, checks the reply, retries, and logs (M3).

All model traffic goes through the repository-root ``client.py`` (which this file never
imports an SDK around), so changing provider is a ``.env`` change only. A reply is accepted
only if it parses as JSON and validates against the Pydantic model the caller supplies.

Every model call, including retries and re-asks, writes one line to ``run_log.jsonl`` via
``observability.log_call`` with exactly one of the four statuses:

    ok              reply parsed and validated
    invalid_output  reply was empty, not JSON, or failed validation (after one re-ask)
    refused         the model declined in prose (never retried or re-asked)
    error           the call raised (after bounded retries)

Retry policy, all bounded so a run ends well inside the course harness's 60 s limit:
- A call that raises is retried up to ``max_error_attempts`` calls in total, sleeping
  ``max(retry_after, base_delay * 2**n)`` (capped at ``max_delay``) in between. Errors that
  will not change on retry (HTTP 400/401/403/404/422) are not retried.
- A reply that fails parsing or validation gets ONE re-ask that quotes the validation error.
- A rate limit (HTTP 429) is read, not just retried (``rate_limit.py``). A short per-minute wait the
  provider asks for is waited out. A daily quota, or a wait longer than ``max_delay``, is NOT retried:
  that model is marked unavailable until the provider says it resets, the call moves on to the next of
  ``LLM_FALLBACK_MODELS`` if there is one, and otherwise ends at once as ``error`` saying when to try again.
- Optional, off unless configured: ``LLM_TPM_LIMIT`` paces calls so the per-minute limit is not hit, and
  ``LLM_CACHE=1`` stores validated replies on disk so a repeated run costs no tokens (cache hits make no
  model call and write no ``run_log.jsonl`` line).

Nothing secret or large is logged: no API key, prompt or reply text, only counts and timings.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, Optional, Sequence, Type, TypeVar

from pydantic import BaseModel, ValidationError

import client as _client
import observability
import security

from .rate_limit import (
    Pacer,
    ReplyCache,
    classify,
    describe_wait,
    fallback_models_from_env,
    retry_after as _retry_after,
    status_code as _status_code,
)

T = TypeVar("T", bound=BaseModel)

STATUS_OK = "ok"
STATUS_INVALID = "invalid_output"
STATUS_REFUSED = "refused"
STATUS_ERROR = "error"

DEFAULT_TIMEOUT = 30.0  # seconds for one model call
DEFAULT_MAX_RETRY_DELAY = 5.0
_NON_RETRYABLE = frozenset({400, 401, 403, 404, 422})
_REASK_ECHO_CHARS = 1500
EXPECTED_COMPLETION_TOKENS = 1200  # what the pacer assumes a reply will cost before the real count is known

_REFUSAL = re.compile(
    r"\bI(?:'m| am)\s+(?:sorry|unable|not able)\b|\bI\s+(?:can(?:'|no)t|cannot|won't|will not)\b|\bI(?:'m| am) not able to\b",
    re.IGNORECASE,
)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class LLMResult(Generic[T]):
    """Outcome of one ``call``. ``value`` is set only when ``status`` is ``ok``."""

    status: str
    value: Optional[T]
    error: Optional[str]
    calls: int  # model calls made, retries and the re-ask included (0 for a cached reply)
    cached: bool = False  # the reply came from the on-disk cache, not from a model call
    model: Optional[str] = None  # the model that produced a good reply


# --------------------------------------------------------------------------
# Reply handling
# --------------------------------------------------------------------------


def extract_json(text: str) -> Any:
    """Parse a JSON value from a reply, tolerating code fences and a chatty lead-in.

    Raises ValueError if nothing parseable is found. Trailing commas and other near-JSON
    are NOT repaired: a malformed reply is a malformed reply.
    """
    text = text.strip()
    if not text:
        raise ValueError("empty reply")
    candidates = [text]
    fenced = _FENCE.search(text)
    if fenced:
        candidates.append(fenced.group(1).strip())
    first = min((i for i in (text.find("{"), text.find("[")) if i != -1), default=-1)
    if first != -1:
        candidates.append(text[first:])
    decoder = json.JSONDecoder()
    last: Optional[Exception] = None
    for candidate in candidates:
        try:
            return decoder.raw_decode(candidate)[0]
        except json.JSONDecodeError as e:
            last = e
    raise ValueError(f"not valid JSON: {last}")


def _brief(err: ValidationError) -> str:
    """Field paths and messages only; never the offending input."""
    parts = []
    for e in err.errors(include_input=False, include_url=False)[:5]:
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        parts.append(f"{loc}: {e['msg']}")
    return "; ".join(parts)


def _interpret(text: str, refusal_flag: bool, model_cls: Type[T]) -> tuple[str, Optional[T], Optional[str]]:
    """(status, value, error) for a reply."""
    if refusal_flag:
        return STATUS_REFUSED, None, "the model refused"
    try:
        data = extract_json(text)
    except ValueError as e:
        if "{" not in text and "[" not in text and _REFUSAL.search(text):
            return STATUS_REFUSED, None, "the model refused"
        return STATUS_INVALID, None, str(e)
    try:
        return STATUS_OK, model_cls.model_validate(data), None
    except ValidationError as e:
        return STATUS_INVALID, None, _brief(e)


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


def _default_max_delay() -> float:
    """Longest wait between retries. 5 s keeps stub runs fast; set LLM_MAX_RETRY_DELAY=60 for a
    real provider whose free tier rate-limits per minute and asks callers to wait."""
    try:
        return max(0.0, float(os.getenv("LLM_MAX_RETRY_DELAY", "")))
    except ValueError:
        return DEFAULT_MAX_RETRY_DELAY


def _prompt_text(messages: Sequence[dict]) -> str:
    return "\n".join(str(m.get("content", "")) for m in messages)


class StructuredLLM:
    """Send messages, get back a validated Pydantic object or a typed failure.

    ``client_factory``, ``sleep``, ``clock`` and ``log_path`` exist so tests can run without a
    network or real delays; production code uses the defaults. ``fallback_models``, ``pacer`` and
    ``cache`` default to what the environment asks for (``LLM_FALLBACK_MODELS``, ``LLM_TPM_LIMIT``,
    ``LLM_CACHE``), which is nothing unless set. Pass ``cache=None`` to force no cache.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_error_attempts: int = 3,
        max_reasks: int = 1,
        base_delay: float = 0.5,
        max_delay: Optional[float] = None,
        client_factory: Callable[[], Any] = _client.get_client,
        model_name: Callable[[], str] = _client.get_model,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        log_path: Optional[str] = None,
        fallback_models: Optional[Sequence[str]] = None,
        pacer: Any = "auto",
        cache: Any = "auto",
    ) -> None:
        self.timeout = timeout
        self.max_error_attempts = max(1, max_error_attempts)
        self.max_reasks = max(0, max_reasks)
        self.base_delay = base_delay
        self.max_delay = _default_max_delay() if max_delay is None else max_delay
        self._client_factory = client_factory
        self._model_name = model_name
        self._sleep = sleep
        self._clock = clock
        self._log_path = log_path
        self._client: Any = None
        self._fallbacks = list(fallback_models) if fallback_models is not None else fallback_models_from_env()
        self._pacer: Optional[Pacer] = Pacer.from_env(sleep=sleep) if isinstance(pacer, str) else pacer
        self.cache: Optional[ReplyCache] = ReplyCache.from_env() if isinstance(cache, str) else cache
        self._unavailable: dict[str, tuple[float, bool]] = {}  # model -> (usable again at, daily quota?)

    # -- public ---------------------------------------------------------------

    def call(self, messages: Sequence[dict], response_model: Type[T], purpose: str = "") -> LLMResult[T]:
        """Run the call. Never raises for provider or reply problems; they come back as a status."""
        original = [dict(m) for m in messages]
        hit = self._from_cache(original, response_model)
        if hit is not None:
            return hit
        history = list(original)
        calls = errors = reasks = 0
        while True:
            model = self._pick_model()
            if model is None:
                return LLMResult(STATUS_ERROR, None, self._unavailable_message(), calls)
            if self._pacer is not None:
                self._pacer.wait_for(observability.estimate_tokens(_prompt_text(history)) + EXPECTED_COMPLETION_TOKENS)
            calls += 1
            reply = self._request(history, model)
            if reply.exception is not None:
                self._log(STATUS_ERROR, history, None, reply, purpose, calls)
                limit = classify(reply.exception)
                if limit is not None and (limit.daily or limit.wait > self.max_delay):
                    # Waiting would not help (or is longer than we are willing to wait): stop using this model.
                    self._unavailable[model] = (self._clock() + limit.wait, limit.daily)
                    if self._pick_model() is not None:
                        continue  # another configured model still has quota: no sleep, not a retry
                    return LLMResult(STATUS_ERROR, None, self._unavailable_message(), calls)
                errors += 1
                code = _status_code(reply.exception)
                brief = f"{type(reply.exception).__name__}: {str(reply.exception)[:200]}"
                if code in _NON_RETRYABLE or errors >= self.max_error_attempts:
                    return LLMResult(STATUS_ERROR, None, brief, calls)
                self._sleep(self._delay(errors, reply.exception))
                continue

            if self._pacer is not None:
                spent = (reply.prompt_tokens or 0) + (reply.completion_tokens or 0)
                self._pacer.record(spent or EXPECTED_COMPLETION_TOKENS)
            status, value, err = _interpret(reply.text, reply.refused, response_model)
            self._log(status, history, reply.text, reply, purpose, calls)
            if status == STATUS_OK:
                if self.cache is not None:
                    self.cache.put(ReplyCache.key(model, original), reply.text, model)
                return LLMResult(STATUS_OK, value, None, calls, model=model)
            if status == STATUS_REFUSED:
                return LLMResult(STATUS_REFUSED, None, err, calls)

            security.log_event(
                security.GUARDRAIL_OUTPUT, where="llm_client.py:call", detail=f"reply rejected ({purpose or 'call'}): {err}"[:300]
            )
            if reasks >= self.max_reasks:
                return LLMResult(STATUS_INVALID, None, err, calls)
            reasks += 1
            history = [
                *history,
                {"role": "assistant", "content": reply.text[:_REASK_ECHO_CHARS]},
                {
                    "role": "user",
                    "content": f"That reply was rejected: {err}. Reply again with exactly one JSON object that matches the schema.",
                },
            ]

    # -- models and quota ------------------------------------------------------------

    def models(self) -> list[str]:
        """The configured model first, then the fallbacks, without repeats."""
        ordered = [self._model_name(), *self._fallbacks]
        return [m for i, m in enumerate(ordered) if m and m not in ordered[:i]]

    def _pick_model(self) -> Optional[str]:
        now = self._clock()
        for m in self.models():
            if self._unavailable.get(m, (0.0, False))[0] <= now:
                return m
        return None

    def has_quota(self) -> bool:
        """False while every configured model is rate limited (a call would fail without being sent)."""
        return self._pick_model() is not None

    def unavailable_models(self) -> list[tuple[str, float, bool]]:
        """(model, seconds until it may be called again, daily quota?) for each model that is rate limited now."""
        now = self._clock()
        return [(m, until - now, daily) for m, (until, daily) in self._unavailable.items() if until > now]

    def _unavailable_message(self) -> str:
        now = self._clock()
        waits = [(until - now, daily, m) for m, (until, daily) in self._unavailable.items() if until > now]
        if not waits:
            return "no model is available"
        soonest, daily, model = min(waits)
        which = f"{model} is" if len(self.models()) == 1 else f"all {len(self.models())} configured models are"
        kind = "daily quota" if daily else "rate limit"
        return f"rate limited: {which} out of its {kind}; the provider allows another call in about {describe_wait(soonest)}"

    def _from_cache(self, messages: Sequence[dict], response_model: Type[T]) -> Optional[LLMResult[T]]:
        if self.cache is None:
            return None
        for model in self.models():
            text = self.cache.get(ReplyCache.key(model, messages))
            if text is None:
                continue
            status, value, _ = _interpret(text, False, response_model)
            if status == STATUS_OK:  # a stale entry that no longer validates is ignored, not trusted
                self.cache.hits += 1
                return LLMResult(STATUS_OK, value, None, 0, cached=True, model=model)
        return None

    # -- internals ---------------------------------------------------------------

    def _delay(self, attempt: int, exc: BaseException) -> float:
        return min(self.max_delay, max(_retry_after(exc), self.base_delay * 2 ** (attempt - 1)))

    def _request(self, messages: Sequence[dict], model: str) -> "_Reply":
        reply = _Reply(model=model)
        started = time.perf_counter()
        try:
            if self._client is None:
                client = self._client_factory()
                # The OpenAI SDK quietly retries 429/5xx itself, which would hide calls from the
                # run log. Turn that off so that one log line is one call.
                with_options = getattr(client, "with_options", None)
                self._client = with_options(max_retries=0) if callable(with_options) else client
            response = self._client.chat.completions.create(
                model=reply.model,
                messages=list(messages),
                response_format={"type": "json_object"},
                temperature=0,
                timeout=self.timeout,
            )
            choice = response.choices[0]
            message = choice.message
            reply.text = message.content or ""
            reply.refused = bool(getattr(message, "refusal", None)) or getattr(choice, "finish_reason", None) == "content_filter"
            usage = getattr(response, "usage", None)
            if usage is not None and getattr(usage, "prompt_tokens", None) is not None:
                reply.prompt_tokens = usage.prompt_tokens
                reply.completion_tokens = usage.completion_tokens
        except Exception as e:  # provider/network failures of any kind are data here
            reply.exception = e
        finally:
            reply.latency_ms = int((time.perf_counter() - started) * 1000)
        return reply

    def _log(self, status: str, messages: Sequence[dict], text: Optional[str], reply: "_Reply", purpose: str, call_no: int) -> None:
        estimated = False
        prompt_tokens, completion_tokens = reply.prompt_tokens, reply.completion_tokens
        if reply.exception is None and prompt_tokens is None:
            prompt_tokens = observability.estimate_tokens(_prompt_text(messages))
            completion_tokens = observability.estimate_tokens(text or "")
            estimated = True
        observability.log_call(
            status,
            reply.model,
            prompt_tokens,
            completion_tokens,
            reply.latency_ms,
            observability.estimate_cost(prompt_tokens, completion_tokens),
            tokens_estimated=estimated,
            path=self._log_path or observability.LOG_PATH,
            purpose=purpose,
            call=call_no,
        )


@dataclass
class _Reply:
    model: str
    text: str = ""
    refused: bool = False
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_ms: int = 0
    exception: Optional[BaseException] = None
