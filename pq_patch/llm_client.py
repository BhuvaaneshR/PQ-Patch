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

Nothing secret or large is logged: no API key, prompt or reply text, only counts and timings.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, Optional, Sequence, Type, TypeVar

from pydantic import BaseModel, ValidationError

import client as _client
import observability
import security

T = TypeVar("T", bound=BaseModel)

STATUS_OK = "ok"
STATUS_INVALID = "invalid_output"
STATUS_REFUSED = "refused"
STATUS_ERROR = "error"

DEFAULT_TIMEOUT = 30.0  # seconds for one model call
_NON_RETRYABLE = frozenset({400, 401, 403, 404, 422})
_REASK_ECHO_CHARS = 1500

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
    calls: int  # model calls made, retries and the re-ask included


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


def _status_code(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


def _retry_after(exc: BaseException) -> float:
    value = getattr(exc, "retry_after", None)
    if value is None:
        headers = getattr(getattr(exc, "response", None), "headers", None)
        try:
            value = headers.get("retry-after") if headers is not None else None
        except Exception:  # headers can be any mapping-like object
            value = None
    try:
        return max(0.0, float(value)) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _prompt_text(messages: Sequence[dict]) -> str:
    return "\n".join(str(m.get("content", "")) for m in messages)


class StructuredLLM:
    """Send messages, get back a validated Pydantic object or a typed failure.

    ``client_factory``, ``sleep`` and ``log_path`` exist so tests can run without a
    network or real delays; production code uses the defaults.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_error_attempts: int = 3,
        max_reasks: int = 1,
        base_delay: float = 0.5,
        max_delay: float = 5.0,
        client_factory: Callable[[], Any] = _client.get_client,
        model_name: Callable[[], str] = _client.get_model,
        sleep: Callable[[float], None] = time.sleep,
        log_path: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.max_error_attempts = max(1, max_error_attempts)
        self.max_reasks = max(0, max_reasks)
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._client_factory = client_factory
        self._model_name = model_name
        self._sleep = sleep
        self._log_path = log_path
        self._client: Any = None

    # -- public ---------------------------------------------------------------

    def call(self, messages: Sequence[dict], response_model: Type[T], purpose: str = "") -> LLMResult[T]:
        """Run the call. Never raises for provider or reply problems; they come back as a status."""
        history = [dict(m) for m in messages]
        calls = errors = reasks = 0
        while True:
            calls += 1
            reply = self._request(history)
            if reply.exception is not None:
                errors += 1
                self._log(STATUS_ERROR, history, None, reply, purpose, calls)
                code = _status_code(reply.exception)
                brief = f"{type(reply.exception).__name__}: {str(reply.exception)[:200]}"
                if code in _NON_RETRYABLE or errors >= self.max_error_attempts:
                    return LLMResult(STATUS_ERROR, None, brief, calls)
                self._sleep(self._delay(errors, reply.exception))
                continue

            status, value, err = _interpret(reply.text, reply.refused, response_model)
            self._log(status, history, reply.text, reply, purpose, calls)
            if status == STATUS_OK:
                return LLMResult(STATUS_OK, value, None, calls)
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

    # -- internals ---------------------------------------------------------------

    def _delay(self, attempt: int, exc: BaseException) -> float:
        return min(self.max_delay, max(_retry_after(exc), self.base_delay * 2 ** (attempt - 1)))

    def _request(self, messages: Sequence[dict]) -> "_Reply":
        reply = _Reply(model=self._model_name())
        started = time.perf_counter()
        try:
            if self._client is None:
                self._client = self._client_factory()
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
