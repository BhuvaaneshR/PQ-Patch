"""Coping with a provider that limits tokens: classify 429s, pace calls, remember replies.

A free tier limits tokens per minute (TPM) and per day (TPD), per model. The cure for each differs,
so ``llm_client`` uses three small tools from here:

* ``classify`` reads a 429 and says whether it is a per-minute limit (worth waiting out) or a daily one
  (waiting is pointless; use another model or stop at once), and how long the provider asked us to wait.
* ``Pacer`` keeps a rolling one-minute count of tokens sent and sleeps BEFORE a call that would pass
  ``LLM_TPM_LIMIT``, so the 429 never happens.
* ``ReplyCache`` stores validated replies on disk (``LLM_CACHE=1``) so repeating a run, re-opening the UI
  or re-running a demo costs no tokens. Only replies that already passed validation are stored, and a
  cached reply is validated again when read, so the cache can never smuggle in a reply the schema rejects.

Everything is opt-in through environment variables, so tests and the course stub behave as before.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

_DAILY = re.compile(r"per\s+day|\bTPD\b|\bRPD\b|\bdaily\b", re.IGNORECASE)
_TRY_AGAIN = re.compile(r"try again in\s+((?:\d+(?:\.\d+)?\s*(?:ms|h|m|s)\s*)+)", re.IGNORECASE)
_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|h|m|s)", re.IGNORECASE)
_UNIT_SECONDS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}

UNKNOWN_DAILY_WAIT = 3600.0  # when a daily limit does not say when it resets


# --------------------------------------------------------------------------
# Reading a provider error
# --------------------------------------------------------------------------


def status_code(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


def parse_wait(text: str) -> Optional[float]:
    """Seconds from a message such as 'Please try again in 8m22.5s' or '... in 450ms'. None if absent."""
    match = _TRY_AGAIN.search(text or "")
    if not match:
        return None
    return sum(float(n) * _UNIT_SECONDS[u.lower()] for n, u in _PART.findall(match.group(1)))


def retry_after(exc: BaseException) -> float:
    """Seconds the provider asked us to wait: attribute, ``retry-after`` header, or the message text."""
    value = getattr(exc, "retry_after", None)
    if value is None:
        headers = getattr(getattr(exc, "response", None), "headers", None)
        try:
            value = headers.get("retry-after") if headers is not None else None
        except Exception:  # headers can be any mapping-like object
            value = None
    try:
        if value is not None:
            return max(0.0, float(value))
    except (TypeError, ValueError):
        pass
    return parse_wait(str(exc)) or 0.0


@dataclass(frozen=True)
class RateLimitInfo:
    daily: bool  # a daily quota: waiting a minute will not help
    wait: float  # seconds until the provider says we may call again (a guess for daily limits)


def classify(exc: BaseException) -> Optional[RateLimitInfo]:
    """None unless ``exc`` is a rate-limit error (HTTP 429 or a ``RateLimit...`` exception type)."""
    if status_code(exc) != 429 and "RateLimit" not in type(exc).__name__:
        return None
    daily = bool(_DAILY.search(str(exc)))
    wait = retry_after(exc)
    if daily and wait <= 0:
        wait = UNKNOWN_DAILY_WAIT
    return RateLimitInfo(daily=daily, wait=wait)


def describe_wait(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    return f"{seconds / 3600:.1f}h"


# --------------------------------------------------------------------------
# Pacing: stay under tokens-per-minute instead of hitting the 429
# --------------------------------------------------------------------------


class Pacer:
    """Sleep before a call that would push the last 60 seconds of tokens over ``tokens_per_minute``."""

    WINDOW = 60.0

    def __init__(
        self,
        tokens_per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.limit = max(0, int(tokens_per_minute))
        self._clock, self._sleep = clock, sleep
        self._sent: deque[tuple[float, int]] = deque()

    @classmethod
    def from_env(cls, **kw: Any) -> Optional["Pacer"]:
        try:
            limit = int(os.getenv("LLM_TPM_LIMIT", "0"))
        except ValueError:
            return None
        return cls(limit, **kw) if limit > 0 else None

    def _trim(self, now: float) -> int:
        while self._sent and now - self._sent[0][0] >= self.WINDOW:
            self._sent.popleft()
        return sum(n for _, n in self._sent)

    def wait_for(self, tokens: int) -> float:
        """Sleep until ``tokens`` more fit in the window; returns the seconds slept."""
        slept = 0.0
        if tokens >= self.limit:  # a single call larger than the budget can never fit: do not stall forever
            return slept
        while True:
            now = self._clock()
            used = self._trim(now)
            if used + tokens <= self.limit or not self._sent:
                return slept
            pause = max(0.05, self.WINDOW - (now - self._sent[0][0]))
            self._sleep(pause)
            slept += pause

    def record(self, tokens: int) -> None:
        self._sent.append((self._clock(), max(0, int(tokens))))


# --------------------------------------------------------------------------
# Reply cache
# --------------------------------------------------------------------------


class ReplyCache:
    """Validated model replies on disk, keyed by a hash of (model, messages). The prompt is not stored."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.hits = 0

    @classmethod
    def from_env(cls) -> Optional["ReplyCache"]:
        """A cache only when ``LLM_CACHE`` is 1/true/on, and never for the offline course stub."""
        if os.getenv("LLM_CACHE", "").strip().lower() not in {"1", "true", "on", "yes"}:
            return None
        if os.getenv("LLM_BASE_URL", "").startswith("local://"):
            return None
        return cls(os.getenv("LLM_CACHE_DIR") or ".llm_cache")

    @staticmethod
    def key(model: str, messages: Sequence[dict]) -> str:
        blob = json.dumps([model, [[m.get("role"), m.get("content")] for m in messages]], ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def get(self, key: str) -> Optional[str]:
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
            text = data["text"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return text if isinstance(text, str) else None

    def put(self, key: str, text: str, model: str) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            tmp = self._path(key).with_suffix(".tmp")
            tmp.write_text(json.dumps({"model": model, "text": text}), encoding="utf-8")
            os.replace(tmp, self._path(key))
        except OSError:
            pass  # a cache that cannot be written is a cache miss next time, never a failure

    def clear(self) -> int:
        """Delete every stored reply; returns how many."""
        count = 0
        for path in self.directory.glob("*.json") if self.directory.exists() else []:
            try:
                path.unlink()
                count += 1
            except OSError:
                pass
        return count


def fallback_models_from_env() -> list[str]:
    """``LLM_FALLBACK_MODELS=model-a,model-b``: models to try, in order, when the main one is out of quota."""
    return [m.strip() for m in os.getenv("LLM_FALLBACK_MODELS", "").split(",") if m.strip()]
