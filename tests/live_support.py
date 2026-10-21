"""Helpers for the opt-in live tests (``python -m pytest -m live``).

* ``preflight`` makes one tiny call and turns a configuration problem into one clear sentence, so a wrong
  model id costs one short message instead of eight identical failures and minutes of waiting.
* ``build_record`` / ``append_record`` write what each live test saw (plan, patch, verdict, tokens) as one
  JSON line, so a run leaves evidence that can be quoted in EVAL.md and compared with other runs.

Nothing here touches the key: records carry the model name and counts, never credentials, and never the
provider's raw error text beyond a short, truncated description.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pq_patch.rate_limit import classify, describe_wait

PREFLIGHT_MESSAGE = [{"role": "user", "content": "Reply with the single word: ok"}]


def preflight(client: Any, model: str, base_url: str) -> Optional[str]:
    """None if one cheap call succeeds, else a sentence saying what to fix. Never includes the key."""
    try:
        sdk_off = getattr(client, "with_options", None)  # one call means one call: no SDK-level retries
        target = sdk_off(max_retries=0) if callable(sdk_off) else client
        target.chat.completions.create(model=model, messages=PREFLIGHT_MESSAGE, max_tokens=32, temperature=0, timeout=30)
    except Exception as e:  # any failure here is a configuration finding, not a crash
        code = getattr(e, "status_code", None)
        name = type(e).__name__
        if code == 404:
            reason = (
                f"the provider says model {model!r} does not exist or you cannot use it. Check LLM_MODEL in .env: "
                "Groq model ids carry a prefix, for example openai/gpt-oss-120b"
            )
        elif code in (401, 403):
            reason = f"the provider rejected the API key (HTTP {code}). Check LLM_API_KEY in .env"
        elif code == 429:
            limit = classify(e)
            if limit is not None and limit.daily:
                reason = (
                    f"the daily token quota for {model!r} is used up (HTTP 429); the provider allows another call in about "
                    f"{describe_wait(limit.wait)}. Set LLM_FALLBACK_MODELS in .env to use another model meanwhile"
                )
            else:
                reason = "the provider is rate limiting you right now (HTTP 429). Wait a minute, or check your free-tier limits"
        elif "Connection" in name or "Timeout" in name:
            reason = f"cannot reach {base_url!r} ({name}). Check LLM_BASE_URL in .env and your network"
        else:
            reason = f"the provider call failed: {name}: {str(e)[:200]}"
        return f"live tests cannot run: {reason}."
    return None


def usage_from_log(path: Path) -> dict:
    """Totals from one test's run_log.jsonl: calls, tokens, latency, cost and the status of each call."""
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    def total(key: str) -> Optional[float]:
        values = [r[key] for r in rows if r.get(key) is not None]
        return round(sum(values), 8) if values else None

    return {
        "calls": len(rows),
        "statuses": [r.get("status") for r in rows],
        "prompt_tokens": total("prompt_tokens"),
        "completion_tokens": total("completion_tokens"),
        "latency_ms": total("latency_ms"),
        "cost_usd": total("cost_usd"),
        "tokens_estimated": any(r.get("tokens_estimated") for r in rows),
    }


def build_record(test: str, model: str, passed: Optional[bool], failure: Optional[str], usage: dict, data: dict) -> dict:
    return {
        "test": test,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "passed": passed,
        "failure": (failure or "")[:1500] or None,
        "usage": usage,
        **data,
    }


def append_record(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def describe_plan(result: Any) -> dict:
    """What a PlanResult says, as plain data for a record."""
    plan = getattr(result, "plan", None)
    return {
        "outcome": result.outcome.value,
        "calls": result.calls,
        "reason": result.reason,
        "target_algorithm": plan.target_algorithm if plan else None,
        "usage_context": plan.usage_context.value if plan else None,
        "approach": plan.approach if plan else None,
        "interface_notes": plan.interface_notes if plan else None,
        "risks": list(plan.risks) if plan else None,
    }


def describe_patch(result: Any) -> dict:
    """What a PatchResult says, as plain data for a record."""
    return {
        "outcome": result.outcome.value,
        "calls": result.calls,
        "reason": result.reason,
        "problems": list(result.problems),
        "warnings": list(result.warnings),
        "notes": list(result.notes),
        "explanation": result.patch.explanation if result.patch else None,
        "diff": result.diff,
    }


def describe_verification(result: Any) -> dict:
    return {
        "outcome": result.outcome.value,
        "compile_ok": result.compile_ok,
        "detector_clear": result.detector_clear,
        "tests_ran": result.tests_ran,
        "output": result.output,
    }
