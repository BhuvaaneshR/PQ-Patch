"""
observability.py - how every model call gets written down.

Supplied with Lab 5. You MAY edit this file, and you will have to edit the
two price constants below. You may add fields, helpers and extra functions.
You may NOT rename or remove any of the nine keys that log_call writes,
because the marking script reads them by name.

You must be able to explain every line of this file.

WHAT IT WRITES
    run_log.jsonl in the repository root. One JSON object per line, appended,
    never rewritten. One line per MODEL CALL, not per run. A retry is its own
    line. Lines from the same run of main.py share one run_id.

THE NINE KEYS
    timestamp          string   ISO 8601, UTC
    run_id             string   shared by every call in one run
    model              string   the model name actually used
    status             string   ok | invalid_output | refused | error
    prompt_tokens      int      tokens sent, measured or estimated
    completion_tokens  int      tokens returned, measured or estimated
    latency_ms         int      wall-clock time around the call
    cost_usd           float    computed by you, never reported by a provider
    tokens_estimated   bool     true if the two token counts are your estimate

UNKNOWN IS null, NOT 0
    Zero is a measurement. null is an absence. If a call raised before any
    reply came back, pass None for the token counts and the cost. Do not
    pass 0 to tidy the line up.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Your provider's published prices, in US dollars per MILLION tokens.
#
# Look them up on your provider's pricing page for the model you are actually
# calling. If your free tier publishes no price, use the paid price of the
# same or nearest model and say so in REPORT.md.
#
# Leaving these at 0.0 means every cost you report is 0.0, which answers the
# client's question with a number you did not work for.
# --------------------------------------------------------------------------

PRICE_IN_PER_MTOK = 0.075   # input / prompt tokens
PRICE_OUT_PER_MTOK = 0.30   # output / completion tokens

LOG_PATH = os.getenv("RUN_LOG_PATH", "run_log.jsonl")

# One id per run of the program. Every line written by this process shares it.
RUN_ID = "r-" + uuid.uuid4().hex[:6]


def estimate_tokens(text: str) -> int:
    """Rough token count when the provider does not report one.

    About 4 characters per token. It under-counts JSON, because braces,
    quotes and field names tokenise densely. It is a sanity check, not a
    measurement: anything derived from it is an estimate and must be
    labelled as one.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def estimate_cost(prompt_tokens, completion_tokens) -> float:
    """Cost of one call, from token counts and the prices above.

    Prices are quoted per million tokens, so divide before you multiply.
    Returns None if either count is unknown.
    """
    if prompt_tokens is None or completion_tokens is None:
        return None
    return round(
        prompt_tokens * (PRICE_IN_PER_MTOK / 1_000_000)
        + completion_tokens * (PRICE_OUT_PER_MTOK / 1_000_000),
        8,
    )


def log_call(status, model, prompt_tokens, completion_tokens,
             latency_ms, cost_usd, tokens_estimated=False,
             path=LOG_PATH, **extra):
    """Append one line to run_log.jsonl. Call this once per model call.

    Anything you pass as an extra keyword argument is added to the line.
    Extra fields are welcome. Missing or renamed ones are not.

    Never pass the API key, the full prompt or the full reply.
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": RUN_ID,
        "model": model,
        "status": status,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "latency_ms": latency_ms,
        "cost_usd": cost_usd,
        "tokens_estimated": tokens_estimated,
    }
    record.update(extra)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record


class Timer:
    """Wall-clock time around one call, in milliseconds.

        with Timer() as t:
            response = client.chat.completions.create(...)
        t.ms

    perf_counter, not time.time: it is monotonic, so a clock adjustment
    cannot produce a negative duration. The timer stops even when the call
    raises, which is the case you need for a status of error.
    """

    def __enter__(self):
        self._start = time.perf_counter()
        self.ms = 0
        return self

    def __exit__(self, *exc):
        self.ms = int((time.perf_counter() - self._start) * 1000)
        return False
