"""security.py — the security event log.

Supplied. You may edit it, add fields and add helpers. You may not rename or
remove the five keys, and you may not invent new event names: the marking
script looks for these exact strings.

A guardrail that never writes a line here is, as far as marking is concerned,
a guardrail that never ran. "Present in the file" is not the same as "invoked".

Usage:

    import security

    security.log_event(
        security.GUARDRAIL_INPUT,
        where="guards.py:strip_instructions",
        detail="removed 2 instruction lines from corpus/06_exam_security_handbook.pdf",
    )

Every line lands in security_log.jsonl in the repository root. That file is in
.gitignore and is never committed. You commit samples/security_log_sample.jsonl
instead.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path("security_log.jsonl")

# -- the event vocabulary. These strings are fixed. ------------------------

#: An input guardrail changed or rejected text on its way to the model.
GUARDRAIL_INPUT = "guardrail_input"

#: An output guardrail rejected or scrubbed something on its way back.
GUARDRAIL_OUTPUT = "guardrail_output"

#: An instruction found inside a document was identified and not acted on.
INSTRUCTION_IGNORED = "instruction_ignored"

#: A tool call was refused because its arguments did not validate.
TOOL_ARG_REJECTED = "tool_arg_rejected"

#: A tool returned something that failed validation and was not passed on.
TOOL_RESULT_REJECTED = "tool_result_rejected"

#: A generated question was not stored because it already existed.
DUPLICATE_BLOCKED = "duplicate_blocked"

#: The tool loop hit its documented cap and stopped.
LOOP_CAP_REACHED = "loop_cap_reached"

EVENTS = (
    GUARDRAIL_INPUT,
    GUARDRAIL_OUTPUT,
    INSTRUCTION_IGNORED,
    TOOL_ARG_REJECTED,
    TOOL_RESULT_REJECTED,
    DUPLICATE_BLOCKED,
    LOOP_CAP_REACHED,
)

_RUN_ID = os.environ.get("GAP_RUN_ID") or uuid.uuid4().hex[:12]


def run_id() -> str:
    """One id shared by every event in one run of main.py."""
    return _RUN_ID


def log_event(event: str, where: str, detail: str = "") -> dict:
    """Append one security event. Returns the record it wrote.

    event   one of the constants above
    where   file and function, e.g. "guards.py:strip_instructions"
    detail  what actually happened. No secrets, no full prompts, no full replies.
    """
    if event not in EVENTS:
        raise ValueError(f"Unknown security event {event!r}. Known events: {', '.join(EVENTS)}")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": _RUN_ID,
        "event": event,
        "where": where,
        "detail": str(detail)[:400],
    }
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return record


def read_events(path: Path | str = LOG_PATH) -> list[dict]:
    """Every well-formed event in the log. Bad lines are skipped."""
    path = Path(path)
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
