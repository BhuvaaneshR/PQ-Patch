"""Planner: turn one detector finding into a replacement plan, or an escalation (M4).

The model sees the finding, the imports and the enclosing scope of the flagged call, all
framed as untrusted data (see ``prompts.py``). It answers with either a ``Plan``
(ML-DSA replacement for a signing call) or an escalation (key exchange, encryption, or
unclear). Anything else is rejected by ``PlanReply`` before a human sees it.

The planner never writes patch code; that is M5. A human approves or rejects the plan
(M7/M9); on rejection ``plan_finding`` is called again with their feedback.

Human feedback is passed to the model as trusted text, so it is length-limited but not
redacted: it is meant to be followed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .llm_client import (
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_REFUSED,
    StructuredLLM,
)
from .prompts import build_messages
from .schemas import ALLOWED_TARGETS, Finding, Plan, PlanReply
from .source_text import import_lines, split_lines, strip_eol

DEFAULT_TARGET = "ML-DSA-65"
MAX_FEEDBACK_CHARS = 2000
MAX_SCOPE_CHARS = 12_000
MAX_IMPORT_CHARS = 3_000
CONTEXT_LINES = 40  # kept either side of the call when a scope is clipped


class PlanOutcome(str, Enum):
    PLANNED = "planned"
    ESCALATED = "escalated"
    INVALID_OUTPUT = "invalid_output"
    REFUSED = "refused"
    ERROR = "error"


@dataclass(frozen=True)
class PlanResult:
    outcome: PlanOutcome
    plan: Optional[Plan] = None
    reason: Optional[str] = None  # escalation reason, or why the model call failed
    calls: int = 0  # model calls made


# --------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------


def _scope_text(finding: Finding, lines: list[str]) -> tuple[str, int]:
    """(code of the enclosing scope, first line number shown). Clipped around the call if huge."""
    start, end = finding.scope_start_line, finding.scope_end_line
    text = "\n".join(lines[start - 1 : end])
    if len(text) <= MAX_SCOPE_CHARS:
        return text, start
    a = max(start, finding.line - CONTEXT_LINES)
    b = min(end, finding.end_line + CONTEXT_LINES)
    clipped = "\n".join(lines[a - 1 : b])
    head = "# [earlier lines of this scope omitted]\n" if a > start else ""
    tail = "\n# [later lines of this scope omitted]" if b < end else ""
    return (head + clipped + tail)[:MAX_SCOPE_CHARS], a


# --------------------------------------------------------------------------
# Prompt
# --------------------------------------------------------------------------


def _task(finding: Finding, first_line: int, feedback: Optional[str]) -> str:
    targets = ", ".join(sorted(ALLOWED_TARGETS))
    scope = finding.enclosing_scope or "module level code"
    task = (
        "Plan the post-quantum replacement for one flagged cryptographic call.\n\n"
        "Background: a deterministic scanner flagged a call that uses RSA or elliptic-curve "
        "signatures, which a quantum computer could break. The only replacement allowed is the NIST "
        f"ML-DSA signature scheme (FIPS 204). Allowed targets: {targets}. Use {DEFAULT_TARGET} unless "
        "the code gives a reason to pick another. Assume the replacement uses the liboqs Python "
        'bindings: `import oqs`, then `oqs.Signature("<target>")` with its generate_keypair, sign and '
        "verify methods. Do not plan around any other library.\n\n"
        f"Flagged call: `{finding.original_call}` ({finding.algorithm.value} family), resolved as "
        f"{finding.qualified_name}.\n"
        f"Location: line {finding.line} of the file, inside {scope}. The scope code below starts at "
        f"line {first_line}.\n\n"
        "First decide how the key or call is used:\n"
        "- Digital signing or verifying: write a plan.\n"
        "- Anything else (key exchange, key agreement, encryption, or you cannot tell from the code "
        "shown): do not write a plan. Explain why in an escalation.\n\n"
        "For a plan, describe in plain words which ML-DSA API replaces which call and how keys and "
        "signatures are held, and how the surrounding function signature or interface stays the same. "
        "Keys held in variables or parameters become raw `bytes` after the move (ML-DSA keys are byte "
        "strings), so say in interface_notes how callers must change. If the code cannot be migrated "
        "without knowing what its callers pass, escalate rather than guess. List the risks a reviewer "
        "should check (much larger keys and signatures, changed serialisation, hashing behaviour, other "
        "code or services that expect the old format). Do not write the patched code yet. Do not invent "
        "library functions or algorithm identifiers you are not sure exist; say so in the risks instead.\n\n"
        'Reply as {"plan": {...}} using the plan fields in the schema, or '
        '{"escalate": {"reason": "..."}}.'
    )
    if feedback:
        task += (
            "\n\nThe reviewer rejected the previous plan and asked for changes. Their feedback is "
            f"below. Revise the plan to address it.\nReviewer feedback: {feedback.strip()}"
        )
    return task


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def plan_finding(
    finding: Finding,
    source: str,
    *,
    llm: Optional[StructuredLLM] = None,
    feedback: Optional[str] = None,
    previous_plan: Optional[Plan] = None,
) -> PlanResult:
    """Ask the model for a plan for ``finding``. ``source`` is the whole file the finding is in.

    Pass ``feedback`` (and ``previous_plan``) to revise a plan a human rejected. Provider or
    reply problems come back as a non-planned outcome; ValueError means the caller passed
    inputs that cannot be planned (source does not match the finding, feedback too long).
    """
    lines = [strip_eol(x) for x in split_lines(source)]  # the parser's line numbering, not str.splitlines
    if finding.scope_end_line > len(lines):
        raise ValueError("finding does not match the source: its scope extends past the end of the file")
    if feedback is not None and len(feedback) > MAX_FEEDBACK_CHARS:
        raise ValueError(f"feedback is {len(feedback)} characters; the limit is {MAX_FEEDBACK_CHARS}")

    scope, first_line = _scope_text(finding, lines)
    untrusted = {"imports": import_lines(source, MAX_IMPORT_CHARS), "scope_code": scope}
    if previous_plan is not None:
        untrusted["previous_plan"] = previous_plan.model_dump_json(indent=2)

    messages = build_messages(_task(finding, first_line, feedback), untrusted, PlanReply, "planner.py:plan_finding")
    result = (llm or StructuredLLM()).call(messages, PlanReply, purpose="planner")

    if result.status == STATUS_REFUSED:
        return PlanResult(PlanOutcome.REFUSED, reason=result.error, calls=result.calls)
    if result.status == STATUS_INVALID:
        return PlanResult(PlanOutcome.INVALID_OUTPUT, reason=result.error, calls=result.calls)
    if result.status == STATUS_ERROR:
        return PlanResult(PlanOutcome.ERROR, reason=result.error, calls=result.calls)

    reply = result.value
    assert reply is not None
    if reply.escalate is not None:
        return PlanResult(PlanOutcome.ESCALATED, reason=reply.escalate.reason, calls=result.calls)
    return PlanResult(PlanOutcome.PLANNED, plan=reply.plan, calls=result.calls)
