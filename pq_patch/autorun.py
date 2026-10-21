"""Drive a ``Session`` without a UI: automatically, or asking a person in the terminal.

Used by ``main.py`` and by the evaluation harness. Two policies:

* automatic (default): every plan is approved, and a failed check is escalated, never retried. This is
  the one place where the plan checkpoint is bypassed, so the command can run unattended; the UI never
  does this.
* ask: a person answers at every plan and at every failure. Closing the terminal (end of input) means
  escalate, never approve.

The run stops at the first model step that ends in anything but ``ok`` and reports that status; findings
not reached are escalated with a note saying they were not attempted.
"""

from __future__ import annotations

import sys
from typing import Callable

from .orchestrator import Action, Session, State

STATUS_OK = "ok"


def _stderr(message: str = "") -> None:
    print(message, file=sys.stderr)


def _ask(prompt: str, choices: str, read: Callable[[str], str]) -> str:
    """Prompt until the answer starts with one of ``choices``; end of input counts as the last choice."""
    while True:
        try:
            answer = read(prompt).strip().lower()
        except EOFError:
            return choices[-1]
        if answer[:1] in choices:
            return answer[:1]


def _approve_or_revise(session: Session, read: Callable[[str], str], log: Callable[[str], None]) -> None:
    for rec in [r for r in session.records if r.state is State.AWAITING_PLAN_APPROVAL]:
        f, plan = rec.finding, rec.plan
        log(f"\n#{rec.id} line {f.line}: {f.original_call} -> {plan.target_algorithm}")
        log(f"  approach: {plan.approach}")
        for risk in plan.risks:
            log(f"  risk: {risk}")
        choice = _ask("  [a]pprove, [r]evise, [e]scalate? ", "are", read)
        if choice == "a":
            session.act(rec.id, Action.APPROVE_PLAN)
        elif choice == "r" and Action.REVISE_PLAN in session.allowed_actions(rec.id):
            session.act(rec.id, Action.REVISE_PLAN, feedback=read("  what should change? ")[:2000] or "please revise")
        else:
            session.act(rec.id, Action.ESCALATE, feedback="escalated by the reviewer at the plan checkpoint")


def _decide_failures(session: Session, ask: bool, read: Callable[[str], str], log: Callable[[str], None]) -> None:
    for rec in [r for r in session.records if r.state is State.AWAITING_FAILURE_DECISION]:
        failure = rec.failure
        log(f"\n#{rec.id} line {rec.finding.line}: {failure.stage} step ended {failure.kind}")
        log("  " + failure.detail.strip().replace("\n", "\n  ")[:600])
        if ask and Action.RETRY in session.allowed_actions(rec.id):
            choice = _ask("  [r]etry with guidance, [e]scalate? ", "re", read)
            if choice == "r":
                session.act(rec.id, Action.RETRY, feedback=read("  guidance (optional): ")[:2000] or None)
                continue
        session.act(rec.id, Action.ESCALATE, feedback=f"needs a person: {failure.stage} step ended {failure.kind}")


def run_session(
    session: Session,
    *,
    ask: bool = False,
    read: Callable[[str], str] = input,
    log: Callable[[str], None] = _stderr,
) -> str:
    """Drive ``session`` until nothing is left to do; returns the run status."""
    for _ in range(50):  # a hard bound: every pass either makes progress or ends the loop
        session.run_pending(stop_on_model_failure=True)
        if session.run_status not in (None, STATUS_OK):
            break
        waiting_plan = [r for r in session.records if r.state is State.AWAITING_PLAN_APPROVAL]
        if waiting_plan:
            if ask:
                _approve_or_revise(session, read, log)
            else:
                for rec in waiting_plan:
                    session.act(rec.id, Action.APPROVE_PLAN)
            continue
        if any(r.state is State.AWAITING_FAILURE_DECISION for r in session.records):
            _decide_failures(session, ask, read, log)
            continue
        if all(r.state in (State.READY_FOR_REVIEW, State.ESCALATED) for r in session.records):
            break
    status = session.run_status or STATUS_OK
    if status != STATUS_OK:  # stopped by a failed model step: say what was and was not done
        for rec in session.records:
            if rec.state is State.AWAITING_FAILURE_DECISION and rec.failure:
                session.act(rec.id, Action.ESCALATE, feedback=f"model step failed ({rec.failure.kind}): {rec.failure.detail}"[:900])
            elif rec.state is State.DETECTED:
                session.act(rec.id, Action.ESCALATE, feedback=f"not attempted: an earlier model step ended {status}")
    return status
