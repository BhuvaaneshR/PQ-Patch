"""Orchestrator: the deterministic state machine that runs detect -> plan -> patch -> verify (M7).

No model decides what happens next. Each finding is a ``FindingRecord`` in one ``State``; code moves it
along the table in ``_ALLOWED`` and nothing else can. Two kinds of state:

* automatic states (DETECTED, PLANNING, PATCHING, VERIFYING) are worked off by ``Session.run_pending``;
* waiting states (AWAITING_PLAN_APPROVAL, AWAITING_FAILURE_DECISION) change only when a person calls
  ``Session.act``. There is no action that skips the plan checkpoint: the only way from
  AWAITING_PLAN_APPROVAL to PATCHING is ``Action.APPROVE_PLAN``.

            DETECTED -> PLANNING -> AWAITING_PLAN_APPROVAL -> PATCHING -> VERIFYING -> READY_FOR_REVIEW
                            |  ^            |   ^                |           |
                            v  |            v   |                v           v
                         ESCALATED     (revise plan)     AWAITING_FAILURE_DECISION -> retry / revise / escalate

The session never writes the input file. READY_FOR_REVIEW means "a verified diff exists and a person
still has to read it", not "applied".

Limits, all enforced here and not by the model: 3 patch attempts per finding, 3 plan revisions, feedback of at
most 2,000 characters, a test timeout of at most 300 s on a re-verify.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional, Union

from .detector import scan_source
from .llm_client import StructuredLLM
from .patcher import PatchOutcome, PatchResult, patch_finding
from .planner import PlanOutcome, PlanResult, plan_finding
from .schemas import (
    Finding,
    FindingStatus,
    Plan,
    ReportRow,
    VerificationOutcome,
    VerificationResult,
)
from .verifier import DEFAULT_TEST_TIMEOUT, verify

MAX_INPUT_BYTES = 256 * 1024
MAX_FEEDBACK_CHARS = 2000
MAX_ATTEMPTS = 3
MAX_PLAN_REVISIONS = 3
MAX_TEST_TIMEOUT = 300.0
MAX_DETAIL_CHARS = 4000

RUN_OK = "ok"  # run status of a model step that returned a usable reply


class State(str, Enum):
    DETECTED = "detected"
    PLANNING = "planning"
    AWAITING_PLAN_APPROVAL = "awaiting_plan_approval"
    PATCHING = "patching"
    VERIFYING = "verifying"
    READY_FOR_REVIEW = "ready_for_review"
    AWAITING_FAILURE_DECISION = "awaiting_failure_decision"
    ESCALATED = "escalated"


AUTOMATIC = frozenset({State.DETECTED, State.PLANNING, State.PATCHING, State.VERIFYING})
WAITING = frozenset({State.AWAITING_PLAN_APPROVAL, State.AWAITING_FAILURE_DECISION})

_ALLOWED: dict[State, frozenset[State]] = {
    State.DETECTED: frozenset({State.PLANNING, State.ESCALATED}),
    State.PLANNING: frozenset({State.AWAITING_PLAN_APPROVAL, State.AWAITING_FAILURE_DECISION, State.ESCALATED}),
    State.AWAITING_PLAN_APPROVAL: frozenset({State.PATCHING, State.PLANNING, State.ESCALATED}),
    State.PATCHING: frozenset({State.VERIFYING, State.AWAITING_FAILURE_DECISION, State.ESCALATED}),
    State.VERIFYING: frozenset({State.READY_FOR_REVIEW, State.AWAITING_FAILURE_DECISION, State.ESCALATED}),
    State.AWAITING_FAILURE_DECISION: frozenset({State.PLANNING, State.PATCHING, State.VERIFYING, State.ESCALATED}),
    State.READY_FOR_REVIEW: frozenset({State.PATCHING, State.PLANNING, State.ESCALATED}),
    State.ESCALATED: frozenset(),
}


class Action(str, Enum):
    """What a person can do. Each is only valid in some states (see ``Session.allowed_actions``)."""

    APPROVE_PLAN = "approve_plan"
    REVISE_PLAN = "revise_plan"  # needs feedback
    RETRY = "retry"  # draft the patch again (or repeat the failed model step); feedback optional
    REVERIFY = "reverify"  # run the checks again on the same patch, optionally with a longer test timeout
    ESCALATE = "escalate"  # give up on automation for this finding


class ActionNotAllowed(ValueError):
    """The action is not valid for the finding's current state, or a limit has been reached."""


class InputRejected(ValueError):
    """The input file cannot be used; nothing was sent to a model."""


@dataclass(frozen=True)
class Failure:
    stage: str  # plan | patch | verify
    kind: str  # invalid_output | refused | error | failed_compile | failed_test | ...
    detail: str


@dataclass(frozen=True)
class Event:
    time: str
    from_state: Optional[State]
    to_state: State
    why: str


@dataclass(frozen=True)
class Attempt:
    """One drafted patch and what the checks said about it."""

    number: int
    diff: str
    verification: Optional[VerificationOutcome]
    output: str


@dataclass
class FindingRecord:
    id: int
    finding: Finding
    state: State = State.DETECTED
    plan: Optional[Plan] = None
    patch_result: Optional[PatchResult] = None
    verification: Optional[VerificationResult] = None
    attempts: int = 0  # patches drafted and sent to the verifier
    plan_revisions: int = 0
    failure: Optional[Failure] = None
    escalation_reason: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    history: list[Event] = field(default_factory=list)
    attempt_log: list[Attempt] = field(default_factory=list)
    model_calls: int = 0
    cached_replies: int = 0
    run_status: Optional[str] = None  # status of this finding's most recent model step
    feedback: Optional[str] = None  # reviewer text for the next model step
    test_timeout: float = DEFAULT_TEST_TIMEOUT


# --------------------------------------------------------------------------
# Input
# --------------------------------------------------------------------------


def read_input(path: Union[str, Path]) -> str:
    """Return the source text of ``path`` or raise ``InputRejected`` saying why. Makes no model call."""
    p = Path(path)
    if p.suffix.lower() != ".py":
        raise InputRejected(f"{p.name}: not a .py file")
    try:
        raw = p.read_bytes()
    except OSError as e:
        raise InputRejected(f"{p.name}: cannot be read ({e.strerror or e})") from None
    return check_source(raw, p.name)


def check_source(data: Union[bytes, str], name: str = "input") -> str:
    """The same checks for text that did not come from a path (an upload)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if not raw.strip():
        raise InputRejected(f"{name}: the file is empty")
    if len(raw) > MAX_INPUT_BYTES:
        raise InputRejected(f"{name}: {len(raw):,} bytes is over the {MAX_INPUT_BYTES:,}-byte limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputRejected(f"{name}: not valid UTF-8 text") from None
    try:
        ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        where = f" (line {e.lineno})" if isinstance(e, SyntaxError) and e.lineno else ""
        raise InputRejected(f"{name}: not valid Python{where}: {getattr(e, 'msg', e)}") from None
    return text


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clip(text: str, limit: int = MAX_DETAIL_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------


class Session:
    """All findings of one file, and the rules for moving them along.

    ``plan_fn``, ``patch_fn`` and ``verify_fn`` default to the real stages; tests and the course stub run
    pass their own. ``llm`` is shared by the two model stages.
    """

    def __init__(
        self,
        file: Union[str, Path],
        source: str,
        *,
        llm: Optional[StructuredLLM] = None,
        project_root: Union[str, Path, None] = None,
        display_name: Optional[str] = None,
        max_attempts: int = MAX_ATTEMPTS,
        max_plan_revisions: int = MAX_PLAN_REVISIONS,
        plan_fn: Callable[..., PlanResult] = plan_finding,
        patch_fn: Callable[..., PatchResult] = patch_finding,
        verify_fn: Callable[..., VerificationResult] = verify,
    ) -> None:
        self.file = str(file)
        self.source = source
        self.display_name = display_name or self.file.replace("\\", "/")
        self.project_root = Path(project_root) if project_root else None
        self.max_attempts = max_attempts
        self.max_plan_revisions = max_plan_revisions
        self._llm = llm
        self._plan_fn, self._patch_fn, self._verify_fn = plan_fn, patch_fn, verify_fn
        self.run_status: Optional[str] = None  # status of the last model step, for the whole session
        self.scan_error: Optional[str] = None

        scan = scan_source(source, self.file)
        if not scan.parse_ok:
            self.scan_error = scan.parse_error
        self.records: list[FindingRecord] = []
        for number, f in enumerate(scan.findings, start=1):
            rec = FindingRecord(id=number, finding=f)
            rec.history.append(Event(_now(), None, State.DETECTED, "found by the detector"))
            self.records.append(rec)
        self._note_shared_scopes()

    @classmethod
    def from_file(cls, path: Union[str, Path], **kw) -> "Session":
        """Read and validate ``path`` (raises ``InputRejected``), then detect."""
        return cls(path, read_input(path), **kw)

    def _note_shared_scopes(self) -> None:
        by_scope: dict[tuple[int, int], list[FindingRecord]] = {}
        for rec in self.records:
            by_scope.setdefault((rec.finding.scope_start_line, rec.finding.scope_end_line), []).append(rec)
        for group in by_scope.values():
            if len(group) > 1:
                ids = ", ".join(f"#{r.id}" for r in group)
                for rec in group:
                    rec.notes.append(
                        f"findings {ids} share one enclosing scope; each patch rewrites that whole scope from the original, "
                        "so review them together and apply only one of their diffs"
                    )

    # -- reading state ----------------------------------------------------------------

    def get(self, finding_id: int) -> FindingRecord:
        for rec in self.records:
            if rec.id == finding_id:
                return rec
        raise KeyError(f"no finding #{finding_id}")

    @property
    def model_calls(self) -> int:
        return sum(r.model_calls for r in self.records)

    @property
    def cached_replies(self) -> int:
        return sum(r.cached_replies for r in self.records)

    @property
    def waiting(self) -> list[FindingRecord]:
        return [r for r in self.records if r.state in WAITING]

    @property
    def done(self) -> bool:
        """Nothing left to run automatically and nobody left to wait for."""
        return all(r.state in (State.READY_FOR_REVIEW, State.ESCALATED) for r in self.records)

    def allowed_actions(self, finding_id: int) -> list[Action]:
        rec = self.get(finding_id)
        s = rec.state
        out: list[Action] = []
        if s is State.AWAITING_PLAN_APPROVAL:
            out.append(Action.APPROVE_PLAN)
            if rec.plan_revisions < self.max_plan_revisions:
                out.append(Action.REVISE_PLAN)
        elif s is State.AWAITING_FAILURE_DECISION and rec.failure is not None:
            if rec.failure.stage == "verify":
                out.append(Action.REVERIFY)
            if rec.failure.stage != "verify" or rec.attempts < self.max_attempts:
                out.append(Action.RETRY)
            if rec.plan is not None and rec.plan_revisions < self.max_plan_revisions:
                out.append(Action.REVISE_PLAN)
        elif s is State.READY_FOR_REVIEW:
            if rec.attempts < self.max_attempts:
                out.append(Action.RETRY)
            if rec.plan_revisions < self.max_plan_revisions:
                out.append(Action.REVISE_PLAN)
        if s is not State.ESCALATED:
            out.append(Action.ESCALATE)
        return out

    # -- moving ---------------------------------------------------------------------------

    def _move(self, rec: FindingRecord, to: State, why: str) -> None:
        if to not in _ALLOWED[rec.state]:
            raise RuntimeError(f"finding #{rec.id}: {rec.state.value} -> {to.value} is not a legal transition")
        rec.history.append(Event(_now(), rec.state, to, why))
        rec.state = to

    def _escalate(self, rec: FindingRecord, reason: str) -> None:
        rec.escalation_reason = reason
        self._move(rec, State.ESCALATED, reason)

    def act(self, finding_id: int, action: Action, *, feedback: Optional[str] = None, test_timeout: Optional[float] = None) -> FindingRecord:
        """Apply a person's decision. It changes the state only; ``run_pending`` does the work that follows."""
        rec = self.get(finding_id)
        action = Action(action)
        if action not in self.allowed_actions(finding_id):
            why = f"{action.value} is not available while the finding is {rec.state.value}"
            if action in (Action.RETRY, Action.REVISE_PLAN) and rec.state is not State.ESCALATED:
                why += f" (attempts {rec.attempts}/{self.max_attempts}, plan revisions {rec.plan_revisions}/{self.max_plan_revisions})"
            raise ActionNotAllowed(why)
        text = (feedback or "").strip() or None
        if text and len(text) > MAX_FEEDBACK_CHARS:
            raise ValueError(f"feedback is {len(text)} characters; the limit is {MAX_FEEDBACK_CHARS}")

        if action is Action.APPROVE_PLAN:
            rec.feedback = None
            self._move(rec, State.PATCHING, "plan approved by the reviewer")
        elif action is Action.REVISE_PLAN:
            if not text:
                raise ActionNotAllowed("revise_plan needs feedback saying what to change")
            rec.plan_revisions += 1
            rec.feedback = text
            rec.failure = None
            rec.patch_result = rec.verification = None  # a new plan makes the old patch moot
            self._move(rec, State.PLANNING, f"plan revision {rec.plan_revisions} requested: {_clip(text, 120)}")
        elif action is Action.RETRY:
            if rec.state is State.READY_FOR_REVIEW and not text:
                raise ActionNotAllowed("retry from ready_for_review needs feedback saying what to change")
            rec.feedback = text
            stage = rec.failure.stage if rec.failure else "patch"
            if stage == "plan":
                self._move(rec, State.PLANNING, "retry of the planning step")
            else:
                self._move(rec, State.PATCHING, "retry: draft the patch again" + (f" ({_clip(text, 120)})" if text else ""))
        elif action is Action.REVERIFY:
            timeout = DEFAULT_TEST_TIMEOUT if test_timeout is None else float(test_timeout)
            if not 0 < timeout <= MAX_TEST_TIMEOUT:
                raise ValueError(f"test_timeout must be between 0 and {MAX_TEST_TIMEOUT:.0f} seconds")
            rec.test_timeout = timeout
            self._move(rec, State.VERIFYING, f"checks repeated on the same patch (test timeout {timeout:.0f}s)")
        elif action is Action.ESCALATE:
            self._escalate(rec, text or "escalated by the reviewer")
        return rec

    # -- doing the work ---------------------------------------------------------------------------

    def run_pending(self, *, stop_on_model_failure: bool = False, only: Optional[Iterable[int]] = None) -> None:
        """Work findings forward until each is waiting for a person or settled.

        With ``stop_on_model_failure`` the first model step that ends in anything but ``ok`` ends the run
        (the findings after it are left untouched), which is what the command line promises. ``only``
        limits the work to those finding ids, so a UI can spend model calls on one finding at a time.
        """
        wanted = None if only is None else set(only)
        for rec in self.records:
            if wanted is not None and rec.id not in wanted:
                continue
            guard = 0
            while rec.state in AUTOMATIC:
                guard += 1
                if guard > 20:  # unreachable unless a transition is mis-written; never loop forever
                    raise RuntimeError(f"finding #{rec.id} did not settle")
                self._step(rec)
                if stop_on_model_failure and rec.run_status not in (None, RUN_OK):
                    return

    def _step(self, rec: FindingRecord) -> None:
        if rec.state is State.DETECTED:
            self._move(rec, State.PLANNING, "planning started")
        elif rec.state is State.PLANNING:
            self._do_plan(rec)
        elif rec.state is State.PATCHING:
            self._do_patch(rec)
        elif rec.state is State.VERIFYING:
            self._do_verify(rec)

    def _count(self, rec: FindingRecord, calls: int) -> None:
        rec.model_calls += calls
        if calls == 0:
            rec.cached_replies += 1

    def _model_status(self, rec: FindingRecord, status: str) -> None:
        rec.run_status = status
        self.run_status = status

    def _do_plan(self, rec: FindingRecord) -> None:
        feedback, previous, rec.feedback = rec.feedback, rec.plan, None
        result = self._plan_fn(rec.finding, self.source, llm=self._llm, feedback=feedback, previous_plan=previous)
        self._count(rec, result.calls)
        if result.outcome is PlanOutcome.PLANNED:
            self._model_status(rec, RUN_OK)
            rec.plan, rec.failure = result.plan, None
            self._move(rec, State.AWAITING_PLAN_APPROVAL, "plan drafted; waiting for the reviewer")
        elif result.outcome is PlanOutcome.ESCALATED:
            self._model_status(rec, RUN_OK)
            self._escalate(rec, result.reason or "the planner could not plan this call")
        else:
            self._model_status(rec, result.outcome.value)
            rec.feedback = feedback  # a retry should still carry the reviewer's words
            rec.failure = Failure("plan", result.outcome.value, _clip(result.reason or ""))
            self._move(rec, State.AWAITING_FAILURE_DECISION, f"planning ended {result.outcome.value}")

    def _do_patch(self, rec: FindingRecord) -> None:
        assert rec.plan is not None, "patching without an approved plan"
        feedback, rec.feedback = rec.feedback, None
        failed = rec.failure.detail if rec.failure and rec.failure.stage == "verify" else None
        previous = rec.patch_result.patch if rec.patch_result else None
        result = self._patch_fn(
            rec.finding, self.source, rec.plan, llm=self._llm, feedback=feedback, previous_patch=previous,
            failure_output=failed, display_name=self.display_name,
        )
        self._count(rec, result.calls)
        if result.outcome is PatchOutcome.PATCHED:
            self._model_status(rec, RUN_OK)
            rec.attempts += 1
            rec.patch_result, rec.failure, rec.verification = result, None, None
            rec.test_timeout = DEFAULT_TEST_TIMEOUT
            self._move(rec, State.VERIFYING, f"patch attempt {rec.attempts} drafted")
        elif result.outcome is PatchOutcome.ESCALATED:
            self._model_status(rec, RUN_OK)
            self._escalate(rec, result.reason or "the patcher could not patch this call")
        else:
            self._model_status(rec, result.outcome.value)
            rec.feedback = feedback
            rec.failure = Failure("patch", result.outcome.value, _clip(result.reason or ""))
            self._move(rec, State.AWAITING_FAILURE_DECISION, f"patching ended {result.outcome.value}")

    def _do_verify(self, rec: FindingRecord) -> None:
        assert rec.patch_result is not None and rec.patch_result.patched_source is not None
        try:
            result = self._verify_fn(
                rec.finding, self.source, rec.patch_result.patched_source,
                project_root=self.project_root, test_timeout=rec.test_timeout,
            )
        except ValueError as e:  # e.g. the file is outside the project root: check what we can, and say so
            result = self._verify_fn(rec.finding, self.source, rec.patch_result.patched_source, project_root=None)
            rec.notes.append(f"the project's tests were not run: {e}")
        rec.verification = result
        known = [a for a in rec.attempt_log if a.number == rec.attempts]
        entry = Attempt(rec.attempts, rec.patch_result.diff or "", result.outcome, result.output)
        if known:
            rec.attempt_log[rec.attempt_log.index(known[0])] = entry  # re-verifying the same patch replaces its verdict
        else:
            rec.attempt_log.append(entry)

        if result.outcome is VerificationOutcome.PASS:
            rec.failure = None
            self._move(rec, State.READY_FOR_REVIEW, "all deterministic checks passed; waiting for a human to read the diff")
        elif rec.attempts >= self.max_attempts and result.outcome is not VerificationOutcome.FAILED_TEST_TIMEOUT:
            self._escalate(rec, f"retry limit reached after {rec.attempts} attempts; last result {result.outcome.value}:\n{_clip(result.output)}")
        else:
            rec.failure = Failure("verify", result.outcome.value, _clip(result.output))
            self._move(rec, State.AWAITING_FAILURE_DECISION, f"verification {result.outcome.value}")

    # -- the report -----------------------------------------------------------------------------

    def report_rows(self) -> list[ReportRow]:
        """One row per finding, or a single ``no_action_needed`` row when nothing was flagged."""
        if not self.records:
            note = f"the file does not parse: {self.scan_error}" if self.scan_error else "no RSA or ECDSA signing calls were found"
            return [ReportRow(file=self.display_name, status=FindingStatus.NO_ACTION_NEEDED, notes=note)]
        return [self._row(rec) for rec in self.records]

    def _row(self, rec: FindingRecord) -> ReportRow:
        f = rec.finding
        base = dict(file=self.display_name, line=f.line, original_call=f.original_call, attempts=rec.attempts)
        target = rec.plan.target_algorithm if rec.plan else None
        diff = rec.patch_result.diff if rec.patch_result else None
        verification = rec.verification.outcome if rec.verification else None
        notes = list(rec.notes)
        if rec.patch_result:
            notes.extend(rec.patch_result.notes)

        if rec.state is State.READY_FOR_REVIEW:
            return ReportRow(
                **base, target_algorithm=target, proposed_patch=diff, verification_result=verification,
                status=FindingStatus.READY_FOR_REVIEW, notes="; ".join(notes),
            )
        if rec.state is State.ESCALATED:
            reason = rec.escalation_reason or "escalated"
        else:
            reason = f"not finished: {rec.state.value.replace('_', ' ')}"
            if rec.failure:
                reason += f" ({rec.failure.stage} step: {rec.failure.kind})"
        if verification is VerificationOutcome.PASS:  # an escalated row cannot carry a pass
            notes.append("the checks had passed before a person escalated this finding")
            verification = None
        return ReportRow(
            **base, target_algorithm=target, proposed_patch=diff, verification_result=verification,
            status=FindingStatus.ESCALATED, notes="; ".join([reason, *notes]),
        )
