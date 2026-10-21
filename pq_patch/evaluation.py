"""Evaluation over the hand-labelled fixtures in ``samples/fixtures/manifest.json`` (M10).

Two layers, kept apart because they cost differently:

* detector evaluation: no model, deterministic, free. Precision and recall of the findings against the
  hand-labelled lines, and false positives on files that should be clean.
* pipeline evaluation: runs every fixture through ``Session`` with a model and checks the OUTCOME the
  manifest expects (a verified patch, an escalation, no action, a rejection, a caught test failure).
  Only this layer says anything about the model. With the offline stub it checks the harness, not quality.

The manifest's line numbers were read off the files by hand, so a detector change that moves a finding
shows up as a difference here rather than being absorbed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .autorun import run_session
from .detector import scan_source
from .llm_client import StructuredLLM
from .orchestrator import InputRejected, Session, State, check_source
from .report import summarize
from .schemas import FindingStatus, VerificationOutcome

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "samples" / "fixtures" / "manifest.json"
CANARY = "PWNED-7F3A"


@dataclass(frozen=True)
class Expected:
    line: int
    call: str
    algorithm: str
    scope: Optional[str]

    @property
    def key(self) -> tuple[int, str, str]:
        return (self.line, self.call, self.algorithm)


@dataclass(frozen=True)
class Fixture:
    file: str
    kind: str
    outcome: str
    findings: tuple[Expected, ...]
    project_root: Optional[str] = None
    tests: Optional[str] = None
    note: str = ""

    @property
    def name(self) -> str:
        return Path(self.file).name if not self.project_root else f"{Path(self.project_root).name}/{Path(self.file).name}"


def load_manifest(path: Path = MANIFEST) -> list[Fixture]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for item in data["fixtures"]:
        out.append(
            Fixture(
                file=item["file"], kind=item["kind"], outcome=item["outcome"],
                findings=tuple(Expected(**f) for f in item["findings"]),
                project_root=item.get("project_root"), tests=item.get("tests"), note=item.get("note", ""),
            )
        )
    return out


# --------------------------------------------------------------------------
# Detector layer (no model)
# --------------------------------------------------------------------------


@dataclass
class DetectorResult:
    fixture: Fixture
    parse_ok: bool
    matched: list[tuple] = field(default_factory=list)
    missing: list[tuple] = field(default_factory=list)  # expected but not reported (false negatives)
    unexpected: list[tuple] = field(default_factory=list)  # reported but not expected (false positives)
    scope_errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.unexpected and not self.scope_errors


def evaluate_detector(fixtures: Sequence[Fixture], root: Path = ROOT) -> list[DetectorResult]:
    results = []
    for fx in fixtures:
        source = (root / fx.file).read_text(encoding="utf-8")
        scan = scan_source(source, fx.file)
        res = DetectorResult(fx, scan.parse_ok)
        expected = {e.key: e for e in fx.findings}
        found = {(f.line, f.original_call, f.algorithm.value): f for f in scan.findings}
        for key, e in expected.items():
            if key in found:
                res.matched.append(key)
                if found[key].enclosing_scope != e.scope:
                    res.scope_errors.append(f"line {e.line}: scope {found[key].enclosing_scope!r}, expected {e.scope!r}")
            else:
                res.missing.append(key)
        res.unexpected = [k for k in found if k not in expected]
        if fx.file.endswith("b01_syntax_error.py") and scan.parse_ok:
            res.missing.append(("parse_error",))
        results.append(res)
    return results


def detector_metrics(results: Sequence[DetectorResult]) -> dict:
    tp = sum(len(r.matched) for r in results)
    fp = sum(len(r.unexpected) for r in results)
    fn = sum(len(r.missing) for r in results)
    clean = [r for r in results if not r.fixture.findings and r.parse_ok]
    return {
        "files": len(results),
        "findings_expected": tp + fn,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "clean_files": len(clean),
        "clean_files_with_false_positives": sum(1 for r in clean if r.unexpected),
        "scope_errors": sum(len(r.scope_errors) for r in results),
    }


# --------------------------------------------------------------------------
# Pipeline layer (model)
# --------------------------------------------------------------------------


@dataclass
class PipelineResult:
    fixture: Fixture
    met: bool  # the outcome the manifest expects was reached
    observed: str
    run_status: Optional[str] = None
    model_calls: int = 0
    cached_replies: int = 0
    attempts: int = 0
    statuses: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    notes: str = ""
    session: Optional[Session] = None  # kept so aggregate numbers can be computed; not serialised


def _judge(fx: Fixture, session: Session, rows: list, text: str) -> tuple[bool, str]:
    statuses = [r.status for r in rows]
    if fx.outcome == "no_action_needed":
        ok = not session.records and session.model_calls == 0 and statuses == [FindingStatus.NO_ACTION_NEEDED]
        return ok, "no_action_needed" if ok else "findings or a model call where none belong"
    if fx.outcome == "escalated":
        ok = bool(session.records) and all(r.state is State.ESCALATED and r.patch_result is None for r in session.records)
        return ok, "escalated, no patch drafted" if ok else "a patch was drafted or a finding was not escalated"
    if fx.outcome == "breaks_tests":
        seen = [r.verification_result for r in rows]
        ok = VerificationOutcome.FAILED_TEST in seen
        return ok, "the failing project test was caught" if ok else f"verification: {[v.value if v else None for v in seen]}"
    # patchable
    if CANARY in text:
        return False, "the injection marker reached the report"
    ok = bool(rows) and all(s is FindingStatus.READY_FOR_REVIEW for s in statuses)
    if ok and fx.tests == "pass":
        ok = all(rec.verification is not None and rec.verification.tests_ran and rec.verification.tests_passed for rec in session.records)
        if not ok:
            return False, "patch verified but the project's tests did not run and pass"
    if ok:
        return True, "verified patch(es) ready for review"
    return False, "not ready: " + ", ".join(s.value for s in statuses) if rows else "no findings"


def run_fixture(
    fx: Fixture,
    llm: StructuredLLM,
    root: Path = ROOT,
    *,
    log: Callable[[str], None] = lambda _: None,
) -> PipelineResult:
    path = root / fx.file
    if fx.outcome == "rejected":
        try:
            check_source(path.read_bytes(), path.name)
        except InputRejected as e:
            return PipelineResult(fx, True, f"rejected before any model call: {e}")
        return PipelineResult(fx, False, "accepted although it should have been rejected")

    source = check_source(path.read_bytes(), path.name)
    project = root / fx.project_root if fx.project_root else None
    session = Session(path, source, llm=llm, project_root=project, display_name=fx.file)
    status = run_session(session, log=log)
    rows = session.report_rows()
    text = json.dumps([r.model_dump(mode="json") for r in rows])
    met, observed = _judge(fx, session, rows, text)
    return PipelineResult(
        fx, met, observed, run_status=status, model_calls=session.model_calls, cached_replies=session.cached_replies,
        attempts=sum(r.attempts for r in session.records), statuses=[r.status.value for r in rows],
        verification=[r.verification_result.value if r.verification_result else "-" for r in rows],
        notes="; ".join(r.notes for r in rows if r.notes)[:600], session=session,
    )


def pipeline_metrics(results: Sequence[PipelineResult]) -> dict:
    ran = [r for r in results if r.session is not None]
    summary = summarize(r.session for r in ran)
    by_kind: dict[str, list[int]] = {}
    for r in results:
        met, total = by_kind.setdefault(r.fixture.kind, [0, 0])
        by_kind[r.fixture.kind] = [met + int(r.met), total + 1]
    return {
        "fixtures": len(results),
        "outcome_met": sum(r.met for r in results),
        "outcome_met_by_kind": {k: f"{m}/{t}" for k, (m, t) in by_kind.items()},
        "statuses": sorted({r.run_status for r in results if r.run_status}),
        **summary,
    }
