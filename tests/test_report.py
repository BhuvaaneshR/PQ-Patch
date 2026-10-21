import csv
import io
import json

import pytest

from pq_patch.orchestrator import Action, Session
from pq_patch.report import (
    COLUMNS,
    diff_name,
    row_dict,
    status_counts,
    summarize,
    to_csv,
    to_json,
    to_jsonl,
    write_report,
)
from pq_patch.schemas import FindingStatus, ReportRow, VerificationOutcome
from scripted_llm import BAD_PATCH, GOOD_PATCH, GOOD_PLAN, ScriptedLLM
from test_orchestrator import SAMPLE, TWO, _write

DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
STORED = DIFF.rstrip("\n")  # ReportRow strips trailing whitespace


def ready_row(**kw):
    base = dict(
        file="src/x.py", line=3, original_call="key.sign", target_algorithm="ML-DSA-65", proposed_patch=DIFF,
        verification_result=VerificationOutcome.PASS, attempts=1, status=FindingStatus.READY_FOR_REVIEW, notes="",
    )
    return ReportRow(**{**base, **kw})


def escalated_row(**kw):
    base = dict(file="src/x.py", line=9, original_call="key.sign", status=FindingStatus.ESCALATED, notes="key exchange")
    return ReportRow(**{**base, **kw})


def test_a_row_has_exactly_the_nine_fields_in_order():
    assert list(row_dict(ready_row())) == list(COLUMNS) and len(COLUMNS) == 9
    assert row_dict(ready_row())["verification_result"] == "pass"


def test_json_round_trips():
    rows = [ready_row(), escalated_row()]
    back = [ReportRow(**d) for d in json.loads(to_json(rows))]
    assert back == rows
    lines = to_jsonl(rows).splitlines()
    assert len(lines) == 2 and json.loads(lines[1])["status"] == "escalated"


def test_csv_has_a_header_and_one_row_per_finding():
    parsed = list(csv.DictReader(io.StringIO(to_csv([ready_row(), escalated_row()]))))
    assert [r["status"] for r in parsed] == ["ready_for_review", "escalated"]
    assert parsed[0]["proposed_patch"] == "'" + STORED and parsed[1]["proposed_patch"] == ""


@pytest.mark.parametrize("text", ["=HYPERLINK(\"http://evil\")", "+1+1", "-2+3", "@SUM(A1)"])
def test_csv_cells_cannot_start_a_formula(text):
    parsed = list(csv.DictReader(io.StringIO(to_csv([escalated_row(notes=text)]))))
    assert parsed[0]["notes"] == "'" + text


def test_a_diff_in_csv_is_protected_because_it_starts_with_dashes():
    cell = list(csv.DictReader(io.StringIO(to_csv([ready_row()]))))[0]["proposed_patch"]
    assert DIFF.startswith("---") and cell == "'" + STORED


def test_write_report_makes_json_csv_and_one_diff_per_patch(tmp_path):
    rows = [ready_row(), ready_row(line=20), escalated_row()]
    written = write_report(rows, tmp_path / "out")
    names = sorted(p.name for p in written)
    assert names == ["report.csv", "report.json", "x.L20.diff", "x.L3.diff"]
    assert (tmp_path / "out" / "x.L3.diff").read_text() == DIFF
    assert json.loads((tmp_path / "out" / "report.json").read_text())[2]["status"] == "escalated"


def test_diff_names_come_from_the_row_not_from_model_text():
    assert diff_name(ready_row(file="../../etc/pass wd.py")) == "pass_wd.L3.diff"
    assert diff_name(ready_row(file="a/b/c.py", line=None, proposed_patch=DIFF)) == "c.diff"


def test_two_files_with_the_same_name_do_not_overwrite_each_other(tmp_path):
    rows = [ready_row(file="a/x.py"), ready_row(file="b/x.py")]
    assert len({p.name for p in write_report(rows, tmp_path) if p.suffix == ".diff"}) == 2


def test_status_counts_cover_every_status():
    assert status_counts([ready_row(), escalated_row()]) == {"ready_for_review": 1, "escalated": 1, "no_action_needed": 0}


def test_summary_counts_a_real_session():
    good = Session.from_file(SAMPLE, llm=ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    good.run_pending()
    good.act(1, Action.APPROVE_PLAN)
    good.run_pending()
    retried = Session.from_file(SAMPLE, llm=ScriptedLLM([GOOD_PLAN], [BAD_PATCH, BAD_PATCH, GOOD_PATCH]))
    retried.run_pending()
    retried.act(1, Action.APPROVE_PLAN)
    retried.run_pending()
    retried.act(1, Action.RETRY)
    retried.run_pending()
    waiting = Session.from_file(_write(TWO), llm=ScriptedLLM([GOOD_PLAN, GOOD_PLAN]))
    waiting.run_pending()

    summary = summarize([good, retried, waiting])
    assert summary["findings"] == 4 and summary["ready_for_review"] == 2 and summary["unfinished"] == 2
    assert summary["patched"] == 2 and summary["patch_pass_rate"] == 1.0 and summary["retry_rate"] == 0.5
    assert summary["attempts"] == 3 and summary["verification"] == {"pass": 2}
    assert summary["model_calls"] == 2 + 4 + 2


def test_summary_of_nothing_has_no_rates():
    assert summarize([])["patch_pass_rate"] is None
