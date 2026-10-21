"""main.py: the output contract (last stdout line = status, exit codes) and the human-gate policy."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import main as cli
from pq_patch.orchestrator import Action, Session, State
from scripted_llm import BAD_PATCH, ESCALATE, GOOD_PATCH, GOOD_PLAN, ScriptedLLM
from test_orchestrator import SAMPLE, TWO, _write

ROOT = Path(__file__).resolve().parents[1]
INJECTED = ROOT / "samples" / "injected_input.py"
CANARY = "PWNED-7F3A"


def run_main(capsys, argv, llm=None, read=None):
    kwargs = {"llm": llm}
    if read is not None:
        kwargs["read"] = read
    code = cli.main([str(a) for a in argv], **kwargs)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def rows_of(out):
    return [json.loads(line) for line in out.strip().splitlines()[:-1]]


# --- the output contract ---------------------------------------------------------------------------------


def test_success_prints_rows_then_ok_as_the_last_line(capsys):
    code, out, err = run_main(capsys, [SAMPLE], ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    assert code == 0 and out.strip().splitlines()[-1] == "ok"
    (row,) = rows_of(out)
    assert row["status"] == "ready_for_review" and row["verification_result"] == "pass" and row["attempts"] == 1
    assert "model calls: 2" in err


def test_stdout_has_nothing_but_rows_and_the_status(capsys):
    _, out, _ = run_main(capsys, [SAMPLE], ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    lines = out.strip().splitlines()
    assert all(line.startswith("{") for line in lines[:-1]) and lines[-1] == "ok"


@pytest.mark.parametrize("status", ["invalid_output", "refused", "error"])
def test_a_failed_model_step_is_the_run_status_and_exit_1(capsys, status):
    code, out, _ = run_main(capsys, [SAMPLE], ScriptedLLM(plans=[status]))
    assert code == 1 and out.strip().splitlines()[-1] == status
    (row,) = rows_of(out)
    assert row["status"] == "escalated" and f"({status})" in row["notes"] and row["proposed_patch"] is None


def test_the_run_stops_at_the_first_failed_model_call_and_lists_the_rest_as_not_attempted(capsys):
    llm = ScriptedLLM(plans=["refused"])
    code, out, _ = run_main(capsys, [_write(TWO)], llm)
    assert code == 1 and llm.count() == 1
    first, second = rows_of(out)
    assert "refused" in first["notes"] and "not attempted" in second["notes"]


def test_a_planner_escalation_is_a_normal_ok_run(capsys):
    code, out, _ = run_main(capsys, [SAMPLE], ScriptedLLM(plans=[ESCALATE]))
    assert code == 0 and out.strip().splitlines()[-1] == "ok"
    assert rows_of(out)[0]["status"] == "escalated"


def test_a_failed_verification_is_escalated_not_retried_without_a_person(capsys):
    llm = ScriptedLLM([GOOD_PLAN], [BAD_PATCH, BAD_PATCH])
    code, out, _ = run_main(capsys, [SAMPLE], llm)
    (row,) = rows_of(out)
    assert code == 0 and row["status"] == "escalated" and row["verification_result"] == "failed_compile"
    assert "needs a person" in row["notes"] and llm.count("patcher") == 2


def test_nothing_flagged_is_no_action_needed_with_no_model_call(capsys):
    class NeverCalled:
        def call(self, *a, **k):
            raise AssertionError("no model call expected")

    code, out, _ = run_main(capsys, [_write("def add(a, b):\n    return a + b\n")], NeverCalled())
    (row,) = rows_of(out)
    assert code == 0 and row["status"] == "no_action_needed" and row["proposed_patch"] is None


@pytest.mark.parametrize(
    "name, data",
    [
        pytest.param("empty.py", b"", id="empty"),
        pytest.param("bad.py", b"def x(:\n", id="syntax"),
        pytest.param("note.txt", b"x = 1\n", id="not-py"),
        pytest.param("big.py", b"x = 1\n" * 60000, id="big"),
    ],
)
def test_rejected_input_exits_2_before_any_model_call(capsys, tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)

    class NeverCalled:
        def call(self, *a, **k):
            raise AssertionError("no model call expected")

    code, out, err = run_main(capsys, [path], NeverCalled())
    assert code == 2 and out == "" and "input rejected" in err


def test_the_input_file_is_not_modified_and_nothing_is_written_without_out(capsys, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    target = work / "signer.py"
    target.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    before = target.read_bytes()
    monkeypatch.chdir(work)
    run_main(capsys, [target], ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    assert target.read_bytes() == before and [p.name for p in work.iterdir()] == ["signer.py"]


def test_out_writes_the_report_files(capsys, tmp_path):
    run_main(capsys, [SAMPLE, "--out", tmp_path / "rep"], ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    names = sorted(p.name for p in (tmp_path / "rep").iterdir())
    assert names == ["report.csv", "report.json", "sample_input.L9.diff"]


# --- --ask: a person at every checkpoint ----------------------------------------------------------------------


def answers(*items):
    queue = list(items)

    def read(prompt):
        if not queue:
            raise EOFError
        return queue.pop(0)

    return read


def test_ask_waits_for_a_yes_before_any_patch_is_drafted(capsys):
    llm = ScriptedLLM(plans=[GOOD_PLAN])
    code, out, _ = run_main(capsys, [SAMPLE, "--ask"], llm, answers("e"))
    assert llm.calls == ["planner"]  # escalating at the plan checkpoint means no patch call, ever
    assert rows_of(out)[0]["status"] == "escalated" and "plan checkpoint" in rows_of(out)[0]["notes"]


def test_ask_approve_then_patch(capsys):
    llm = ScriptedLLM([GOOD_PLAN], [GOOD_PATCH])
    code, out, _ = run_main(capsys, [SAMPLE, "--ask"], llm, answers("a"))
    assert rows_of(out)[0]["status"] == "ready_for_review" and llm.calls == ["planner", "patcher"]


def test_ask_revise_sends_the_feedback_and_asks_again(capsys):
    llm = ScriptedLLM([GOOD_PLAN, {**GOOD_PLAN, "target_algorithm": "ML-DSA-87"}], [GOOD_PATCH])
    code, out, _ = run_main(capsys, [SAMPLE, "--ask"], llm, answers("r", "use the strongest level", "a"))
    assert rows_of(out)[0]["target_algorithm"] == "ML-DSA-87" and llm.calls == ["planner", "planner", "patcher"]
    assert "strongest level" in "\n".join(m["content"] for m in llm.messages[1])


def test_ask_retry_with_guidance_after_a_failed_check(capsys):
    llm = ScriptedLLM([GOOD_PLAN], [BAD_PATCH, BAD_PATCH, GOOD_PATCH])
    code, out, _ = run_main(capsys, [SAMPLE, "--ask"], llm, answers("a", "r", "balance the brackets"))
    row = rows_of(out)[0]
    assert row["status"] == "ready_for_review" and row["attempts"] == 2


def test_closing_the_terminal_means_escalate_never_approve(capsys):
    llm = ScriptedLLM(plans=[GOOD_PLAN])
    code, out, _ = run_main(capsys, [SAMPLE, "--ask"], llm, answers())  # input ends at once
    assert rows_of(out)[0]["status"] == "escalated" and llm.calls == ["planner"]


# --- as a real process, against the course stub (what check_capstone.py does) ---------------------------------


def run_process(tmp_path, input_path, mode, *extra):
    env = {
        **os.environ,
        "LLM_API_KEY": "not-needed",
        "LLM_BASE_URL": "local://stub",
        "LLM_MODEL": f"stub:{mode}",
        "STUB_SAMPLES_DIR": str(ROOT / "samples"),
        "RUN_LOG_PATH": str(tmp_path / "run_log.jsonl"),
        "PYTHONPATH": str(ROOT),
        "PYTHONUTF8": "1",
        "LLM_CACHE": "0",
    }
    for var in ("LLM_FALLBACK_MODELS", "LLM_TPM_LIMIT"):
        env.pop(var, None)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), str(input_path), *extra],
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    log = tmp_path / "run_log.jsonl"
    lines = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    events = tmp_path / "security_log.jsonl"
    names = {json.loads(x)["event"] for x in events.read_text().splitlines()} if events.exists() else set()
    return proc, lines, names


def last_line(proc):
    return proc.stdout.strip().splitlines()[-1]


def test_stub_ok_runs_the_whole_pipeline(tmp_path):
    proc, log, _ = run_process(tmp_path, SAMPLE, "ok")
    assert (proc.returncode, last_line(proc)) == (0, "ok") and "Traceback" not in proc.stderr
    assert [x["status"] for x in log] == ["ok", "ok"] and len({x["run_id"] for x in log}) == 1


@pytest.mark.parametrize("mode, status", [("malformed", "invalid_output"), ("badshape", "invalid_output"), ("empty", "invalid_output"), ("refused", "refused"), ("error", "error")])
def test_stub_failures_end_with_the_matching_status(tmp_path, mode, status):
    proc, log, _ = run_process(tmp_path, SAMPLE, mode)
    assert (proc.returncode, last_line(proc)) == (1, status) and "Traceback" not in proc.stderr
    assert log and log[-1]["status"] == status and all(x["status"] != "ok" for x in log)
    assert {p.name for p in tmp_path.iterdir()} <= {"run_log.jsonl", "security_log.jsonl", ".stub_calls.log"}  # only the logs (the stub keeps its own call log)


def test_stub_flaky_recovers(tmp_path):
    proc, log, _ = run_process(tmp_path, SAMPLE, "flaky")
    assert (proc.returncode, last_line(proc)) == (0, "ok") and log[0]["status"] == "error"


def test_stub_ratelimit_gives_up_cleanly(tmp_path):
    proc, log, _ = run_process(tmp_path, SAMPLE, "ratelimit")
    assert (proc.returncode, last_line(proc)) == (1, "error") and len(log) == 3


def test_stub_obedient_cannot_get_its_marker_through(tmp_path):
    proc, log, events = run_process(tmp_path, INJECTED, "obedient")
    assert last_line(proc) in {"ok", "invalid_output", "refused", "error"} and "Traceback" not in proc.stderr
    assert CANARY not in proc.stdout and {"guardrail_input", "instruction_ignored"} <= events


@pytest.mark.parametrize(
    "name, data",
    [pytest.param("empty.py", b"", id="empty"), pytest.param("big.py", b"x = 1\n" * 200000, id="big")],
)
def test_stub_bad_input_exits_2_with_no_call_and_no_log_line(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    proc, log, _ = run_process(tmp_path, path, "ok")
    assert proc.returncode == 2 and log == [] and proc.stdout == ""
