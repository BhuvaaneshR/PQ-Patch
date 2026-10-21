"""The state machine, with the real planner/patcher/verifier and a scripted model."""

import textwrap
from pathlib import Path

import pytest

from pq_patch.orchestrator import (
    Action,
    ActionNotAllowed,
    InputRejected,
    MAX_INPUT_BYTES,
    Session,
    State,
    check_source,
    read_input,
)
from pq_patch.planner import PlanOutcome, PlanResult
from pq_patch.schemas import FindingStatus, VerificationOutcome, VerificationResult
from scripted_llm import BAD_PATCH, ESCALATE, GOOD_PATCH, GOOD_PLAN, ScriptedLLM

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "sample_input.py"

TWO = textwrap.dedent(
    '''\
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding


    def sign_a(key, m):
        return key.sign(m, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


    def sign_b(key, m):
        return key.sign(m, padding.PKCS1v15(), hashes.SHA256())
    '''
)

SHARED = textwrap.dedent(
    '''\
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding


    def sign_both(key, m):
        a = key.sign(m, padding.PKCS1v15(), hashes.SHA256())
        b = key.sign(m, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        return a + b
    '''
)


def session(llm, path=SAMPLE, **kw):
    return Session.from_file(path, llm=llm, **kw)


def approved(s, fid=1):
    s.run_pending()
    s.act(fid, Action.APPROVE_PLAN)
    s.run_pending()
    return s.get(fid)


# --- the happy path and the human gate ---------------------------------------------------------


def test_happy_path_waits_for_approval_then_patches_and_verifies():
    llm = ScriptedLLM(plans=[GOOD_PLAN], patches=[GOOD_PATCH])
    s = session(llm)
    rec = s.get(1)
    assert rec.state is State.DETECTED and llm.count() == 0

    s.run_pending()
    assert rec.state is State.AWAITING_PLAN_APPROVAL and rec.plan.target_algorithm == "ML-DSA-65"
    assert llm.calls == ["planner"]  # no patch has been drafted

    s.run_pending()  # running again without a decision changes nothing
    assert rec.state is State.AWAITING_PLAN_APPROVAL and llm.calls == ["planner"]

    s.act(1, Action.APPROVE_PLAN)
    assert rec.state is State.PATCHING
    s.run_pending()
    assert rec.state is State.READY_FOR_REVIEW
    assert (rec.attempts, rec.verification.outcome, rec.run_status) == (1, VerificationOutcome.PASS, "ok")
    assert s.done and s.run_status == "ok" and s.model_calls == 2

    (row,) = s.report_rows()
    assert row.status is FindingStatus.READY_FOR_REVIEW and row.attempts == 1
    assert row.proposed_patch.startswith("--- a/") and "+++ b/" in row.proposed_patch
    assert row.original_call.endswith("sign") and row.target_algorithm == "ML-DSA-65"


def test_the_input_file_is_never_written():
    before = SAMPLE.read_bytes()
    approved(session(ScriptedLLM([GOOD_PLAN], [GOOD_PATCH])))
    assert SAMPLE.read_bytes() == before


def test_there_is_no_way_to_skip_the_plan_checkpoint():
    s = session(ScriptedLLM(plans=[GOOD_PLAN]))
    s.run_pending()
    for action in (Action.RETRY, Action.REVERIFY):
        with pytest.raises(ActionNotAllowed):
            s.act(1, action)
    assert s.get(1).state is State.AWAITING_PLAN_APPROVAL
    assert set(s.allowed_actions(1)) == {Action.APPROVE_PLAN, Action.REVISE_PLAN, Action.ESCALATE}


def test_every_transition_goes_through_the_table():
    s = session(ScriptedLLM())
    with pytest.raises(RuntimeError, match="not a legal transition"):
        s._move(s.get(1), State.READY_FOR_REVIEW, "cheating")


def test_history_records_each_move():
    s = session(ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    rec = approved(s)
    path = [e.to_state for e in rec.history]
    assert path == [State.DETECTED, State.PLANNING, State.AWAITING_PLAN_APPROVAL, State.PATCHING, State.VERIFYING, State.READY_FOR_REVIEW]


# --- failure, guidance, retry --------------------------------------------------------------------


def test_failed_patch_then_guidance_then_retry_succeeds_with_two_attempts():
    llm = ScriptedLLM(plans=[GOOD_PLAN], patches=[BAD_PATCH, BAD_PATCH, GOOD_PATCH])
    s = session(llm)
    rec = approved(s)
    # the patcher already tried a second draft inside this attempt; both were broken
    assert rec.state is State.AWAITING_FAILURE_DECISION and rec.attempts == 1
    assert (rec.failure.stage, rec.failure.kind) == ("verify", "failed_compile")
    assert Action.RETRY in s.allowed_actions(1) and Action.REVERIFY in s.allowed_actions(1)

    s.act(1, Action.RETRY, feedback="close the parenthesis and keep the signature")
    s.run_pending()
    assert rec.state is State.READY_FOR_REVIEW and rec.attempts == 2
    assert [a.verification for a in rec.attempt_log] == [VerificationOutcome.FAILED_COMPILE, VerificationOutcome.PASS]
    prompt = "\n".join(m["content"] for m in llm.messages[-1])
    assert "close the parenthesis" in prompt and "[compile]" in prompt  # guidance and the failure reach the model
    assert s.report_rows()[0].attempts == 2


def test_three_failed_attempts_escalate_with_the_last_failure():
    llm = ScriptedLLM(plans=[GOOD_PLAN], patches=[BAD_PATCH] * 6)
    s = session(llm)
    rec = approved(s)
    for _ in range(2):
        assert rec.state is State.AWAITING_FAILURE_DECISION
        s.act(1, Action.RETRY)
        s.run_pending()
    assert rec.state is State.ESCALATED and rec.attempts == 3
    assert "retry limit reached after 3 attempts" in rec.escalation_reason and "failed_compile" in rec.escalation_reason
    row = s.report_rows()[0]
    assert row.status is FindingStatus.ESCALATED and row.verification_result is VerificationOutcome.FAILED_COMPILE
    with pytest.raises(ActionNotAllowed):
        s.act(1, Action.RETRY)


def test_retry_from_ready_for_review_needs_feedback_and_counts_an_attempt():
    s = session(ScriptedLLM([GOOD_PLAN], [GOOD_PATCH, GOOD_PATCH]))
    rec = approved(s)
    with pytest.raises(ActionNotAllowed, match="needs feedback"):
        s.act(1, Action.RETRY)
    s.act(1, Action.RETRY, feedback="use ML-DSA-87 instead")
    s.run_pending()
    assert rec.state is State.READY_FOR_REVIEW and rec.attempts == 2


def test_a_timeout_offers_a_longer_test_timeout_without_a_new_patch():
    calls = []

    def verify_fn(finding, original, patched, **kw):
        calls.append(kw["test_timeout"])
        if len(calls) == 1:
            return VerificationResult(
                outcome=VerificationOutcome.FAILED_TEST_TIMEOUT, compile_ok=True, detector_clear=True,
                tests_ran=True, tests_passed=False, output="[tests] timed out",
            )
        return VerificationResult(outcome=VerificationOutcome.PASS, compile_ok=True, detector_clear=True, output="ok")

    llm = ScriptedLLM([GOOD_PLAN], [GOOD_PATCH])
    s = session(llm, verify_fn=verify_fn, max_attempts=1)  # even at the attempt limit a timeout is not an escalation
    rec = approved(s)
    assert rec.state is State.AWAITING_FAILURE_DECISION and rec.failure.kind == "failed_test(timeout)"
    assert Action.REVERIFY in s.allowed_actions(1) and Action.RETRY not in s.allowed_actions(1)

    for bad in (0, -5, 999):
        with pytest.raises(ValueError):
            s.act(1, Action.REVERIFY, test_timeout=bad)
    s.act(1, Action.REVERIFY, test_timeout=120)
    s.run_pending()
    assert calls == [30, 120] and rec.state is State.READY_FOR_REVIEW
    assert rec.attempts == 1 and llm.count("patcher") == 1  # same patch, no model call
    assert len(rec.attempt_log) == 1 and rec.attempt_log[0].verification is VerificationOutcome.PASS


# --- plan revision ------------------------------------------------------------------------------


def test_revising_a_plan_sends_the_feedback_and_needs_approval_again():
    llm = ScriptedLLM(plans=[GOOD_PLAN, {**GOOD_PLAN, "target_algorithm": "ML-DSA-87"}], patches=[GOOD_PATCH])
    s = session(llm)
    s.run_pending()
    with pytest.raises(ActionNotAllowed, match="needs feedback"):
        s.act(1, Action.REVISE_PLAN)
    s.act(1, Action.REVISE_PLAN, feedback="we need the highest security level")
    assert s.get(1).state is State.PLANNING
    s.run_pending()
    rec = s.get(1)
    assert rec.state is State.AWAITING_PLAN_APPROVAL and rec.plan.target_algorithm == "ML-DSA-87"
    assert llm.calls == ["planner", "planner"]  # still no patch
    assert "highest security level" in "\n".join(m["content"] for m in llm.messages[-1])
    s.act(1, Action.APPROVE_PLAN)
    s.run_pending()
    assert rec.state is State.READY_FOR_REVIEW


def test_plan_revisions_are_capped():
    s = session(ScriptedLLM(plans=[GOOD_PLAN] * 4), max_plan_revisions=2)
    s.run_pending()
    for _ in range(2):
        s.act(1, Action.REVISE_PLAN, feedback="again")
        s.run_pending()
    assert Action.REVISE_PLAN not in s.allowed_actions(1)
    with pytest.raises(ActionNotAllowed):
        s.act(1, Action.REVISE_PLAN, feedback="once more")


def test_feedback_over_the_limit_is_rejected():
    s = session(ScriptedLLM([GOOD_PLAN]))
    s.run_pending()
    with pytest.raises(ValueError, match="2000"):
        s.act(1, Action.REVISE_PLAN, feedback="x" * 2001)


# --- escalation -------------------------------------------------------------------------------------


def test_planner_escalation_stops_before_any_patch():
    llm = ScriptedLLM(plans=[ESCALATE])
    s = session(llm)
    s.run_pending()
    rec = s.get(1)
    assert rec.state is State.ESCALATED and "key exchange" in rec.escalation_reason
    assert llm.calls == ["planner"] and rec.run_status == "ok"
    row = s.report_rows()[0]
    assert row.status is FindingStatus.ESCALATED and "key exchange" in row.notes and row.proposed_patch is None


def test_a_person_can_escalate_at_any_time_even_after_a_pass():
    s = session(ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]))
    rec = approved(s)
    s.act(1, Action.ESCALATE, feedback="the compliance team must look at this")
    row = s.report_rows()[0]
    assert rec.state is State.ESCALATED and row.status is FindingStatus.ESCALATED
    assert row.verification_result is None and "compliance team" in row.notes and "had passed" in row.notes
    assert s.allowed_actions(1) == []


# --- model failures ------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["error", "refused", "invalid_output"])
def test_a_failed_plan_step_waits_for_a_person_and_can_be_retried(status):
    s = session(ScriptedLLM(plans=[status, GOOD_PLAN]))
    s.run_pending()
    rec = s.get(1)
    assert rec.state is State.AWAITING_FAILURE_DECISION and rec.run_status == status and s.run_status == status
    assert (rec.failure.stage, rec.failure.kind) == ("plan", status)
    assert rec.attempts == 0
    assert Action.RETRY in s.allowed_actions(1) and Action.REVERIFY not in s.allowed_actions(1)
    s.act(1, Action.RETRY)
    s.run_pending()
    assert rec.state is State.AWAITING_PLAN_APPROVAL and rec.run_status == "ok" and s.run_status == "ok"


def test_a_failed_patch_step_does_not_use_up_an_attempt():
    s = session(ScriptedLLM(plans=[GOOD_PLAN], patches=["error", GOOD_PATCH]))
    rec = approved(s)
    assert rec.state is State.AWAITING_FAILURE_DECISION and rec.attempts == 0 and rec.failure.stage == "patch"
    s.act(1, Action.RETRY)
    s.run_pending()
    assert rec.state is State.READY_FOR_REVIEW and rec.attempts == 1


def test_stop_on_model_failure_leaves_the_rest_untouched():
    llm = ScriptedLLM(plans=["error"])
    s = session(llm, path=_write(TWO))
    s.run_pending(stop_on_model_failure=True)
    assert s.run_status == "error" and llm.count() == 1
    assert [r.state for r in s.records] == [State.AWAITING_FAILURE_DECISION, State.DETECTED]
    rows = s.report_rows()
    assert all(r.status is FindingStatus.ESCALATED for r in rows) and "not finished" in rows[1].notes


def test_without_the_stop_flag_each_finding_is_worked_independently():
    llm = ScriptedLLM(plans=["error", GOOD_PLAN])
    s = session(llm, path=_write(TWO))
    s.run_pending()
    assert [r.state for r in s.records] == [State.AWAITING_FAILURE_DECISION, State.AWAITING_PLAN_APPROVAL]


def test_cached_replies_are_counted_apart_from_model_calls():
    def plan_fn(finding, source, **kw):
        return PlanResult(PlanOutcome.PLANNED, plan=__import__("pq_patch.schemas", fromlist=["Plan"]).Plan(**GOOD_PLAN), calls=0)

    s = session(ScriptedLLM(), plan_fn=plan_fn)
    s.run_pending()
    assert (s.model_calls, s.cached_replies) == (0, 1)


# --- no findings, shared scopes, input checks ----------------------------------------------------------


def test_a_file_with_nothing_to_fix_makes_no_model_call_and_fabricates_no_patch():
    class NeverCalled:
        def call(self, *a, **k):
            raise AssertionError("the model must not be called")

    s = session(NeverCalled(), path=_write("def add(a, b):\n    return a + b\n"))
    s.run_pending()
    (row,) = s.report_rows()
    assert s.records == [] and s.done and row.status is FindingStatus.NO_ACTION_NEEDED
    assert row.proposed_patch is None and row.attempts == 0 and row.verification_result is None


def test_findings_in_the_same_scope_are_flagged_for_joint_review():
    s = session(ScriptedLLM(), path=_write(SHARED))
    assert len(s.records) == 2
    assert all("share one enclosing scope" in r.notes[0] for r in s.records)


def test_separate_scopes_get_no_such_note():
    s = session(ScriptedLLM(), path=_write(TWO))
    assert all(not r.notes for r in s.records)


@pytest.mark.parametrize(
    "name, data, fragment",
    [
        ("a.py", b"", "empty"),
        ("a.py", b"   \n\n", "empty"),
        pytest.param("a.py", b"x = 1\n" * (MAX_INPUT_BYTES // 6 + 10), "limit", id="too-large"),
        ("a.py", b"def broken(:\n", "not valid Python"),
        ("a.py", b"\xff\xfe\x00bad", "UTF-8"),
        ("a.txt", b"x = 1\n", "not a .py"),
    ],
)
def test_bad_input_is_rejected_before_anything_else(tmp_path, name, data, fragment):
    path = tmp_path / name
    path.write_bytes(data)
    with pytest.raises(InputRejected, match=fragment):
        read_input(path)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(InputRejected, match="cannot be read"):
        read_input(tmp_path / "nope.py")


def test_uploads_use_the_same_checks():
    assert check_source("x = 1\n") == "x = 1\n"
    with pytest.raises(InputRejected):
        check_source(b"", "upload.py")


# --- with a project folder -----------------------------------------------------------------------------


def test_project_tests_run_against_the_patch(tmp_path):
    (tmp_path / "signer.py").write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "test_signer.py").write_text("# covers signer\ndef test_nothing_breaks():\n    assert True\n", encoding="utf-8")
    s = Session.from_file(tmp_path / "signer.py", llm=ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]), project_root=tmp_path)
    rec = approved(s)
    assert rec.state is State.READY_FOR_REVIEW and rec.verification.tests_ran is True


def test_a_file_outside_the_project_root_is_still_checked_and_the_gap_is_reported(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    s = Session.from_file(SAMPLE, llm=ScriptedLLM([GOOD_PLAN], [GOOD_PATCH]), project_root=other)
    rec = approved(s)
    assert rec.state is State.READY_FOR_REVIEW and rec.verification.tests_ran is False
    assert any("tests were not run" in n for n in rec.notes)


def _write(text):
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "case.py"
    p.write_text(text, encoding="utf-8")
    return p


def test_only_limits_the_work_to_chosen_findings():
    llm = ScriptedLLM(plans=[GOOD_PLAN])
    s = session(llm, path=_write(TWO))
    s.run_pending(only=[2])
    assert [r.state for r in s.records] == [State.DETECTED, State.AWAITING_PLAN_APPROVAL] and llm.count() == 1
