import pytest
from pydantic import ValidationError

from pq_patch.schemas import (
    Algorithm,
    FileScanResult,
    Finding,
    FindingStatus,
    Patch,
    PatchReply,
    Plan,
    ReportRow,
    UsageContext,
    VerificationOutcome,
    VerificationResult,
)


def make_finding(**kw):
    base = dict(
        file="a.py", line=5, end_line=5, column=4,
        original_call="rsa.generate_private_key",
        qualified_name="cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
        algorithm=Algorithm.RSA,
        enclosing_scope="make_key", scope_start_line=3, scope_end_line=8,
    )
    base.update(kw)
    return Finding(**base)


# ---- Scope ----

def test_scope_is_rsa_and_ecdsa_signing_only():
    assert {a.value for a in Algorithm} == {"RSA", "EC", "ECDSA"}
    assert {u.value for u in UsageContext} == {"signing", "other"}


# ---- Finding / FileScanResult ----

def test_finding_valid():
    assert make_finding().algorithm is Algorithm.RSA


def test_finding_rejects_call_outside_scope():
    with pytest.raises(ValidationError):
        make_finding(line=1, end_line=1)


def test_finding_rejects_unknown_field():
    with pytest.raises(ValidationError):
        make_finding(severity="high")


def test_unparseable_file_requires_error_and_no_findings():
    with pytest.raises(ValidationError):
        FileScanResult(file="x.py", parse_ok=False)
    with pytest.raises(ValidationError):
        FileScanResult(file="x.py", parse_ok=False, parse_error="bad", findings=[make_finding()])
    assert FileScanResult(file="x.py", parse_ok=False, parse_error="bad").parse_ok is False


# ---- Plan ----

def plan_kw(**kw):
    base = dict(usage_context="signing", target_algorithm="ML-DSA-65", approach="Replace RSA signing with ML-DSA-65.")
    base.update(kw)
    return base


def test_plan_valid_signing():
    assert Plan(**plan_kw()).usage_context is UsageContext.SIGNING


def test_plan_rejects_unknown_algorithm():
    with pytest.raises(ValidationError):
        Plan(**plan_kw(target_algorithm="RSA-4096"))


def test_plan_rejects_kem_target_out_of_scope():
    with pytest.raises(ValidationError):
        Plan(**plan_kw(target_algorithm="ML-KEM-768"))


def test_plan_rejects_non_signing_usage():
    with pytest.raises(ValidationError):
        Plan(**plan_kw(usage_context="other"))
    with pytest.raises(ValidationError):
        Plan(**plan_kw(usage_context="key_exchange"))  # no longer a valid context


def test_plan_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Plan(**plan_kw(verification="skip"))


@pytest.mark.parametrize("dash", ["‐", "‑", "‒", "–", "—", "−"])
def test_plan_normalises_unicode_dashes_in_the_target_name(dash):
    # A real model wrote non-breaking hyphens throughout its prose; the same can happen in the name.
    assert Plan(**plan_kw(target_algorithm=f"ML{dash}DSA{dash}65")).target_algorithm == "ML-DSA-65"
    assert Plan(**plan_kw(target_algorithm=f" ML{dash}DSA{dash}87 ")).target_algorithm == "ML-DSA-87"


def test_plan_still_rejects_a_look_alike_that_is_not_an_allowed_target():
    with pytest.raises(ValidationError):
        Plan(**plan_kw(target_algorithm="ML‑KEM‑768"))


# ---- Patch ----

def test_patch_valid():
    p = Patch(new_source="def f():\n    pass\n", imports=["import oqs", "from oqs import Signature"])
    assert len(p.imports) == 2


def test_patch_allows_syntactically_broken_source():
    # Syntax errors must reach the verifier, not be hidden by the schema.
    Patch(new_source="def f(:\n")


@pytest.mark.parametrize("bad", ["os.system('x')", "import os; os.system('x')", "import a\nimport b"])
def test_patch_rejects_non_import_statements(bad):
    with pytest.raises(ValidationError):
        Patch(new_source="x = 1", imports=[bad])


def test_patch_rejects_empty_source():
    with pytest.raises(ValidationError):
        Patch(new_source="")


def test_patch_rejects_blank_source():
    with pytest.raises(ValidationError):
        Patch(new_source="  \n\t\n")


def test_patch_keeps_leading_whitespace_because_it_is_code():
    # Stripping only the first line's indent would leave the other lines indented: a broken patch.
    src = "    def f(self):\n        return 1\n"
    assert Patch(new_source=src).new_source == src


# ---- PatchReply ----

def test_patch_reply_needs_exactly_one_of_patch_or_escalate():
    with pytest.raises(ValidationError):
        PatchReply.model_validate({})
    with pytest.raises(ValidationError):
        PatchReply.model_validate({"patch": {"new_source": "x = 1"}, "escalate": {"reason": "cannot do it"}})
    assert PatchReply.model_validate({"patch": {"new_source": "x = 1"}}).patch is not None
    assert PatchReply.model_validate({"escalate": {"reason": "needs a wider change"}}).escalate is not None


def test_patch_reply_ignores_the_other_stages_key_but_patch_stays_strict():
    assert PatchReply.model_validate({"plan": {"anything": 1}, "patch": {"new_source": "x = 1"}}).patch is not None
    with pytest.raises(ValidationError):
        PatchReply.model_validate({"patch": {"new_source": "x = 1", "surprise": True}})


# ---- VerificationResult ----

def test_verification_pass_valid():
    r = VerificationResult(outcome="pass", compile_ok=True, detector_clear=True, tests_ran=True, tests_passed=True)
    assert r.outcome is VerificationOutcome.PASS


def test_verification_pass_without_tests_valid():
    VerificationResult(outcome="pass", compile_ok=True, detector_clear=True)


def test_verification_pass_cannot_hide_failures():
    with pytest.raises(ValidationError):
        VerificationResult(outcome="pass", compile_ok=False, detector_clear=True)
    with pytest.raises(ValidationError):
        VerificationResult(outcome="pass", compile_ok=True, detector_clear=False)
    with pytest.raises(ValidationError):
        VerificationResult(outcome="pass", compile_ok=True, detector_clear=True, tests_ran=True, tests_passed=False)


def test_verification_failed_outcomes_must_match_evidence():
    with pytest.raises(ValidationError):
        VerificationResult(outcome="failed_compile", compile_ok=True)
    with pytest.raises(ValidationError):
        VerificationResult(outcome="failed_test", compile_ok=True, tests_ran=True, tests_passed=True)
    VerificationResult(outcome="failed_compile", compile_ok=False, output="SyntaxError")
    VerificationResult(outcome="failed_test", compile_ok=True, tests_ran=True, tests_passed=False)


def test_failed_test_timeout_outcome_must_match_evidence():
    ok = VerificationResult(outcome="failed_test(timeout)", compile_ok=True, tests_ran=True, tests_passed=False)
    assert ok.outcome.value == "failed_test(timeout)"
    with pytest.raises(ValidationError):  # tests did not run
        VerificationResult(outcome="failed_test(timeout)", compile_ok=True)
    with pytest.raises(ValidationError):  # tests passed
        VerificationResult(outcome="failed_test(timeout)", compile_ok=True, tests_ran=True, tests_passed=True)
    with pytest.raises(ValidationError):  # a timeout is never a pass
        VerificationResult(outcome="pass", compile_ok=True, detector_clear=True, tests_ran=True, tests_passed=False)


def test_verification_tests_flags_consistent():
    with pytest.raises(ValidationError):
        VerificationResult(outcome="needs_review", compile_ok=True, tests_ran=True)
    with pytest.raises(ValidationError):
        VerificationResult(outcome="needs_review", compile_ok=True, tests_ran=False, tests_passed=True)


# ---- ReportRow ----

def test_report_row_ready_for_review():
    row = ReportRow(
        file="a.py", line=5, original_call="rsa.generate_private_key", target_algorithm="ML-DSA-65",
        proposed_patch="--- a\n+++ b\n", verification_result="pass", attempts=1, status="ready_for_review",
    )
    assert row.status is FindingStatus.READY_FOR_REVIEW


def test_report_row_ready_requires_pass_patch_and_attempt():
    base = dict(file="a.py", status="ready_for_review", proposed_patch="d", verification_result="pass", attempts=1)
    ReportRow(**base)
    with pytest.raises(ValidationError):
        ReportRow(**{**base, "verification_result": "failed_test"})
    with pytest.raises(ValidationError):
        ReportRow(**{**base, "proposed_patch": None})
    with pytest.raises(ValidationError):
        ReportRow(**{**base, "attempts": 0})


def test_report_row_rejects_out_of_scope_target():
    with pytest.raises(ValidationError):
        ReportRow(file="a.py", status="escalated", target_algorithm="ML-KEM-768", notes="x")


def test_report_row_no_action_needed_has_no_patch():
    ReportRow(file="safe.py", status="no_action_needed", notes="only quantum-safe algorithms")
    with pytest.raises(ValidationError):
        ReportRow(file="safe.py", status="no_action_needed", proposed_patch="fabricated diff")


def test_report_row_escalated_needs_reason_and_not_pass():
    ReportRow(file="a.py", status="escalated", verification_result="failed_test", attempts=3, notes="max attempts")
    with pytest.raises(ValidationError):
        ReportRow(file="a.py", status="escalated", verification_result="failed_test", attempts=3)
    with pytest.raises(ValidationError):
        ReportRow(file="a.py", status="escalated", verification_result="pass", attempts=1, notes="x")


def test_report_row_json_roundtrip_has_all_nine_fields():
    row = ReportRow(file="safe.py", status="no_action_needed")
    data = row.model_dump(mode="json")
    assert set(data) == {
        "file", "line", "original_call", "target_algorithm", "proposed_patch",
        "verification_result", "attempts", "status", "notes",
    }
    assert ReportRow.model_validate_json(row.model_dump_json()) == row
