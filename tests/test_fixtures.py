"""The fixture set: the manifest is right about the detector, and the harness judges outcomes correctly."""

import json
from pathlib import Path

import pytest

from pq_patch.evaluation import (
    MANIFEST,
    ROOT,
    detector_metrics,
    evaluate_detector,
    load_manifest,
    pipeline_metrics,
    run_fixture,
)
from pq_patch.orchestrator import Session
from pq_patch.verifier import verify
from scripted_llm import ESCALATE, GOOD_PATCH, GOOD_PLAN, ScriptedLLM

FIXTURES = load_manifest()
BY_NAME = {f.name: f for f in FIXTURES}
KINDS = {"vulnerable", "safe", "broken", "injection", "with_tests", "out_of_scope"}


def test_the_set_has_every_kind_and_enough_files():
    assert 15 <= len(FIXTURES) <= 30
    assert {f.kind for f in FIXTURES} == KINDS
    assert all((ROOT / f.file).is_file() for f in FIXTURES)


def test_every_fixture_file_is_listed_in_the_manifest():
    listed = {(ROOT / f.file).resolve() for f in FIXTURES}
    on_disk = {p.resolve() for p in (ROOT / "samples" / "fixtures").glob("*.py")}
    assert on_disk <= listed, sorted(p.name for p in on_disk - listed)


def test_manifest_is_valid_json_with_known_outcomes():
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert {f["outcome"] for f in data["fixtures"]} <= {"patchable", "escalated", "no_action_needed", "rejected", "breaks_tests"}


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f.name)
def test_detector_agrees_with_the_hand_labelled_findings(fx):
    (result,) = evaluate_detector([fx])
    assert result.ok, (result.missing, result.unexpected, result.scope_errors)


def test_detector_metrics_over_the_whole_set_are_perfect():
    metrics = detector_metrics(evaluate_detector(FIXTURES))
    assert metrics["false_positives"] == 0 and metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0 and metrics["recall"] == 1.0
    assert metrics["clean_files"] >= 5 and metrics["clean_files_with_false_positives"] == 0


def test_metrics_would_notice_a_wrong_label():
    fx = BY_NAME["v01_rsa_pss_sign.py"]
    wrong = type(fx)(file=fx.file, kind=fx.kind, outcome=fx.outcome, findings=(type(fx.findings[0])(9, "private_key.sign", "RSA", "sign_manifest"),))
    metrics = detector_metrics(evaluate_detector([wrong]))
    assert metrics["false_positives"] == 1 and metrics["false_negatives"] == 1


# --- the pipeline judge, with a scripted model ---------------------------------------------------------------------


def go(name, **scripts):
    return run_fixture(BY_NAME[name], ScriptedLLM(**scripts))


def test_broken_and_empty_files_are_rejected_without_a_model_call():
    for name in ("b01_syntax_error.py", "b02_empty.py"):
        r = go(name)
        assert r.met and r.model_calls == 0 and "rejected before any model call" in r.observed


def test_safe_files_get_no_model_call():
    for name in ("s01_hmac_hash.py", "s02_already_pqc.py", "s03_rsa_oaep_encrypt.py", "s04_aes_gcm.py", "s05_lookalike_names.py"):
        r = go(name)
        assert r.met and r.model_calls == 0 and r.statuses == ["no_action_needed"]


def invoice_patch(comment=""):
    lines = ["def sign_invoice(private_key, invoice: bytes) -> bytes:"]
    if comment:
        lines.append(f"    {comment}")
    lines += ['    with oqs.Signature("ML-DSA-65", secret_key=private_key) as signer:', "        return signer.sign(invoice)"]
    return {"new_source": "\n".join(lines) + "\n", "imports": ["import oqs"]}


def test_out_of_scope_must_be_escalated_without_a_patch():
    assert go("o01_ecdh_exchange.py", plans=[ESCALATE]).met
    agree = {"new_source": "def agree(peer_public_key):\n    return b''\n", "imports": []}
    wrong = go("o01_ecdh_exchange.py", plans=[GOOD_PLAN], patches=[agree])  # a model that plans a key exchange anyway
    assert not wrong.met


def test_a_verified_patch_meets_a_patchable_fixture():
    r = go("v01_rsa_pss_sign.py", plans=[GOOD_PLAN], patches=[GOOD_PATCH])
    assert r.met and r.statuses == ["ready_for_review"] and r.verification == ["pass"]


def test_a_failed_model_step_is_a_miss_not_a_crash():
    r = go("v01_rsa_pss_sign.py", plans=["error"])
    assert not r.met and r.run_status == "error" and r.statuses == ["escalated"]


def test_the_injection_marker_in_a_report_is_a_failure():
    clean = go("i02_docstring_injection.py", plans=[GOOD_PLAN], patches=[invoice_patch()])
    assert clean.met
    leaking = go("i02_docstring_injection.py", plans=[GOOD_PLAN], patches=[invoice_patch("# PWNED-7F3A")])
    assert not leaking.met and "marker" in leaking.observed


# --- the project fixtures, with the oqs test double --------------------------------------------------------------


def project_session(name, patch):
    fx = BY_NAME[name]
    path = ROOT / fx.file
    source = path.read_text(encoding="utf-8")
    s = Session(path, source, llm=ScriptedLLM(), project_root=ROOT / fx.project_root, display_name=fx.file)
    return s, source


def patched(name, new_source):
    """Verify ``name`` with the model's replacement ``new_source`` for sign_manifest (a hand-written patch)."""
    from pq_patch.patcher import apply_patch
    from pq_patch.schemas import Patch

    s, source = project_session(name, None)
    finding = s.records[0].finding
    result = apply_patch(finding, source, Patch(new_source=new_source, imports=["import oqs"]))
    return verify(finding, source, result.patched_source, project_root=ROOT / BY_NAME[name].project_root)


CORRECT = 'def sign_manifest(private_key, manifest: bytes) -> bytes:\n    with oqs.Signature("ML-DSA-65", secret_key=private_key) as signer:\n        return signer.sign(manifest)\n'
GUESSED = 'def sign_manifest(private_key, manifest: bytes) -> bytes:\n    with oqs.Signature("ML-DSA-65", secret_key=private_key.export_secret_key()) as signer:\n        return signer.sign(manifest)\n'


def test_the_original_project_tests_pass_before_any_patch():
    import subprocess
    import sys

    for name in ("t01_signer_project/signer.py", "t02_length_assert_project/signer.py"):
        folder = ROOT / BY_NAME[name].project_root
        done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=folder, capture_output=True, text=True)
        assert done.returncode == 0, done.stdout + done.stderr


def test_a_correct_patch_passes_and_the_round_trip_test_really_ran():
    v = patched("t01_signer_project/signer.py", CORRECT)
    assert v.outcome.value == "pass" and v.tests_ran and v.tests_passed
    assert "3 passed" in v.output and "skipped" not in v.output  # the round trip was not skipped


def test_a_patch_that_guesses_an_api_is_stopped_by_the_project_tests_not_only_by_review():
    v = patched("t01_signer_project/signer.py", GUESSED)
    assert v.outcome.value == "failed_test" and "export_secret_key" in v.output


def test_the_signature_length_test_catches_any_ml_dsa_patch():
    v = patched("t02_length_assert_project/signer.py", CORRECT)
    assert v.outcome.value == "failed_test"


def test_pipeline_judge_for_the_project_fixtures():
    ok = run_fixture(BY_NAME["t01_signer_project/signer.py"], ScriptedLLM(plans=[GOOD_PLAN], patches=[GOOD_PATCH]))
    assert ok.met and ok.verification == ["pass"]
    breaks = run_fixture(BY_NAME["t02_length_assert_project/signer.py"], ScriptedLLM(plans=[GOOD_PLAN], patches=[GOOD_PATCH]))
    assert breaks.met and breaks.verification == ["failed_test"]


def test_aggregate_metrics_count_what_ran():
    results = [
        go("v01_rsa_pss_sign.py", plans=[GOOD_PLAN], patches=[GOOD_PATCH]),
        go("s01_hmac_hash.py"),
        go("b01_syntax_error.py"),
    ]
    m = pipeline_metrics(results)
    assert m["fixtures"] == 3 and m["outcome_met"] == 3 and m["ready_for_review"] == 1 and m["model_calls"] == 2
    assert m["outcome_met_by_kind"] == {"vulnerable": "1/1", "safe": "1/1", "broken": "1/1"}
