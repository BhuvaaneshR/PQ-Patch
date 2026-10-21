"""Plan -> patch -> verify against the REAL model configured in .env. Opt in with: python -m pytest -m live

This is the phase-3 acceptance check: RSA signing becomes ML-DSA-65 as a diff that compiles and clears
the detector. Failures are findings about the prompt or the model, not necessarily bugs: record them in
EVAL.md. Each test spends a few thousand free-tier tokens.
"""

import time
from pathlib import Path

import pytest

from live_support import describe_patch, describe_plan, describe_verification
from pq_patch.detector import scan_source
from pq_patch.patcher import PatchOutcome, patch_finding
from pq_patch.planner import PlanOutcome, plan_finding
from pq_patch.schemas import Patch
from pq_patch.verifier import verify

pytestmark = pytest.mark.live

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SAMPLE = (SAMPLES / "sample_input.py").read_text(encoding="utf-8")
INJECTED = (SAMPLES / "injected_input.py").read_text(encoding="utf-8")

CLASS_SOURCE = '''"""Release signing service."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Signer:
    """Signs release artifacts."""

    algorithm = "rsa-pss"

    @staticmethod
    def sign(private_key, data: bytes) -> bytes:
        """Return an RSA-PSS signature.

        The caller keeps the key; this only signs.
        """
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

    def describe(self) -> str:
        return f"signer using {self.algorithm}"
'''


def run_pipeline(llm, source, name, record, scenario):
    """Plan then patch, writing what the model did into ``record`` even if a later assertion fails."""
    finding = scan_source(source, name).findings[0]
    record["scenario"] = scenario
    planned = plan_finding(finding, source, llm=llm)
    record["plan"] = describe_plan(planned)
    assert planned.outcome is PlanOutcome.PLANNED, f"planner: {planned.outcome} {planned.reason}"
    time.sleep(10)
    patched = patch_finding(finding, source, planned.plan, llm=llm, display_name=name)
    record["patch"] = describe_patch(patched)
    return finding, planned, patched


def verified(record, finding, source, patched):
    """Verify the patched file and record the verdict."""
    v = verify(finding, source, patched.patched_source)
    record["verifier"] = describe_verification(v)
    return v


def explain(patched):
    return (
        f"{patched.outcome}: {patched.reason}\nnotes: {patched.notes}\n"
        f"--- patched source ---\n{patched.patched_source}"
    )


def test_sample_signing_function_becomes_a_verified_ml_dsa_patch(live_llm, live_record):
    finding, planned, patched = run_pipeline(
        live_llm, SAMPLE, "samples/sample_input.py", live_record, "sample: RSA-PSS signing function"
    )
    assert patched.outcome is PatchOutcome.PATCHED, explain(patched)
    assert "oqs" in patched.patched_source and "padding.PSS(" not in patched.patched_source, explain(patched)
    assert patched.problems == (), explain(patched)  # no guessed API: this was the first run's failure
    assert "export_secret_key" not in patched.patched_source, explain(patched)
    assert patched.diff.startswith("--- a/samples/sample_input.py\n+++ b/samples/sample_input.py\n")
    v = verified(live_record, finding, SAMPLE, patched)
    assert v.outcome.value == "pass", f"{v.output}\n{explain(patched)}"


def test_method_in_a_class_keeps_its_structure(live_llm, live_record):
    finding, _, patched = run_pipeline(
        live_llm, CLASS_SOURCE, "svc.py", live_record, "decorated static method inside a class, with a docstring"
    )
    assert patched.outcome is PatchOutcome.PATCHED, explain(patched)
    out = patched.patched_source
    # nothing outside the method may change, apart from the import the patch adds
    without_import = out.replace("import oqs\n", "", 1)
    assert without_import.startswith(CLASS_SOURCE[: CLASS_SOURCE.index("    @staticmethod")]), explain(patched)
    assert out.endswith(CLASS_SOURCE[CLASS_SOURCE.index("    def describe") :]), explain(patched)
    # the model may now annotate the key as bytes, as the prompt says keys become: accept that
    assert "@staticmethod" in out and "def sign(private_key" in out and "data: bytes) -> bytes:" in out, explain(patched)
    method_lines = out[out.index("    @staticmethod") : out.index("    def describe")].splitlines()
    assert all(ln.startswith("        ") or not ln.strip() or ln.startswith("    ") for ln in method_lines), explain(patched)
    docstring_lines = [ln for ln in method_lines if "The caller keeps the key" in ln or ln.strip() == '"""']
    assert docstring_lines and all(ln.startswith("        ") for ln in docstring_lines), "docstring is misaligned\n" + explain(patched)
    method = out[out.index("    @staticmethod") : out.index("    def describe")]
    assert "RSA-PSS" not in method, "the docstring still describes the old algorithm\n" + explain(patched)
    assert patched.problems == () and patched.warnings == (), explain(patched)
    v = verified(live_record, finding, CLASS_SOURCE, patched)
    assert v.outcome.value == "pass", f"{v.output}\n{explain(patched)}"


def test_retry_with_failure_output_and_guidance_produces_a_new_passing_patch(live_llm, live_record):
    finding = scan_source(SAMPLE, "samples/sample_input.py").findings[0]
    live_record["scenario"] = "retry after a failed attempt, with failure output and reviewer guidance"
    planned = plan_finding(finding, SAMPLE, llm=live_llm)
    live_record["plan"] = describe_plan(planned)
    assert planned.outcome is PlanOutcome.PLANNED, f"{planned.outcome} {planned.reason}"
    time.sleep(10)
    bad = Patch(new_source="def sign_manifest(private_key, manifest: bytes) -> bytes:\n    return None\n")
    r = patch_finding(
        finding, SAMPLE, planned.plan, llm=live_llm, previous_patch=bad,
        failure_output="[tests] failed\n    assert isinstance(sign_manifest(key, b'm'), bytes)\nE   AssertionError: got NoneType",
        feedback="The function must return the signature as bytes.",
    )
    live_record["patch"] = describe_patch(r)
    assert r.outcome is PatchOutcome.PATCHED, explain(r)
    assert "return None" not in r.patched_source, explain(r)
    assert verified(live_record, finding, SAMPLE, r).outcome.value == "pass", explain(r)


def test_injected_comment_does_not_stop_the_patch(live_llm, live_record, security_events):
    finding, _, patched = run_pipeline(
        live_llm, INJECTED, "samples/injected_input.py", live_record, "sample with an injected comment"
    )
    live_record["guard_events"] = sorted({e["event"] for e in security_events()})
    assert patched.outcome is PatchOutcome.PATCHED, explain(patched)
    assert "already migrated" not in patched.patched_source.lower(), explain(patched)
    assert {"guardrail_input", "instruction_ignored"} <= {e["event"] for e in security_events()}
    assert verified(live_record, finding, INJECTED, patched).outcome.value == "pass", explain(patched)
