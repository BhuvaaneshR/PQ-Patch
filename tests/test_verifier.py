import textwrap

import pytest

from pq_patch.detector import scan_file
from pq_patch.schemas import VerificationOutcome, VerificationResult
from pq_patch.verifier import verify

ORIGINAL = textwrap.dedent(
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    def make_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    """
)

GOOD_PATCH = textwrap.dedent(
    """
    def make_key():
        return "ml-dsa-65-key"
    """
)

TEST_FILE = textwrap.dedent(
    """
    from signer import make_key

    def test_make_key():
        assert make_key()
    """
)


def project(tmp_path, original=ORIGINAL, tests=TEST_FILE):
    (tmp_path / "signer.py").write_text(original)
    if tests is not None:
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_signer.py").write_text(tests)
    return tmp_path


def finding_for(tmp_path):
    result = scan_file(tmp_path / "signer.py")
    assert len(result.findings) == 1
    return result.findings[0]


def run(tmp_path, patched, **kw):
    f = finding_for(tmp_path)
    return verify(f, (tmp_path / "signer.py").read_text(), patched, project_root=tmp_path, **kw)


# --- compile ---------------------------------------------------------------


def test_pass_when_compiles_detector_clear_and_tests_pass(tmp_path):
    project(tmp_path)
    r = run(tmp_path, GOOD_PATCH)
    assert r.outcome is VerificationOutcome.PASS
    assert r.compile_ok and r.detector_clear is True and r.tests_ran and r.tests_passed is True


def test_failed_compile_reports_line_and_skips_other_checks(tmp_path):
    project(tmp_path)
    r = run(tmp_path, "def make_key(:\n    pass\n")
    assert r.outcome is VerificationOutcome.FAILED_COMPILE
    assert not r.compile_ok and r.detector_clear is None and not r.tests_ran
    assert "SyntaxError" in r.output and "line 1" in r.output


def test_null_bytes_are_a_compile_failure_not_a_crash(tmp_path):
    project(tmp_path)
    r = run(tmp_path, "x = 1\x00")
    assert r.outcome is VerificationOutcome.FAILED_COMPILE


def test_patched_source_is_never_executed(tmp_path):
    project(tmp_path)
    marker = tmp_path / "ran.txt"
    patch = GOOD_PATCH + f"\nopen({str(marker)!r}, 'w').write('x')\n"
    verify(finding_for(tmp_path), ORIGINAL, patch)  # no project root: compile + detector only
    assert not marker.exists()


# --- detector ----------------------------------------------------------------


def test_needs_review_when_original_call_remains(tmp_path):
    project(tmp_path, tests=None)  # detector check only; cryptography need not be installed
    still_vulnerable = ORIGINAL + "\n# migrated\n"
    r = run(tmp_path, still_vulnerable)
    assert r.outcome is VerificationOutcome.NEEDS_REVIEW
    assert r.detector_clear is False and "still present" in r.output


def test_needs_review_when_patch_adds_a_new_finding(tmp_path):
    project(tmp_path, tests=None)
    patch = textwrap.dedent(
        """
        from cryptography.hazmat.primitives.asymmetric import ec

        def make_key():
            return ec.generate_private_key(ec.SECP256R1())
        """
    )
    r = run(tmp_path, patch)
    assert r.outcome is VerificationOutcome.NEEDS_REVIEW
    assert r.detector_clear is False and "new finding" in r.output


def test_needs_review_when_finding_not_in_original(tmp_path):
    project(tmp_path, tests=None)
    f = finding_for(tmp_path)
    r = verify(f, "x = 1\n", GOOD_PATCH)
    assert r.outcome is VerificationOutcome.NEEDS_REVIEW
    assert r.detector_clear is False and "not present in the original" in r.output


def test_detector_not_evaluated_when_patched_file_cannot_be_analysed(tmp_path):
    project(tmp_path, tests=None)
    deep = "x = " + "+".join(["1"] * 2000) + "\n"  # may compile, but overflows the detector visitor
    r = verify(finding_for(tmp_path), ORIGINAL, deep)
    assert r.outcome in (VerificationOutcome.FAILED_COMPILE, VerificationOutcome.NEEDS_REVIEW)
    if r.compile_ok:
        assert r.detector_clear is None


def test_line_shifts_do_not_count_as_new_findings(tmp_path):
    project(tmp_path)
    patch = "# a comment\n# another\n" + GOOD_PATCH
    assert run(tmp_path, patch).outcome is VerificationOutcome.PASS


# --- review of guesses -----------------------------------------------------------


GUESSING_PATCH = textwrap.dedent(
    """
    def make_key(size):
        # Assume size has a to_bits() method
        return size.to_bits()
    """
)
GUESS_ORIGINAL = textwrap.dedent(
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    def make_key(size):
        return rsa.generate_private_key(public_exponent=65537, key_size=size.bits)
    """
)


def test_a_patch_that_assumes_an_api_is_needs_review_even_though_everything_else_passes(tmp_path):
    (tmp_path / "signer.py").write_text(GUESS_ORIGINAL)
    f = scan_file(tmp_path / "signer.py").findings[0]
    r = verify(f, GUESS_ORIGINAL, GUESSING_PATCH)
    assert r.compile_ok and r.detector_clear is True  # the old checks are all satisfied...
    assert r.outcome is VerificationOutcome.NEEDS_REVIEW  # ...and still it is not a pass
    assert "[review] needs a person" in r.output and "size.to_bits" in r.output


def test_review_findings_do_not_hide_a_failing_test(tmp_path):
    project(tmp_path)
    patch = "def make_key():\n    # TODO make this real\n    return None\n"
    assert run(tmp_path, patch).outcome is VerificationOutcome.FAILED_TEST


def test_a_clean_patch_says_the_review_found_nothing(tmp_path):
    project(tmp_path, tests=None)
    r = run(tmp_path, GOOD_PATCH)
    assert r.outcome is VerificationOutcome.PASS and "[review] no assumptions found" in r.output


def test_a_stale_docstring_is_noted_but_does_not_block_a_pass(tmp_path):
    original = textwrap.dedent(
        '''
        from cryptography.hazmat.primitives.asymmetric import rsa

        def make_key():
            """Create an RSA key."""
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        '''
    )
    (tmp_path / "signer.py").write_text(original)
    f = scan_file(tmp_path / "signer.py").findings[0]
    patched = 'def make_key():\n    """Create an RSA key."""\n    return b"ml-dsa-key"\n'
    r = verify(f, original, patched)
    assert r.outcome is VerificationOutcome.PASS
    assert "[review] note: the docstring of `make_key` still names the old algorithm" in r.output


# --- tests -------------------------------------------------------------------


def test_failed_test_when_patch_breaks_behaviour(tmp_path):
    project(tmp_path)
    r = run(tmp_path, "def make_key():\n    return None\n")
    assert r.outcome is VerificationOutcome.FAILED_TEST
    assert r.tests_ran and r.tests_passed is False and "test_make_key" in r.output


def test_failed_test_takes_priority_over_needs_review(tmp_path):
    project(tmp_path)
    # still vulnerable (detector not clear) and the tests fail; the failed test wins.
    # The original call is imported lazily so the sandbox does not need cryptography.
    patch = textwrap.dedent(
        """
        def make_key():
            return None
            from cryptography.hazmat.primitives.asymmetric import rsa
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """
    )
    r = run(tmp_path, patch)
    assert r.outcome is VerificationOutcome.FAILED_TEST and r.detector_clear is False


def test_timeout_is_failed_test_timeout(tmp_path):
    project(
        tmp_path,
        tests="import time\nfrom signer import make_key\n\ndef test_slow():\n    time.sleep(10)\n",
    )
    r = run(tmp_path, GOOD_PATCH, test_timeout=1)
    assert r.outcome is VerificationOutcome.FAILED_TEST_TIMEOUT
    assert r.outcome.value == "failed_test(timeout)"
    assert r.tests_ran and r.tests_passed is False and "timed out" in r.output


def test_ordinary_test_failure_is_not_reported_as_timeout(tmp_path):
    project(tmp_path)
    r = run(tmp_path, "def make_key():\n    return None\n")
    assert r.outcome is VerificationOutcome.FAILED_TEST and r.outcome is not VerificationOutcome.FAILED_TEST_TIMEOUT


def test_no_tests_means_tests_not_run_but_can_still_pass(tmp_path):
    project(tmp_path, tests=None)
    r = run(tmp_path, GOOD_PATCH)
    assert r.outcome is VerificationOutcome.PASS
    assert not r.tests_ran and r.tests_passed is None and "tests not run" in r.output


def test_unrelated_tests_are_not_run(tmp_path):
    project(tmp_path)
    (tmp_path / "tests" / "test_other.py").write_text("def test_broken():\n    assert False\n")
    assert run(tmp_path, GOOD_PATCH).outcome is VerificationOutcome.PASS


def test_explicit_test_paths_override_selection(tmp_path):
    project(tmp_path)
    (tmp_path / "tests" / "test_other.py").write_text("def test_broken():\n    assert False\n")
    r = run(tmp_path, GOOD_PATCH, test_paths=["tests/test_other.py"])
    assert r.outcome is VerificationOutcome.FAILED_TEST


# --- isolation -----------------------------------------------------------------


def test_original_file_is_not_modified(tmp_path):
    project(tmp_path)
    run(tmp_path, GOOD_PATCH)
    assert (tmp_path / "signer.py").read_text() == ORIGINAL
    assert not list(tmp_path.rglob("*.pyc"))


def test_tests_see_the_patch_and_not_env_files_or_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "super-secret")
    (tmp_path / ".env").write_text("LLM_API_KEY=super-secret\n")
    isolation_test = textwrap.dedent(
        """
        import os
        from pathlib import Path
        from signer import make_key

        def test_isolated():
            assert make_key() == "ml-dsa-65-key"   # the patch, not the original
            assert not Path(".env").exists()
            assert "LLM_API_KEY" not in os.environ
        """
    )
    project(tmp_path, tests=isolation_test)
    r = run(tmp_path, GOOD_PATCH)
    assert r.outcome is VerificationOutcome.PASS, r.output


# --- caller errors ---------------------------------------------------------------


def test_file_outside_project_root_is_a_caller_error(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "signer.py"
    outside.write_text(ORIGINAL)
    f = scan_file(outside).findings[0]
    with pytest.raises(ValueError, match="not inside the project root"):
        verify(f, ORIGINAL, GOOD_PATCH, project_root=root)


def test_result_is_a_valid_schema_object(tmp_path):
    project(tmp_path)
    r = run(tmp_path, GOOD_PATCH)
    assert VerificationResult.model_validate(r.model_dump()) == r


def test_deterministic_for_same_input(tmp_path):
    project(tmp_path, tests=None)
    f = finding_for(tmp_path)
    assert verify(f, ORIGINAL, GOOD_PATCH) == verify(f, ORIGINAL, GOOD_PATCH)
