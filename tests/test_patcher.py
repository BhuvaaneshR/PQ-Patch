import ast
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import stub_client
from pq_patch.detector import scan_file, scan_source
from pq_patch.llm_client import StructuredLLM
from pq_patch.patcher import (
    MAX_FAILURE_CHARS,
    MAX_FEEDBACK_CHARS,
    MAX_SCOPE_CHARS,
    PatchOutcome,
    apply_patch,
    make_diff,
    patch_finding,
    scope_for_prompt,
)
from pq_patch.planner import PlanOutcome, plan_finding
from pq_patch.schemas import Patch, Plan, ReportRow
from pq_patch.verifier import verify

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
CANARY = stub_client.CANARY

PLAN = Plan(usage_context="signing", target_algorithm="ML-DSA-65", approach="Swap the RSA call for an oqs signer.")

SRC = textwrap.dedent(
    '''\
    """Module doc."""
    import os
    from cryptography.hazmat.primitives.asymmetric import padding


    def keep():
        return 1


    def sign(key, m):
        return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)


    def tail():
        return 2
    '''
)
NEW_SIGN = "def sign(key, m):\n    return m\n"


def finding_for(source, name="t.py"):
    result = scan_source(source, name)
    assert result.parse_ok and len(result.findings) == 1, result
    return result.findings[0]


def apply(source, new_source=NEW_SIGN, imports=(), **kw):
    return apply_patch(finding_for(source), source, Patch(new_source=new_source, imports=list(imports), **kw))


# --- apply_patch: the splice -----------------------------------------------------------------


def test_only_the_scope_changes_and_the_result_parses():
    out = apply(SRC).patched_source
    ast.parse(out)
    assert "def sign(key, m):\n    return m\n" in out
    for untouched in ("def keep():\n    return 1\n", "def tail():\n    return 2\n", '"""Module doc."""\nimport os\n'):
        assert untouched in out
    assert "padding.PSS" not in out.split("def tail")[0].split("def sign")[1]


def test_apply_is_deterministic():
    f = finding_for(SRC)
    p = Patch(new_source=NEW_SIGN, imports=["import oqs"])
    assert apply_patch(f, SRC, p) == apply_patch(f, SRC, p)


def test_method_is_reindented_and_the_rest_of_the_class_is_untouched():
    source = textwrap.dedent(
        """\
        from cryptography.hazmat.primitives.asymmetric import padding


        class Svc:
            name = "svc"

            def sign(self, key, m):
                return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)

            def other(self):
                return 3
        """
    )
    out = apply(source, "def sign(self, key, m):\n    return m\n").patched_source
    ast.parse(out)
    assert '    name = "svc"\n' in out and "    def sign(self, key, m):\n        return m\n" in out
    assert "    def other(self):\n        return 3\n" in out


CLASS_WITH_METHOD = textwrap.dedent(
    '''\
    from cryptography.hazmat.primitives.asymmetric import padding


    class Svc:
        def sign(self, key, m):
            return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)
    '''
)
ALIGNED = (
    '    def sign(self, key, m):\n        """Line one.\n\n        More text.\n          Indented detail.\n        """\n        return m\n'
)


@pytest.mark.parametrize("margin", [0, 4, 8, 12])
def test_a_multiline_docstring_is_realigned_whatever_margin_the_model_used(margin):
    # The model sometimes writes the body at the file's absolute indentation, sometimes at the shown one.
    pad = " " * margin
    new = f'def sign(self, key, m):\n    """Line one.\n\n{pad}More text.\n{pad}  Indented detail.\n{pad}"""\n    return m\n'
    out = apply(CLASS_WITH_METHOD, new).patched_source
    assert ALIGNED in out
    doc = ast.get_docstring(ast.parse(out).body[1].body[0])
    assert doc == "Line one.\n\nMore text.\n  Indented detail."  # cleaned text identical; relative indent kept


def test_other_multiline_strings_keep_their_text_exactly():
    new = 'def sign(self, key, m):\n    banner = """top\n  middle\nbottom"""\n    return m\n'
    out = apply(CLASS_WITH_METHOD, new).patched_source
    assert '        banner = """top\n  middle\nbottom"""\n        return m\n' in out
    assert ast.parse(out).body[1].body[0].body[0].value.value == "top\n  middle\nbottom"


def test_a_normal_docstring_round_trips_through_the_prompt_unchanged():
    source = CLASS_WITH_METHOD.replace(
        "    def sign(self, key, m):\n",
        '    def sign(self, key, m):\n        """Sign.\n\n        Details here.\n        """\n',
    )
    f = finding_for(source)
    scope, _ = scope_for_prompt(f, source)
    assert '\n    """Sign.\n\n    Details here.\n    """\n' in scope  # shown fully dedented, docstring included
    assert apply_patch(f, source, Patch(new_source=scope)).patched_source == source


def test_scope_shown_to_the_model_is_dedented_and_round_trips():
    source = "from cryptography.hazmat.primitives.asymmetric import padding\n\n\nclass A:\n    def sign(self, k, m):\n        return k.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    f = finding_for(source)
    scope, indent = scope_for_prompt(f, source)
    assert indent == "    " and scope.startswith("def sign(self, k, m):\n    return k.sign(")
    assert apply_patch(f, source, Patch(new_source=scope)).patched_source == source  # identity patch changes nothing


def test_decorators_are_part_of_the_replaced_scope():
    source = textwrap.dedent(
        """\
        from cryptography.hazmat.primitives.asymmetric import padding

        @deco
        def sign(key, m):
            return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)

        x = 1
        """
    )
    out = apply(source, "@deco\ndef sign(key, m):\n    return m\n").patched_source
    assert out.count("@deco") == 1 and out.endswith("x = 1\n")


def test_module_level_statement_is_replaced():
    source = "from cryptography.hazmat.primitives.asymmetric import padding\nsig = key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\nafter = 1\n"
    out = apply(source, "sig = b''").patched_source
    assert out == "from cryptography.hazmat.primitives.asymmetric import padding\nsig = b''\nafter = 1\n"


def test_form_feed_in_the_file_does_not_shift_the_splice():
    source = "from cryptography.hazmat.primitives.asymmetric import padding\n\x0c\n\ndef sign(key, m):\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    out = apply(source).patched_source
    assert out == "from cryptography.hazmat.primitives.asymmetric import padding\n\x0c\n\ndef sign(key, m):\n    return m\n"


# --- line endings ------------------------------------------------------------------------------------


def test_crlf_files_stay_crlf():
    source = SRC.replace("\n", "\r\n")
    out = apply(source).patched_source
    assert "\r\n" in out and out.replace("\r\n", "").count("\n") == 0 and out.replace("\r\n", "").count("\r") == 0


def test_missing_final_newline_is_preserved():
    source = "from cryptography.hazmat.primitives.asymmetric import padding\n\n\ndef sign(key, m):\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)"
    assert apply(source).patched_source.endswith("    return m")
    assert apply(source + "\n").patched_source.endswith("    return m\n")


# --- imports ---------------------------------------------------------------------------------------------


def test_new_import_goes_after_the_last_top_level_import():
    out = apply(SRC, imports=["import oqs"]).patched_source
    lines = out.splitlines()
    assert lines.index("import oqs") == lines.index("from cryptography.hazmat.primitives.asymmetric import padding") + 1


def test_existing_and_duplicate_imports_are_not_added_twice():
    r = apply(SRC, imports=["import os", "import oqs", "import oqs"])
    assert r.patched_source.count("import os\n") == 1 and r.patched_source.count("import oqs\n") == 1
    assert any("already present" in n for n in r.notes)


def test_import_equivalent_by_syntax_is_recognised_as_present():
    source = SRC.replace("import os", "import  os")
    assert apply(source, imports=["import os"]).patched_source.count("import") == source.count("import")


def test_import_goes_right_after_the_docstring_when_no_import_precedes_the_scope():
    # the only import comes after the function, so none "precedes" it
    source = (
        '"""Doc."""\n\ndef sign(key, m):\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n\n'
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
    )
    out = apply(source, imports=["import oqs"]).patched_source
    assert out.startswith('"""Doc."""\n\nimport oqs\n\n') and "def sign(key, m):\n    return m\n" in out
    ast.parse(out)


def test_import_before_first_statement_keeps_header_comments_and_future_imports_first():
    source = "# license header\nfrom __future__ import annotations\nfrom cryptography.hazmat.primitives.asymmetric import padding\n\nsig = key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    out = apply(source, "sig = b''", imports=["import oqs"]).patched_source
    assert out.startswith("# license header\nfrom __future__ import annotations\n") and "import oqs" in out
    ast.parse(out)


def test_import_goes_before_the_first_statement_when_there_is_no_docstring_or_earlier_import():
    source = (
        "def sign(key, m):\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n\n"
        "from cryptography.hazmat.primitives.asymmetric import padding\n"
    )
    out = apply(source, imports=["import oqs"]).patched_source
    assert out.startswith("import oqs\n\ndef sign(key, m):\n    return m\n")
    ast.parse(out)


def test_malformed_import_is_rejected_with_a_clear_error():
    f = finding_for(SRC)
    with pytest.raises(ValueError, match="not valid Python"):
        apply_patch(f, SRC, Patch(new_source=NEW_SIGN, imports=["from x import ()"]))


# --- look-alike punctuation --------------------------------------------------------------------------------


def test_lookalike_characters_that_break_the_code_are_repaired_and_noted():
    broken = "def sign(key, m):\n    return m \u2011 0\n"
    r = apply(SRC, broken)
    assert "return m - 0" in r.patched_source and any("look-alike" in n for n in r.notes)
    ast.parse(r.patched_source)


def test_legitimate_unicode_in_a_string_is_never_touched():
    fine = 'def sign(key, m):\n    return "a\u2013b \u2018x\u2019"\n'
    r = apply(SRC, fine)
    assert "a\u2013b \u2018x\u2019" in r.patched_source and not r.notes


# --- caller errors ------------------------------------------------------------------------------------------


def test_finding_that_does_not_belong_to_the_source_is_rejected():
    f = finding_for(SRC)
    with pytest.raises(ValueError, match="does not match"):
        apply_patch(f, "x = 1\n", Patch(new_source=NEW_SIGN))


# --- the diff -------------------------------------------------------------------------------------------------


def test_diff_has_headers_and_only_the_changed_lines():
    out = apply(SRC).patched_source
    diff = make_diff("pkg/mod.py", SRC, out)
    assert diff.startswith("--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@")
    assert "-    return key.sign(" in diff and "+    return m\n" in diff
    changed = [ln for ln in diff.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]
    assert changed == ["-    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)", "+    return m"]
    assert make_diff("x.py", SRC, SRC) == ""


def test_diff_names_are_posix_and_never_absolute():
    assert make_diff("C:/Users/x/f.py", "a\n", "b\n").startswith("--- a/Users/x/f.py\n+++ b/Users/x/f.py\n")


@pytest.mark.parametrize("given", ["../targets/pyjwt/jwt/a.py", "./pkg/a.py", "..\\..\\pkg\\a.py"])
def test_diff_names_never_start_with_dot_dot_or_dot_slash(given):
    header = make_diff(given, "a\n", "b\n").splitlines()[0]
    assert header.startswith("--- a/") and "/../" not in header and not header.startswith(("--- a/../", "--- a/./"))


def test_diff_handles_a_file_with_no_final_newline():
    assert make_diff("f.py", "a\nb", "a\nc").endswith("-b\n+c\n")


# --- patch_finding through the course stub -----------------------------------------------------------------


@pytest.fixture
def stub(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "local://stub")
    monkeypatch.setenv("STUB_SAMPLES_DIR", str(SAMPLES))
    monkeypatch.chdir(tmp_path)
    stub_client._CALLS.clear()
    return lambda mode: monkeypatch.setenv("LLM_MODEL", f"stub:{mode}")


@pytest.fixture
def make_llm(tmp_path, security_events):
    return lambda **kw: StructuredLLM(sleep=lambda s: None, log_path=str(tmp_path / "run_log.jsonl"), **kw)


SAMPLE = (SAMPLES / "sample_input.py").read_text(encoding="utf-8")
INJECTED = (SAMPLES / "injected_input.py").read_text(encoding="utf-8")


def sample_finding(name="samples/sample_input.py"):
    return scan_file(ROOT / name).findings[0]


def test_stub_ok_patches_the_sample_and_the_verifier_passes(stub, make_llm):
    stub("ok")
    f = sample_finding()
    r = patch_finding(f, SAMPLE, PLAN, llm=make_llm(), display_name="samples/sample_input.py")
    assert r.outcome is PatchOutcome.PATCHED and r.calls == 1
    assert 'oqs.Signature("ML-DSA-65"' in r.patched_source and "padding.PSS(" not in r.patched_source
    assert "+import oqs" in r.diff and r.diff.startswith("--- a/samples/sample_input.py")
    v = verify(f, SAMPLE, r.patched_source)
    assert v.outcome.value == "pass" and v.detector_clear is True


def test_whole_stub_pipeline_plan_patch_verify_report(stub, make_llm):
    stub("ok")
    llm = make_llm()
    f = sample_finding()
    plan = plan_finding(f, SAMPLE, llm=llm)
    assert plan.outcome is PlanOutcome.PLANNED
    patch = patch_finding(f, SAMPLE, plan.plan, llm=llm, display_name="samples/sample_input.py")
    assert patch.outcome is PatchOutcome.PATCHED
    v = verify(f, SAMPLE, patch.patched_source)
    row = ReportRow(
        file="samples/sample_input.py", line=f.line, original_call=f.original_call, target_algorithm=plan.plan.target_algorithm,
        proposed_patch=patch.diff, verification_result=v.outcome, attempts=1, status="ready_for_review",
    )
    assert row.status.value == "ready_for_review"


@pytest.mark.parametrize(
    "mode,outcome,calls",
    [
        ("malformed", PatchOutcome.INVALID_OUTPUT, 2),
        ("badshape", PatchOutcome.INVALID_OUTPUT, 2),
        ("empty", PatchOutcome.INVALID_OUTPUT, 2),
        ("refused", PatchOutcome.REFUSED, 1),
        ("error", PatchOutcome.ERROR, 3),
    ],
)
def test_stub_failure_modes_never_produce_a_patch(stub, make_llm, mode, outcome, calls):
    stub(mode)
    r = patch_finding(sample_finding(), SAMPLE, PLAN, llm=make_llm())
    assert (r.outcome, r.patch, r.patched_source, r.diff, r.calls) == (outcome, None, None, None, calls)
    assert r.reason


def test_obedient_stub_cannot_taint_the_patch_through_injected_code(stub, make_llm, security_events):
    stub("obedient")
    f = sample_finding("samples/injected_input.py")
    r = patch_finding(f, INJECTED, PLAN, llm=make_llm())
    assert r.outcome is PatchOutcome.PATCHED
    assert CANARY not in r.patched_source and CANARY not in r.diff
    assert {"guardrail_input", "instruction_ignored"} <= {e["event"] for e in security_events()}
    assert verify(f, INJECTED, r.patched_source).outcome.value == "pass"


# --- patch_finding with a fake provider -----------------------------------------------------------------------


def reply(content):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, refusal=None, tool_calls=None), finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
    )


class FakeClient:
    def __init__(self, *contents):
        self.contents, self.calls = list(contents), []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kw):
        self.calls.append(kw)
        return reply(self.contents.pop(0))


@pytest.fixture
def fake(make_llm):
    def build(*contents):
        llm, client = make_llm(), FakeClient(*contents)
        llm._client_factory, llm._model_name = (lambda: client), (lambda: "fake")
        return llm, client

    return build


GOOD = json.dumps({"patch": {"new_source": NEW_SIGN, "imports": ["import oqs"], "explanation": "ok"}})


def user_text(client, call=0):
    return client.calls[call]["messages"][1]["content"]


def test_escalation_from_the_model_is_returned_with_its_reason(fake):
    llm, _ = fake(json.dumps({"escalate": {"reason": "needs changes in the callers too"}}))
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert (r.outcome, r.patch, r.reason) == (PatchOutcome.ESCALATED, None, "needs changes in the callers too")


def test_too_large_a_scope_is_escalated_without_asking_the_model(fake):
    body = "\n".join(f"    x{i} = {i}  # padding" for i in range(1500))
    source = f"from cryptography.hazmat.primitives.asymmetric import padding\n\ndef big(key, m):\n{body}\n    return key.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    llm, client = fake()
    r = patch_finding(finding_for(source), source, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.ESCALATED and "too large" in r.reason and client.calls == []
    assert len(scope_for_prompt(finding_for(source), source)[0]) > MAX_SCOPE_CHARS


def test_a_malformed_import_in_a_valid_reply_is_invalid_output_not_a_crash(fake):
    bad = json.dumps({"patch": {"new_source": NEW_SIGN, "imports": ["from x import ()"]}})
    llm, _ = fake(bad)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.INVALID_OUTPUT and "could not be applied" in r.reason and r.patched_source is None


def test_a_reply_with_both_patch_and_escalate_is_rejected(fake):
    both = json.dumps({"patch": {"new_source": NEW_SIGN}, "escalate": {"reason": "nope nope"}})
    llm, _ = fake(both, both)
    assert patch_finding(finding_for(SRC), SRC, PLAN, llm=llm).outcome is PatchOutcome.INVALID_OUTPUT


def test_prompt_has_plan_scope_imports_rules_and_names_the_algorithm(fake):
    llm, client = fake(GOOD)
    assert patch_finding(finding_for(SRC), SRC, PLAN, llm=llm).outcome is PatchOutcome.PATCHED
    user = user_text(client)
    assert "Approved plan" in user and "Swap the RSA call" in user and "ML-DSA-65" in user
    assert "<<<UNTRUSTED scope_code" in user and "def sign(key, m):" in user and "<<<UNTRUSTED imports" in user
    assert "oqs.Signature" in user and "ASCII" in user
    assert "previous_patch" not in user and "verifier_output" not in user and "Reviewer guidance" not in user


def test_untrusted_code_is_only_in_the_user_message_and_trusted_text_is_clean(fake, security_events):
    llm, client = fake(GOOD)
    patch_finding(finding_for(SRC), SRC, PLAN, llm=llm, feedback="keep the helper name")
    system = client.calls[0]["messages"][0]["content"]
    assert "padding.PSS" not in system and "def sign" not in system
    text = "\n".join(m["content"] for m in client.calls[0]["messages"])
    assert not any(p.search(text) for p in stub_client.INJECTION_PATTERNS) and security_events() == []


def test_method_scope_is_shown_without_its_indentation_and_the_prompt_says_so(fake):
    source = "from cryptography.hazmat.primitives.asymmetric import padding\n\n\nclass A:\n    def sign(self, k, m):\n        return k.sign(m, padding.PSS(mgf=None, salt_length=0), None)\n"
    llm, client = fake(json.dumps({"patch": {"new_source": "def sign(self, k, m):\n    return m\n"}}))
    r = patch_finding(finding_for(source), source, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and "    def sign(self, k, m):\n        return m\n" in r.patched_source
    user = user_text(client)
    assert "without its base indentation of 4 character(s)" in user and "\ndef sign(self, k, m):\n" in user


def test_retry_sends_previous_patch_failure_output_and_guidance(fake):
    previous = Patch(new_source="def sign(key, m):\n    return None\n")
    llm, client = fake(GOOD)
    r = patch_finding(
        finding_for(SRC), SRC, PLAN, llm=llm, previous_patch=previous,
        failure_output="[tests] failed\nassert sign(k, b'x') == b'sig'", feedback="Return the signature bytes.",
    )
    assert r.outcome is PatchOutcome.PATCHED
    user = user_text(client)
    assert "<<<UNTRUSTED previous_patch" in user and "return None" in user
    assert "<<<UNTRUSTED verifier_output" in user and "assert sign(k, b'x')" in user
    assert "Reviewer guidance: Return the signature bytes." in user and "Fix the problem" in user


def test_very_long_failure_output_keeps_only_the_end(fake):
    llm, client = fake(GOOD)
    noisy = "EARLY-NOISE " * 2000 + "THE-REAL-ERROR"
    patch_finding(finding_for(SRC), SRC, PLAN, llm=llm, failure_output=noisy)
    user = user_text(client)
    assert "THE-REAL-ERROR" in user and user.count("EARLY-NOISE") < len(noisy) // len("EARLY-NOISE ")
    assert len(user) < MAX_FAILURE_CHARS + 6000


def test_feedback_over_the_limit_is_a_caller_error(fake):
    llm, client = fake()
    with pytest.raises(ValueError, match="limit"):
        patch_finding(finding_for(SRC), SRC, PLAN, llm=llm, feedback="x" * (MAX_FEEDBACK_CHARS + 1))
    assert client.calls == []


def test_source_that_does_not_match_the_finding_is_a_caller_error(fake):
    llm, client = fake()
    with pytest.raises(ValueError, match="does not match"):
        patch_finding(finding_for(SRC), "x = 1\n", PLAN, llm=llm)
    assert client.calls == []


def test_display_name_is_used_in_the_diff_header(fake):
    llm, _ = fake(GOOD)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm, display_name="src/app/mod.py")
    assert r.diff.startswith("--- a/src/app/mod.py\n+++ b/src/app/mod.py\n")


# --- static review and the one self-correction ---------------------------------------------------------------


GUESSING = json.dumps(
    {"patch": {"new_source": "def sign(key, m):\n    # Assume key provides export_secret_key()\n    return key.export_secret_key()\n"}}
)


RENAMED = json.dumps({"patch": {"new_source": "def sign_manifest(private_key, manifest):\n    return manifest\n"}})


def test_a_draft_that_renames_the_function_is_sent_back_once_and_the_fix_is_used(fake):
    llm, client = fake(RENAMED, GOOD)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.calls == 2 and r.problems == () and "def sign(key, m):" in r.patched_source
    second = user_text(client, 1)
    assert "`sign` no longer exists" in second and "static review of your patch found" in second


def test_a_draft_that_renames_the_function_twice_is_reported_not_hidden(fake):
    llm, _ = fake(RENAMED, RENAMED)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.calls == 2 and any("no longer exists" in p for p in r.problems)
    assert verify(finding_for(SRC), SRC, r.patched_source).outcome.value == "needs_review"


def test_a_clean_first_draft_costs_one_call_and_has_no_findings(fake):
    llm, client = fake(GOOD)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert (r.calls, r.problems, r.warnings) == (1, (), ()) and len(client.calls) == 1


def test_a_guessing_draft_is_sent_back_once_with_the_findings_and_the_fix_is_used(fake):
    llm, client = fake(GUESSING, GOOD)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and r.calls == 2 and r.problems == ()
    assert "return m" in r.patched_source and "export_secret_key" not in r.patched_source
    assert any("revised once" in n for n in r.notes)
    second = user_text(client, 1)
    assert "<<<UNTRUSTED verifier_output" in second and "static review of your patch found" in second
    assert "`key.export_secret_key`" in second and "<<<UNTRUSTED previous_patch" in second


def test_when_the_second_draft_is_no_better_the_first_is_kept_and_the_problems_are_reported(fake):
    llm, client = fake(GUESSING, GUESSING)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and r.calls == 2 and len(client.calls) == 2  # never a third call
    assert len(r.problems) == 2 and any(n.startswith("needs attention:") for n in r.notes)
    assert not any("revised once" in n for n in r.notes)


def test_a_broken_second_draft_does_not_lose_the_first(fake):
    llm, _ = fake(GUESSING, "not json", "still not json")
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and "export_secret_key" in r.patched_source
    assert r.calls == 3 and len(r.problems) == 2  # 1 + the second draft's own re-ask


def test_a_better_but_still_imperfect_second_draft_is_preferred(fake):
    one_problem = json.dumps({"patch": {"new_source": "def sign(key, m):\n    return key.export_secret_key()\n"}})
    llm, _ = fake(GUESSING, one_problem)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert len(r.problems) == 1 and "# Assume" not in r.patched_source and r.calls == 2


STALE = json.dumps({"patch": {"new_source": 'def sign(key, m):\n    """Sign with RSA-PSS."""\n    return m\n'}})
SRC_WITH_DOC = SRC.replace("def sign(key, m):\n", 'def sign(key, m):\n    """Sign with RSA-PSS."""\n')
FIXED_DOC = json.dumps({"patch": {"new_source": 'def sign(key, m):\n    """Sign with ML-DSA-65."""\n    return m\n'}})


def test_a_stale_docstring_gets_the_same_second_chance_and_is_only_a_warning(fake):
    llm, _ = fake(STALE, FIXED_DOC)
    r = patch_finding(finding_for(SRC_WITH_DOC), SRC_WITH_DOC, PLAN, llm=llm)
    assert r.calls == 2 and r.warnings == () and "ML-DSA-65" in r.patched_source
    llm, _ = fake(STALE, STALE)
    kept = patch_finding(finding_for(SRC_WITH_DOC), SRC_WITH_DOC, PLAN, llm=llm)
    assert kept.problems == () and len(kept.warnings) == 1 and any(n.startswith("note:") for n in kept.notes)


def test_both_prompts_tell_the_model_that_keys_become_bytes_and_not_to_guess(fake):
    llm, client = fake(GOOD)
    patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    user = user_text(client)
    assert "raw `bytes`" in user and "secret_key=<parameter>" in user and "escalate instead" in user
    assert "Do not call methods or read attributes on a parameter" in user


def test_lookalike_repair_is_reported_to_the_reviewer(fake):
    broken = json.dumps({"patch": {"new_source": "def sign(key, m):\n    return m \u2011 0\n"}})
    llm, _ = fake(broken)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and any("look-alike" in n for n in r.notes)


# --- double-escaped model output (seen once in four live runs) -----------------------------------------------------


# What the real model returned in the failing run: escaped quotes in code, so the file stopped compiling.
DOUBLE_ESCAPED_DOCSTRING = 'def sign(key, m):\n    \\"\\"\\"Sign with ML-DSA-65.\\"\\"\\"\n    return m\n'


def test_double_escaped_quotes_are_undone_when_the_patch_would_not_parse():
    r = apply(SRC, DOUBLE_ESCAPED_DOCSTRING)
    ast.parse(r.patched_source)
    assert '    """Sign with ML-DSA-65."""\n    return m\n' in r.patched_source
    assert any("double-escaped" in n for n in r.notes)


def test_a_whole_function_on_one_line_with_literal_backslash_n_is_repaired():
    r = apply(SRC, "def sign(key, m):\\n    return m\\n")
    assert "def sign(key, m):\n    return m\n" in r.patched_source and any("double-escaped" in n for n in r.notes)


def test_look_alikes_and_double_escapes_can_be_repaired_together():
    r = apply(SRC, "def sign(key, m):\\n    return m \u2011 0\\n")
    ast.parse(r.patched_source)
    assert any("look-alike" in n for n in r.notes) and any("double-escaped" in n for n in r.notes)


def test_backslashes_in_code_that_already_parses_are_never_touched():
    fine = 'def sign(key, m):\n    return "a\\nb\\"c"\n'  # a real "\n" escape and a real \" inside a string
    r = apply(SRC, fine)
    assert 'return "a\\nb\\"c"' in r.patched_source and not r.notes


def test_a_patch_that_cannot_be_repaired_is_left_alone_for_the_verifier_to_report():
    r = apply(SRC, "def sign(key, m:\n    return m\n")
    assert "def sign(key, m:" in r.patched_source and not r.notes
    assert verify(finding_for(SRC), SRC, r.patched_source).outcome.value == "failed_compile"


def test_a_double_escaped_reply_is_repaired_without_a_second_model_call(fake):
    llm, client = fake(json.dumps({"patch": {"new_source": DOUBLE_ESCAPED_DOCSTRING}}))
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and r.calls == 1 and r.problems == ()
    assert verify(finding_for(SRC), SRC, r.patched_source).outcome.value == "pass"


# --- compile errors go back to the model once ---------------------------------------------------------------------


BROKEN = json.dumps({"patch": {"new_source": "def sign(key, m):\n    return (m\n"}})


def test_a_patch_that_does_not_compile_is_sent_back_once_with_the_error_and_the_line(fake):
    llm, client = fake(BROKEN, GOOD)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.outcome is PatchOutcome.PATCHED and r.calls == 2 and r.problems == ()
    second = user_text(client, 1)
    assert "does not compile" in second and "SyntaxError" in second and "<<<UNTRUSTED previous_patch" in second
    assert any("revised once" in n for n in r.notes)
    assert verify(finding_for(SRC), SRC, r.patched_source).outcome.value == "pass"


def test_a_patch_that_still_does_not_compile_is_reported_not_hidden(fake):
    llm, client = fake(BROKEN, BROKEN)
    r = patch_finding(finding_for(SRC), SRC, PLAN, llm=llm)
    assert r.calls == 2 and len(client.calls) == 2  # exactly one self-correction
    assert any("does not compile" in p for p in r.problems) and any(n.startswith("needs attention:") for n in r.notes)
    assert verify(finding_for(SRC), SRC, r.patched_source).outcome.value == "failed_compile"
