"""The Streamlit page, driven headlessly against the course stub (no browser, no real model)."""

import ast
from pathlib import Path

import pytest

streamlit_testing = pytest.importorskip("streamlit.testing.v1")
AppTest = streamlit_testing.AppTest

import observability  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app.py"


@pytest.fixture
def app(tmp_path, monkeypatch, security_events):
    """An AppTest wired to the stub, with every log in a temp folder."""
    monkeypatch.setenv("LLM_API_KEY", "not-needed")
    monkeypatch.setenv("LLM_BASE_URL", "local://stub")
    monkeypatch.setenv("LLM_MODEL", "stub:ok")
    monkeypatch.setenv("STUB_SAMPLES_DIR", str(ROOT / "samples"))
    monkeypatch.delenv("LLM_FALLBACK_MODELS", raising=False)
    monkeypatch.delenv("LLM_TPM_LIMIT", raising=False)
    monkeypatch.setattr(observability, "LOG_PATH", str(tmp_path / "run_log.jsonl"))
    monkeypatch.chdir(tmp_path)
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.run()
    assert not at.exception
    return at


def click(at, label):
    button = next(b for b in at.button if b.label == label)
    button.click()
    at.run()
    assert not at.exception, at.exception
    return at


def labels(at):
    return [b.label for b in at.button]


def start_sample(at):
    return click(at, "Use the sample")


def text_of(at):
    return "\n".join(str(x.value) for x in [*at.markdown, *at.text, *at.error, *at.warning, *at.success, *at.info, *at.caption, *at.code])


def test_first_page_offers_the_ways_to_choose_a_file(app):
    assert "Use the sample" in labels(app) and "Analyse pasted code" in labels(app)
    assert "Post-quantum patching" in app.title[0].value


def test_pasting_garbage_shows_why_and_makes_no_session(app):
    app.text_area[0].set_value("def broken(:\n")
    click(app, "Analyse pasted code")
    assert any("not valid Python" in e.value for e in app.error)
    assert "session" not in app.session_state


def test_pasting_nothing_is_rejected(app):
    click(app, "Analyse pasted code")
    assert any("empty" in e.value for e in app.error)


def test_sample_shows_one_finding_and_makes_no_model_call(app):
    start_sample(app)
    assert app.session_state["session"].model_calls == 0
    assert "Draft a plan" in labels(app)
    assert "Approve plan and draft the patch" not in labels(app)


def test_the_plan_waits_for_approval_and_no_patch_exists_until_then(app):
    start_sample(app)
    click(app, "Draft a plan")
    session = app.session_state["session"]
    rec = session.records[0]
    assert rec.state.value == "awaiting_plan_approval" and rec.patch_result is None
    assert "No patch is drafted until you approve" in text_of(app)
    app.run()  # rerunning the page, however often, approves nothing
    assert rec.state.value == "awaiting_plan_approval" and session.model_calls == 1


def test_approving_drafts_a_patch_shows_the_diff_and_the_verdict(app):
    start_sample(app)
    click(app, "Draft a plan")
    click(app, "Approve plan and draft the patch")
    rec = app.session_state["session"].records[0]
    assert rec.state.value == "ready_for_review" and rec.verification.outcome.value == "pass"
    shown = text_of(app)
    assert "Verifier: pass" in shown and "--- a/samples/sample_input.py" in shown
    assert "Download diff" in [d.proto.label for d in app.get("download_button")]


def test_escalating_at_the_plan_checkpoint_never_drafts_a_patch(app):
    start_sample(app)
    click(app, "Draft a plan")
    click(app, "Escalate to a person")
    session = app.session_state["session"]
    assert session.records[0].state.value == "escalated" and session.records[0].patch_result is None
    assert session.model_calls == 1


def test_revise_needs_feedback_before_the_button_works(app):
    start_sample(app)
    click(app, "Draft a plan")
    revise = next(b for b in app.button if b.label == "Revise plan")
    assert revise.disabled
    app.text_area[0].set_value("use the highest level")
    app.run()
    click(app, "Revise plan")
    rec = app.session_state["session"].records[0]
    assert rec.state.value == "awaiting_plan_approval" and rec.plan_revisions == 1


def test_a_failing_model_is_shown_and_can_be_retried(app, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "stub:error")
    start_sample(app)
    click(app, "Draft a plan")
    rec = app.session_state["session"].records[0]
    assert rec.state.value == "awaiting_failure_decision"
    assert "needs your decision" in text_of(app) or any("The plan step ended: error" in e.value for e in app.error)
    assert "Retry the plan" in labels(app)


def test_start_over_returns_to_the_first_page(app):
    start_sample(app)
    click(app, "Start over")
    assert "Use the sample" in labels(app) and "session" not in app.session_state


def test_a_file_with_nothing_to_fix_says_so(app):
    app.text_area[0].set_value("def add(a, b):\n    return a + b\n")
    click(app, "Analyse pasted code")
    assert any("No RSA or ECDSA signing calls" in s.value for s in app.success)
    assert app.session_state["session"].model_calls == 0


# --- the course's structural rule: the UI calls the pipeline and never a model ---------------------------


def test_the_ui_never_imports_client_or_a_model_sdk():
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported & {"client", "stub_client", "openai", "anthropic", "groq"}
    assert "pq_patch" in imported
