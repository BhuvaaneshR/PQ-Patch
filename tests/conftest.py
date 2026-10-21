import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

import security

PAUSE_SECONDS = 10  # keeps a free tier's tokens-per-minute budget from running out between live tests
ROOT = Path(__file__).resolve().parents[1]

# Per-process state for the live tests: the preflight runs once, and all tests share one results file.
_LIVE = {"preflight_done": False, "results_file": None}


@pytest.fixture
def security_events(tmp_path, monkeypatch):
    """Send security events to a temp file and return a function that reads them."""
    path = tmp_path / "security_log.jsonl"
    monkeypatch.setattr(security, "LOG_PATH", path)
    return lambda: security.read_events(path)


# --- live tests (python -m pytest -m live) --------------------------------------------------------------


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    setattr(item, "rep_" + call.when, outcome.get_result())  # lets fixtures see whether the test passed


@pytest.fixture(autouse=True)
def _pause_after_live_tests(request):
    yield
    if request.node.get_closest_marker("live") and _LIVE["preflight_done"]:
        time.sleep(PAUSE_SECONDS)


def _results_file() -> Path:
    if _LIVE["results_file"] is None:
        folder = Path(os.getenv("EVAL_RESULTS_DIR") or ROOT / "eval_results")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        _LIVE["results_file"] = folder / f"live_{stamp}.jsonl"
    return _LIVE["results_file"]


def _real_provider_configured() -> bool:
    base = os.getenv("LLM_BASE_URL", "")
    return bool(os.getenv("LLM_API_KEY")) and bool(base) and not base.startswith("local://") and "your-provider.example" not in base


def pytest_collection_finish(session):
    """Before any live test runs, make one tiny call. If it fails, stop the whole run with one sentence.

    Without this, one wrong line in .env makes every live test fail the same way after a long wait.
    Runs only when live tests were selected and a real provider is configured.
    """
    if not any(item.get_closest_marker("live") for item in session.items) or not _real_provider_configured():
        return
    import client
    from live_support import preflight

    try:
        message = preflight(client.get_client(), client.get_model(), os.getenv("LLM_BASE_URL", ""))
    except ImportError as e:  # client.py imports the SDK only when a real provider is used
        message = f"live tests cannot run: {e}. Run: pip install python-dotenv openai."
    if message:
        pytest.exit(message, returncode=2)
    _LIVE["preflight_done"] = True


@pytest.fixture
def live_llm(tmp_path, security_events):
    """A StructuredLLM for the provider in .env, or a skip if none is configured."""
    from pq_patch.llm_client import StructuredLLM

    if not _real_provider_configured():
        pytest.skip(
            "put a real provider in .env: LLM_API_KEY, LLM_BASE_URL and LLM_MODEL "
            "(and make sure python-dotenv is installed, or .env is ignored)"
        )
    return StructuredLLM(max_delay=65, timeout=90, log_path=str(tmp_path / "run_log.jsonl"))


@pytest.fixture
def live_record(request, live_llm):
    """A dict a live test fills with what it saw. It is written to eval_results/ when the test ends."""
    import client
    from live_support import append_record, build_record, usage_from_log

    data: dict = {}
    yield data
    report = getattr(request.node, "rep_call", None)
    passed = None if report is None else report.passed
    failure = None if report is None or report.passed else report.longreprtext
    usage = usage_from_log(Path(live_llm._log_path))
    append_record(_results_file(), build_record(request.node.name, client.get_model(), passed, failure, usage, data))


def pytest_terminal_summary(terminalreporter):
    path = _LIVE["results_file"]
    if path is not None and Path(path).exists():
        terminalreporter.write_line(f"live results recorded in {path}")
        terminalreporter.write_line("compare runs with: python scripts/summarize_live.py")
