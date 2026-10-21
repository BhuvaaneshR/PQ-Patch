"""Offline tests for the helpers the live tests use (no model, no network)."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from live_support import (
    append_record,
    build_record,
    describe_patch,
    describe_plan,
    describe_verification,
    preflight,
    usage_from_log,
)
from pq_patch.patcher import PatchOutcome, PatchResult
from pq_patch.planner import PlanOutcome, PlanResult
from pq_patch.schemas import Patch, Plan, VerificationOutcome, VerificationResult

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import summarize_live  # noqa: E402

URL = "https://api.example.test/v1"


class StatusError(Exception):
    def __init__(self, status_code, text="boom"):
        super().__init__(text)
        self.status_code = status_code


class APIConnectionError(Exception):
    pass


class FakeClient:
    def __init__(self, error=None):
        self.error, self.calls = error, []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kw):
        self.calls.append(kw)
        if self.error:
            raise self.error
        return SimpleNamespace()


# --- preflight ---------------------------------------------------------------------------------------


def test_preflight_passes_when_one_cheap_call_works():
    c = FakeClient()
    assert preflight(c, "some/model", URL) is None
    assert len(c.calls) == 1 and c.calls[0]["model"] == "some/model" and c.calls[0]["max_tokens"] <= 64


def test_a_missing_model_says_what_to_fix_and_names_the_prefix_convention():
    msg = preflight(FakeClient(StatusError(404)), "gpt-oss-120b", URL)
    assert msg.startswith("live tests cannot run:") and "'gpt-oss-120b'" in msg and "LLM_MODEL" in msg
    assert "openai/gpt-oss-120b" in msg


@pytest.mark.parametrize("code", [401, 403])
def test_a_rejected_key_points_at_the_key_without_showing_it(code):
    msg = preflight(FakeClient(StatusError(code, "Incorrect API key sk-live-12345")), "m", URL)
    assert "API key" in msg and str(code) in msg and "sk-live-12345" not in msg


def test_rate_limiting_is_explained_as_temporary():
    assert "rate limiting" in preflight(FakeClient(StatusError(429)), "m", URL)


@pytest.mark.parametrize("name", ["APIConnectionError", "APITimeoutError"])
def test_an_unreachable_provider_names_the_url(name):
    error = type(name, (Exception,), {})("connection reset")
    msg = preflight(FakeClient(error), "m", URL)
    assert URL in msg and name in msg and "LLM_BASE_URL" in msg


def test_other_failures_are_described_briefly_and_truncated():
    msg = preflight(FakeClient(StatusError(500, "x" * 1000)), "m", URL)
    assert "StatusError" in msg and len(msg) < 400


def test_sdk_level_retries_are_switched_off_when_the_client_supports_it():
    class Sdk(FakeClient):
        def with_options(self, **opts):
            self.opts = opts
            return self

    c = Sdk()
    preflight(c, "m", URL)
    assert c.opts == {"max_retries": 0}


# --- records -----------------------------------------------------------------------------------------


def test_usage_totals_come_from_the_run_log_and_skip_bad_lines(tmp_path):
    log = tmp_path / "run_log.jsonl"
    log.write_text(
        json.dumps({"status": "ok", "prompt_tokens": 10, "completion_tokens": 5, "latency_ms": 100, "cost_usd": 0.001, "tokens_estimated": False})
        + "\nnot json\n"
        + json.dumps({"status": "invalid_output", "prompt_tokens": 20, "completion_tokens": None, "latency_ms": 50, "cost_usd": None, "tokens_estimated": True})
        + "\n",
        encoding="utf-8",
    )
    u = usage_from_log(log)
    assert u["calls"] == 2 and u["statuses"] == ["ok", "invalid_output"]
    assert (u["prompt_tokens"], u["completion_tokens"], u["latency_ms"], u["cost_usd"]) == (30, 5, 150, 0.001)
    assert u["tokens_estimated"] is True


def test_usage_for_a_missing_log_is_empty_not_an_error(tmp_path):
    u = usage_from_log(tmp_path / "absent.jsonl")
    assert u["calls"] == 0 and u["prompt_tokens"] is None and u["cost_usd"] is None


def test_a_record_carries_the_verdict_usage_and_data_and_truncates_failures():
    r = build_record("test_x", "m", False, "E " * 2000, {"calls": 1}, {"scenario": "s", "plan": {"outcome": "planned"}})
    assert (r["test"], r["model"], r["passed"], r["usage"]) == ("test_x", "m", False, {"calls": 1})
    assert len(r["failure"]) == 1500 and r["scenario"] == "s" and r["plan"] == {"outcome": "planned"} and r["timestamp"]
    assert build_record("t", "m", True, None, {}, {})["failure"] is None


def test_records_are_appended_one_json_line_each_creating_the_folder(tmp_path):
    path = tmp_path / "deep" / "dir" / "live_x.jsonl"
    append_record(path, {"a": 1, "text": "ML‑DSA"})
    append_record(path, {"a": 2})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(x)["a"] for x in lines] == [1, 2] and "ML‑DSA" in lines[0]


def test_describe_helpers_turn_results_into_plain_data():
    plan = Plan(usage_context="signing", target_algorithm="ML-DSA-65", approach="Swap the RSA call for oqs.", risks=["bigger keys"])
    d = describe_plan(PlanResult(PlanOutcome.PLANNED, plan=plan, calls=1))
    assert d["outcome"] == "planned" and d["target_algorithm"] == "ML-DSA-65" and d["usage_context"] == "signing" and d["risks"] == ["bigger keys"]
    assert describe_plan(PlanResult(PlanOutcome.ESCALATED, reason="key exchange", calls=1))["reason"] == "key exchange"
    p = describe_patch(PatchResult(PatchOutcome.PATCHED, patch=Patch(new_source="x = 1", explanation="e"), diff="--- a", problems=("p",), calls=2))
    assert p["outcome"] == "patched" and p["problems"] == ["p"] and p["explanation"] == "e" and p["diff"] == "--- a" and p["calls"] == 2
    v = describe_verification(VerificationResult(outcome=VerificationOutcome.PASS, compile_ok=True, detector_clear=True, output="[compile] ok"))
    assert v["outcome"] == "pass" and v["compile_ok"] is True and v["output"] == "[compile] ok"
    json.dumps([d, p, v])  # all of it is JSON-serialisable


# --- the summary script ------------------------------------------------------------------------------


def _record(test, passed, tokens=1000, latency=2000, failure=None, model="openai/gpt-oss-120b"):
    return {
        "test": test, "model": model, "passed": passed, "failure": failure,
        "usage": {"calls": 2, "prompt_tokens": tokens - 200, "completion_tokens": 200, "latency_ms": latency, "cost_usd": 0.001},
    }


def test_summary_gives_a_pass_rate_per_test_across_runs():
    rows = summarize_live.summarize(
        [_record("a", True), _record("a", False, failure="E   assert 1 == 2"), _record("a", True), _record("b", True, tokens=500)]
    )
    by = {r["test"]: r for r in rows}
    assert (by["a"]["runs"], by["a"]["passed"]) == (3, 2) and (by["b"]["runs"], by["b"]["passed"]) == (1, 1)
    assert by["a"]["mean_tokens"] == 1000 and by["b"]["mean_tokens"] == 500 and by["a"]["mean_latency_s"] == 2.0
    assert by["a"]["failures"] == ["E   assert 1 == 2"] and round(by["a"]["cost_usd"], 6) == 0.003


def test_summary_separates_models_and_renders_a_readable_table():
    rows = summarize_live.summarize([_record("a", True, model="m1"), _record("a", False, model="m2")])
    assert len(rows) == 2
    text = summarize_live.render(rows, failures=True)
    assert "m1" in text and "m2" in text and "50%" in text and "all tests: 1 of 2 runs passed" in text


def test_the_failure_line_shows_the_assertion_message_not_just_the_file_and_line():
    failure = "def test_a():\n>       assert x == 1\nE       AssertionError: planner: ERROR 404\ntests/t.py:9: AssertionError"
    text = summarize_live.render(summarize_live.summarize([_record("a", False, failure=failure)]), failures=True)
    failed_line = text.split("FAILED", 1)[1]
    assert "AssertionError: planner: ERROR 404" in failed_line and "tests/t.py:9" not in failed_line


def test_summary_of_nothing_says_how_to_get_something():
    assert "python -m pytest -m live" in summarize_live.render([])


def test_summary_reads_every_live_file_in_a_folder_and_ignores_junk(tmp_path):
    (tmp_path / "live_20260101T000000Z.jsonl").write_text(json.dumps(_record("a", True)) + "\nbroken\n", encoding="utf-8")
    (tmp_path / "live_20260102T000000Z.jsonl").write_text(json.dumps(_record("a", False)) + "\n", encoding="utf-8")
    (tmp_path / "other.jsonl").write_text(json.dumps(_record("zzz", True)) + "\n", encoding="utf-8")
    rows = summarize_live.summarize(summarize_live.load(tmp_path))
    assert [(r["test"], r["runs"], r["passed"]) for r in rows] == [("a", 2, 1)]


def test_a_used_up_daily_quota_says_so_and_points_at_fallback_models():
    text = "Rate limit reached on tokens per day (TPD): Limit 200000. Please try again in 8m22.5s."
    msg = preflight(FakeClient(StatusError(429, text)), "openai/gpt-oss-120b", URL)
    assert "daily token quota" in msg and "8m" in msg and "LLM_FALLBACK_MODELS" in msg
