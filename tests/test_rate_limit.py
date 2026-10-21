"""Rate-limit handling: reading a 429, falling back to another model, pacing, and the reply cache."""

import json
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ConfigDict

from pq_patch.llm_client import StructuredLLM
from pq_patch.rate_limit import Pacer, ReplyCache, classify, describe_wait, parse_wait

MESSAGES = [{"role": "user", "content": "hello"}]
VALID = {"answer": "yes"}


@pytest.fixture(autouse=True)
def _security_log_in_tmp(security_events):
    """Rejected replies write security events; keep them out of the real security_log.jsonl."""


class Reply(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


def ok(text=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text or json.dumps(VALID), refusal=None), finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
    )


class Limited(Exception):
    """What the OpenAI SDK raises for HTTP 429, carrying Groq's message."""

    status_code = 429

    def __init__(self, message):
        super().__init__(message)


DAILY = (
    "Error code: 429 - Rate limit reached for model `openai/gpt-oss-120b` on tokens per day (TPD): "
    "Limit 200000, Used 199100, Requested 1800. Please try again in 8m22.5s."
)
MINUTE = "Rate limit reached on tokens per minute (TPM): Limit 8000, Used 7400, Requested 1800. Please try again in 3.2s."


class ByModel:
    """A fake provider whose behaviour depends on the model asked for."""

    def __init__(self, behaviour):
        self.behaviour, self.calls = behaviour, []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kw):
        self.calls.append(kw["model"])
        outcome = self.behaviour[kw["model"]]
        outcome = outcome.pop(0) if isinstance(outcome, list) else outcome
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make(behaviour, *, fallbacks=(), now=None, **kw):
    clock = SimpleNamespace(t=1000.0)
    sleeps = []
    fake = ByModel(behaviour)
    llm = StructuredLLM(
        client_factory=lambda: fake,
        model_name=lambda: "primary",
        fallback_models=list(fallbacks),
        sleep=sleeps.append,
        clock=lambda: clock.t,
        log_path=str(kw.pop("log_path")),
        pacer=None,
        cache=kw.pop("cache", None),
        **kw,
    )
    return llm, fake, sleeps, clock


# --- reading the error ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, seconds",
    [
        ("Please try again in 8m22.5s.", 502.5),
        ("Please try again in 3.2s", 3.2),
        ("please try again in 450ms", 0.45),
        ("Please try again in 1h2m3s", 3723),
        ("no hint here", None),
    ],
)
def test_parse_wait(text, seconds):
    assert parse_wait(text) == (pytest.approx(seconds) if seconds is not None else None)


def test_classify_tells_daily_from_per_minute():
    daily = classify(Limited(DAILY))
    assert daily.daily and daily.wait == pytest.approx(502.5)
    minute = classify(Limited(MINUTE))
    assert not minute.daily and minute.wait == pytest.approx(3.2)
    assert classify(ValueError("boom")) is None


def test_a_daily_limit_without_a_wait_assumes_an_hour():
    assert classify(Limited("Rate limit on requests per day (RPD)")).wait == 3600


def test_describe_wait():
    assert [describe_wait(x) for x in (3, 502, 7200)] == ["3s", "8m", "2.0h"]


# --- daily quota: stop, or move to another model ------------------------------------------------


def test_daily_quota_is_not_retried_and_says_when_to_come_back(tmp_path):
    llm, fake, sleeps, _ = make({"primary": Limited(DAILY)}, log_path=tmp_path / "log")
    r = llm.call(MESSAGES, Reply)
    assert (r.status, r.calls) == ("error", 1) and sleeps == [] and fake.calls == ["primary"]
    assert "daily quota" in r.error and "8m" in r.error and "primary" in r.error


def test_an_exhausted_model_is_not_called_again(tmp_path):
    llm, fake, _, clock = make({"primary": [Limited(DAILY), ok()]}, log_path=tmp_path / "log")
    assert llm.call(MESSAGES, Reply).status == "error"
    second = llm.call(MESSAGES, Reply)  # still inside the 8 minutes: no request goes out
    assert second.status == "error" and second.calls == 0 and fake.calls == ["primary"]
    clock.t += 600  # the provider's wait has passed
    assert llm.call(MESSAGES, Reply).status == "ok"


def test_falls_back_to_the_next_model_when_the_first_is_out_of_quota(tmp_path):
    llm, fake, sleeps, _ = make(
        {"primary": Limited(DAILY), "backup": ok()}, fallbacks=["backup"], log_path=tmp_path / "log"
    )
    r = llm.call(MESSAGES, Reply)
    assert (r.status, r.model, r.calls) == ("ok", "backup", 2) and sleeps == []
    lines = [json.loads(x) for x in (tmp_path / "log").read_text().splitlines()]
    assert [(x["model"], x["status"]) for x in lines] == [("primary", "error"), ("backup", "ok")]
    llm.call(MESSAGES, Reply)  # the next call goes straight to the model that works
    assert fake.calls == ["primary", "backup", "backup"]


def test_every_model_out_of_quota_ends_at_once(tmp_path):
    llm, fake, _, _ = make(
        {"primary": Limited(DAILY), "backup": Limited(DAILY)}, fallbacks=["backup"], log_path=tmp_path / "log"
    )
    r = llm.call(MESSAGES, Reply)
    assert r.status == "error" and r.calls == 2 and fake.calls == ["primary", "backup"]
    assert "all 2 configured models" in r.error


def test_a_short_per_minute_limit_is_waited_out_on_the_same_model(tmp_path):
    llm, fake, sleeps, _ = make({"primary": [Limited(MINUTE), ok()]}, fallbacks=["backup"], log_path=tmp_path / "log", max_delay=60)
    r = llm.call(MESSAGES, Reply)
    assert (r.status, r.model, r.calls) == ("ok", "primary", 2)
    assert fake.calls == ["primary", "primary"] and sleeps and sleeps[0] >= 3.2


# --- pacing -----------------------------------------------------------------------------------


def test_pacer_waits_for_the_window_to_make_room():
    clock, sleeps = SimpleNamespace(t=0.0), []

    def sleep(s):
        sleeps.append(s)
        clock.t += s

    pacer = Pacer(1000, clock=lambda: clock.t, sleep=sleep)
    assert pacer.wait_for(600) == 0
    pacer.record(600)
    clock.t = 20
    assert pacer.wait_for(300) == 0  # 900 fits
    pacer.record(300)
    waited = pacer.wait_for(500)  # 1400 does not: the 600 sent at t=0 must leave the window first
    assert waited == pytest.approx(40) and clock.t == pytest.approx(60)


def test_pacer_does_not_stall_on_a_call_bigger_than_the_whole_budget():
    pacer = Pacer(1000, clock=lambda: 0.0, sleep=lambda s: pytest.fail("slept"))
    pacer.record(900)
    assert pacer.wait_for(5000) == 0


def test_pacer_is_off_unless_configured(monkeypatch):
    monkeypatch.delenv("LLM_TPM_LIMIT", raising=False)
    assert Pacer.from_env() is None
    monkeypatch.setenv("LLM_TPM_LIMIT", "6000")
    assert Pacer.from_env().limit == 6000
    monkeypatch.setenv("LLM_TPM_LIMIT", "lots")
    assert Pacer.from_env() is None


def test_calls_are_paced_before_they_are_sent(tmp_path):
    clock, sleeps = SimpleNamespace(t=0.0), []

    def sleep(s):
        sleeps.append(s)
        clock.t += s

    fake = ByModel({"primary": [ok(), ok()]})
    llm = StructuredLLM(
        client_factory=lambda: fake, model_name=lambda: "primary", fallback_models=[], sleep=sleep,
        log_path=str(tmp_path / "log"), cache=None, pacer=Pacer(1500, clock=lambda: clock.t, sleep=sleep),
    )
    llm.call(MESSAGES, Reply)  # records 120 real tokens
    llm.call(MESSAGES, Reply)  # 120 + (estimate ~1200) fits 1500
    llm.call(MESSAGES, Reply)  # 240 + ~1200 does not
    assert sleeps and sleeps[0] > 0


# --- cache --------------------------------------------------------------------------------------


def test_cache_is_opt_in_and_never_used_with_the_stub(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.example.com/v1")
    monkeypatch.delenv("LLM_CACHE", raising=False)
    assert ReplyCache.from_env() is None
    monkeypatch.setenv("LLM_CACHE", "1")
    assert ReplyCache.from_env() is not None
    monkeypatch.setenv("LLM_BASE_URL", "local://stub")
    assert ReplyCache.from_env() is None


def test_a_cached_reply_costs_no_call_and_no_log_line(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    llm, fake, _, _ = make({"primary": [ok()]}, log_path=tmp_path / "log", cache=cache)
    first = llm.call(MESSAGES, Reply)
    again = llm.call(MESSAGES, Reply)
    assert (first.cached, again.cached, again.calls) == (False, True, 0)
    assert again.value == first.value and fake.calls == ["primary"] and cache.hits == 1
    assert len((tmp_path / "log").read_text().splitlines()) == 1


def test_different_prompts_do_not_share_a_cache_entry(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    llm, fake, _, _ = make({"primary": [ok(), ok()]}, log_path=tmp_path / "log", cache=cache)
    llm.call(MESSAGES, Reply)
    llm.call([{"role": "user", "content": "something else"}], Reply)
    assert len(fake.calls) == 2


def test_only_validated_replies_are_cached(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    llm, _, _, _ = make({"primary": [ok("not json"), ok("not json")]}, log_path=tmp_path / "log", cache=cache)
    assert llm.call(MESSAGES, Reply).status == "invalid_output"
    assert not list((tmp_path / "cache").glob("*.json")) if (tmp_path / "cache").exists() else True


def test_a_cache_entry_that_no_longer_validates_is_ignored(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    cache.put(ReplyCache.key("primary", MESSAGES), json.dumps({"wrong": "shape"}), "primary")
    llm, fake, _, _ = make({"primary": [ok()]}, log_path=tmp_path / "log", cache=cache)
    r = llm.call(MESSAGES, Reply)
    assert r.status == "ok" and not r.cached and fake.calls == ["primary"]


def test_a_corrupt_cache_file_is_a_miss(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / f"{ReplyCache.key('primary', MESSAGES)}.json").write_text("{broken")
    llm, fake, _, _ = make({"primary": [ok()]}, log_path=tmp_path / "log", cache=cache)
    assert llm.call(MESSAGES, Reply).status == "ok" and fake.calls == ["primary"]


def test_a_cached_reply_for_a_fallback_model_is_found_while_the_primary_is_down(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    cache.put(ReplyCache.key("backup", MESSAGES), json.dumps(VALID), "backup")
    llm, fake, _, _ = make({"primary": Limited(DAILY)}, fallbacks=["backup"], log_path=tmp_path / "log", cache=cache)
    r = llm.call(MESSAGES, Reply)
    assert (r.status, r.cached, r.model) == ("ok", True, "backup") and fake.calls == []


def test_clear_removes_entries(tmp_path):
    cache = ReplyCache(tmp_path / "cache")
    cache.put("a", "x", "m")
    cache.put("b", "y", "m")
    assert cache.clear() == 2 and cache.get("a") is None
