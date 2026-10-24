import logging

import pytest

from app.remediation import llm

from .fake_openai import FakeOpenAI


@pytest.fixture
def real_provider(monkeypatch):
    monkeypatch.setenv("TIRITH_LLM_PROVIDER", "openai")
    llm.reset_model_cache()
    yield
    llm.reset_model_cache()


def _point(monkeypatch, srv, key="sk-fake-123"):
    monkeypatch.setenv("TIRITH_LLM_BASE_URL", srv.url)
    monkeypatch.setenv("TIRITH_LLM_API_KEY", key)


def test_model_autodetect_and_streaming_reasoning(real_provider, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    with FakeOpenAI() as srv:
        _point(monkeypatch, srv)
        assert llm.resolve_model() == "deepseek-r1-fake"
        seen = []
        res = llm.chat([{"role": "user", "content": "hi"}], on_reasoning=seen.append)
        assert res.model == "deepseek-r1-fake"
        assert res.reasoning == srv.reasoning
        assert "".join(seen) == srv.reasoning
        assert res.json()["summary"] == "s"
        assert res.finish_reason == "stop"
        req = srv.requests[-1]
        assert req["stream"] is True and req["max_tokens"] >= 8192 and req["model"] == "deepseek-r1-fake"
    assert "sk-fake-123" not in caplog.text


def test_non_streaming_and_explicit_model(real_provider, monkeypatch):
    with FakeOpenAI() as srv:
        _point(monkeypatch, srv)
        monkeypatch.setenv("TIRITH_LLM_MODEL", "pinned-model")
        res = llm.chat([{"role": "user", "content": "x"}], stream=False)
        assert srv.requests[-1]["model"] == "pinned-model"
        assert res.reasoning.startswith("First I trace")
        assert res.json()["fix_plan"] == "f"


def test_inline_think_tags_are_split(real_provider, monkeypatch):
    with FakeOpenAI(mode="think_tags") as srv:
        _point(monkeypatch, srv)
        res = llm.chat([{"role": "user", "content": "x"}])
        assert "<think>" not in res.content
        assert "trace the input" in res.reasoning
        assert res.json()["summary"] == "s"


def test_response_format_fallback(real_provider, monkeypatch):
    with FakeOpenAI(reject_response_format=True) as srv:
        _point(monkeypatch, srv)
        data, _ = llm.chat_json([{"role": "user", "content": "x"}])
        assert data["root_cause"] == "r"
        assert "response_format" in srv.requests[0] and "response_format" not in srv.requests[-1]


def test_bad_key_error_never_contains_key(real_provider, monkeypatch):
    with FakeOpenAI() as srv:
        _point(monkeypatch, srv, key="sk-WRONG-secret-value")
        with pytest.raises(llm.LLMError) as ei:
            llm.resolve_model()
        assert "401" in str(ei.value)
        assert "sk-WRONG-secret-value" not in str(ei.value)


def test_json_repair_round_trip(real_provider, monkeypatch):
    with FakeOpenAI(content="Sure! here you go: not json") as srv:
        _point(monkeypatch, srv)
        with pytest.raises(ValueError):
            llm.chat_json([{"role": "user", "content": "x"}])
        assert len(srv.requests) == 2  # original + one repair attempt


def test_extract_json_variants():
    assert llm.extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.extract_json('blah {"a": {"b": "}"}} trailing') == {"a": {"b": "}"}}
    assert llm.extract_json("[1, 2]") == [1, 2]
    with pytest.raises(ValueError):
        llm.extract_json("nothing here")


def test_stub_is_deterministic():
    ctx = {"title": "SQLi", "rule_id": "r1", "category": "sast", "file": "a.py", "line": 3, "snippet": "x = 1"}
    a = llm.chat([], task="explain", stub_context=ctx)
    b = llm.chat([], task="explain", stub_context=ctx)
    assert a.content == b.content and a.json()["summary"].startswith("[stub]")
    fx = llm.chat([], task="fix", stub_context=ctx).json()
    assert fx["edits"] == [{"file": "a.py", "find": "x = 1", "replace": "x = 1  # tirith: reviewed"}]


def test_thinking_streamer_throttles():
    out = []
    s = llm.ThinkingStreamer(out.append, min_chars=10, min_interval=0)
    for _ in range(5):
        s("abcdefghijk")
    s.flush()
    assert len(out) == 5 and all(o == "abcdefghijk" for o in out)


def test_unclosed_think_is_reasoning_not_content():
    content, reasoning = llm.split_think('<think>still tracing the {"summary": input')
    assert content == "" and "still tracing" in reasoning
    content, reasoning = llm.split_think('{"a": 1}<think>trailing')
    assert content == '{"a": 1}' and reasoning == "trailing"


def test_empty_or_truncated_output_raises(real_provider, monkeypatch):
    with FakeOpenAI(mode="think_tags", content="") as srv:
        _point(monkeypatch, srv)
        with pytest.raises(llm.LLMError, match="no content"):
            llm.chat_json([{"role": "user", "content": "x"}])
        assert len(srv.requests) == 1  # no pointless repair round-trip
    monkeypatch.setattr(llm, "chat", lambda *a, **k: llm.LLMResult(content='{"summary": "cut', finish_reason="length"))
    with pytest.raises(llm.LLMError, match="truncated"):
        llm.chat_json([{"role": "user", "content": "x"}])


def test_deadline_and_queue(real_provider, monkeypatch):
    with FakeOpenAI() as srv:
        _point(monkeypatch, srv)
        with pytest.raises(llm.LLMError, match="deadline"):
            llm.chat([{"role": "user", "content": "x"}], deadline=llm.deadline_in(-1))
        assert srv.requests == []
        sem = llm._semaphore()
        assert sem.acquire(timeout=1)  # simulate the one in-flight request on the single-slot server
        try:
            with pytest.raises(llm.LLMError, match="busy"):
                llm.chat([{"role": "user", "content": "x"}], deadline=llm.deadline_in(0.3))
        finally:
            sem.release()
        assert llm.chat([{"role": "user", "content": "x"}], deadline=llm.deadline_in(30)).json()["summary"] == "s"
