"""Analyst loop, operator tools, host discovery and evidence capture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import config
from app.analyst import loop
from app.analyst.tools import AnalystTools, ToolError
from app.evidence import screenshots
from app.models import Asset
from app.remediation.llm import LLMResult
from app.scanners import discovery


@pytest.fixture()
def env(tmp_path, monkeypatch):
    from app.store import Store, set_store

    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / sub if sub else tmp_path)
    config.ensure_dirs()
    st = Store(tmp_path / "t.db")
    set_store(st)
    # Host scope: one literal host and one CIDR; everything else is denied.
    monkeypatch.setattr(
        "app.scanners.discovery.load_scope",
        lambda: type("S", (), {"host_targets": ["192.0.2.10", "198.51.100.0/28"], "host_ports": [22, 80, 8010]})(),
    )
    return st


def _planner(monkeypatch, replies):
    seq = list(replies)
    calls = {"n": 0}

    def fake_chat(messages, **kw):
        r = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return LLMResult(content=json.dumps(r), model="fake")

    monkeypatch.setattr(loop.llm, "chat", fake_chat)
    return calls


class FakeRegistry:
    def __init__(self):
        self.calls = []

    def names(self):
        return ["discover", "scan"]

    def describe(self):
        return "- discover(host: str) — probe\n- scan(...) — scan"

    async def call(self, name, args):
        self.calls.append((name, args))
        return {"ok": True, "name": name}


def test_loop_executes_planned_tools_and_finishes(env, monkeypatch):
    _planner(monkeypatch, [
        {"thought": "start with discovery", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
        {"thought": "enough", "done": True, "report": {"summary": "only ssh", "notable": ["ssh"], "next_steps": ["harden ssh"]}},
    ])
    reg = FakeRegistry()
    run = loop.run.__wrapped__(None) if False else None  # noqa: F841 - keeps the import list honest
    import asyncio

    run = asyncio.run(loop.run("assess", reg))
    assert run.status == "done"
    assert run.report["summary"] == "only ssh"
    assert [c[0] for c in reg.calls] == ["discover"]
    assert run.steps[0].tool == "discover" and run.steps[0].ok
    assert Path(run.report_path).exists()
    assert "only ssh" in Path(run.report_path).read_text()


def test_loop_refuses_duplicate_calls_and_unknown_tools(env, monkeypatch):
    _planner(monkeypatch, [
        {"thought": "a", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
        {"thought": "same again", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
        {"thought": "bogus", "action": {"tool": "shell", "args": {"cmd": "rm -rf /"}}},
        {"thought": "done", "done": True, "report": {"summary": "ok"}},
    ])
    reg = FakeRegistry()
    import asyncio

    run = asyncio.run(loop.run("assess", reg, max_steps_override=6))
    assert [s.ok for s in run.steps] == [True, False, False]
    assert "already made this exact call" in run.steps[1].observation
    assert "unknown tool" in run.steps[2].observation
    assert len(reg.calls) == 1  # the refused actions never executed


def test_a_refused_call_can_be_retried_after_its_precondition_is_fixed(env, monkeypatch):
    """Register-then-discover: the first discover fails (no asset); the retry must be allowed."""
    _planner(monkeypatch, [
        {"thought": "discover first", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
        {"thought": "register the host", "action": {"tool": "asset", "args": {"kind": "host", "ref": "192.0.2.10"}}},
        {"thought": "now discover", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
        {"thought": "done", "done": True, "report": {"summary": "ok"}},
    ])

    class StatefulRegistry(FakeRegistry):
        def __init__(self):
            super().__init__()
            self.registered = False

        def names(self):
            return ["discover", "scan", "asset"]

        async def call(self, name, args):
            if name == "discover" and not self.registered:
                raise RuntimeError("asset not found; register it first")
            if name == "asset":
                self.registered = True
            self.calls.append((name, args))
            return {"ok": True}

    reg = StatefulRegistry()
    import asyncio

    run = asyncio.run(loop.run("assess", reg, max_steps_override=6))
    assert [s.ok for s in run.steps] == [False, True, True]
    assert [c[0] for c in reg.calls] == ["asset", "discover"]
    assert run.status == "done"


def test_running_out_of_steps_still_produces_a_report(env, monkeypatch):
    """A user who hits the budget must still get a summary, never silence."""
    import asyncio

    _planner(monkeypatch, [
        {"thought": "look", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}},
    ])
    calls = []

    def chat(msgs, **kw):
        calls.append(msgs[0]["content"][:40])
        if len(calls) > 1:  # the forced report call
            return LLMResult(content=json.dumps(
                {"done": True, "report": {"summary": "found ssh and http", "next_steps": ["harden ssh"]}}),
                model="fake")
        return LLMResult(content=json.dumps(
            {"thought": "look", "action": {"tool": "discover", "args": {"host": "192.0.2.10"}}}), model="fake")

    monkeypatch.setattr(loop.llm, "chat", chat)
    run = asyncio.run(loop.run("assess 192.0.2.10", FakeRegistry(), max_steps_override=1))
    assert run.status == "budget"
    assert run.report and run.report.get("summary") == "found ssh and http"
    assert run.report.get("next_steps") == ["harden ssh"]
    assert run.report_path and run.report_path.endswith(".md")


# -- final report validation: fix_status is a code guarantee, not a model promise -------------------

def _issue(**kw):
    base = {"title": "Open admin", "severity": "high", "where": "192.0.2.10:80", "evidence": "200 without auth",
            "reproduce": ["curl it"], "impact": "takeover", "fix": "require auth", "fix_status": "proposed"}
    base.update(kw)
    return base


def _finish_run(monkeypatch, replies):
    """Run the loop with a model that finishes immediately; later replies answer correction requests."""
    import asyncio

    seen = []

    def chat(msgs, **kw):
        seen.append(msgs)
        return LLMResult(content=json.dumps(replies[min(len(seen) - 1, len(replies) - 1)]), model="fake")

    monkeypatch.setattr(loop.llm, "chat", chat)
    # No class probe is watchable with the fake tools here: keep the gate silent so these tests stay
    # about the report schema. (test_probe.py covers the gate itself.)
    monkeypatch.setattr(loop, "proof_gate", _no_gate)
    return asyncio.run(loop.run("assess", FakeRegistry())), seen


async def _no_gate(run_obj, registry):
    return None


def _stored_fix(st, fix_status):
    from app.models import Finding, Fix

    f = Finding(scan_id="scn_1", asset_id="ast_1", fingerprint="fp1", tool="zap", rule_id="r", title="t",
                severity="high", category="dast", status="open", confidence=0.9)
    st.upsert_finding(f)
    st.save_fix(Fix(finding_id=f.id, mode="assisted", status=fix_status))
    return f.id


def test_valid_report_passes_through_unchanged(env, monkeypatch):
    fid = _stored_fix(env, "verified")
    issues = [_issue(), _issue(title="Fixed one", finding_id=fid, fix_status="applied")]
    run, seen = _finish_run(monkeypatch, [{"thought": "done", "done": True, "report": {"summary": "s", "issues": issues}}])
    assert run.status == "done" and len(seen) == 1  # no correction call
    assert [i["fix_status"] for i in run.report["issues"]] == ["proposed", "applied"]
    assert run.report["issues"][0] == issues[0]


def test_invalid_fix_status_is_retried_once_then_coerced(env, monkeypatch):
    bad = {"thought": "done", "done": True, "report": {"summary": "s", "issues": [_issue(fix_status="open")]}}
    run, seen = _finish_run(monkeypatch, [bad, bad, bad])
    assert len(seen) == 2  # original + exactly one correction request
    assert "failed validation" in seen[1][-1]["content"] and "fix_status" in seen[1][-1]["content"]
    assert run.status == "done"
    assert run.report["issues"][0]["fix_status"] == "proposed"
    assert run.report["issues"][0]["title"] == "Open admin"


def test_retry_with_a_valid_answer_is_used(env, monkeypatch):
    bad = {"thought": "done", "done": True, "report": {"summary": "s", "issues": [_issue(fix_status="open")]}}
    good = {"done": True, "report": {"summary": "fixed", "issues": [_issue(fix_status="proposed")]}}
    run, seen = _finish_run(monkeypatch, [bad, good])
    assert len(seen) == 2 and run.report["summary"] == "fixed"


def test_applied_without_a_real_fix_is_downgraded(env, monkeypatch):
    proposed_only = _stored_fix(env, "proposed")
    issues = [_issue(fix_status="applied"),                                   # no finding at all
              _issue(fix_status="applied", finding_id="fnd_does_not_exist"),   # unknown finding
              _issue(fix_status="applied", finding_id=proposed_only)]          # fix exists but never applied
    run, seen = _finish_run(monkeypatch, [{"thought": "done", "done": True, "report": {"summary": "s", "issues": issues}}])
    assert len(seen) == 1
    assert [i["fix_status"] for i in run.report["issues"]] == ["proposed"] * 3
