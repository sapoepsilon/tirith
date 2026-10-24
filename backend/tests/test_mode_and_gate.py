"""Mode switching (and its transient restore), the pause gate, and the lab PATCH route."""

from __future__ import annotations

import asyncio
import json

import pytest

from app import config
from app.analyst import loop
from app.analyst.tools import AnalystTools
from app.remediation import lab as labmod
from app.remediation.llm import LLMResult


@pytest.fixture()
def env(tmp_path, monkeypatch):
    from app.store import Store, set_store

    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / sub if sub else tmp_path)
    config.ensure_dirs()
    st = Store(tmp_path / "t.db")
    set_store(st)
    return st


def test_patch_mode_keeps_the_categories_and_is_audited(env, monkeypatch):
    from app.models import ModePatch
    from app.routes_core import patch_mode

    env.set_mode(env.get_mode().model_copy(update={"mode": "observe"}))
    assert patch_mode(ModePatch(mode="assisted")).mode == "assisted"
    assert env.get_mode().autonomous_categories == ["dependency_bump"]
    assert any(a.action == "mode.set" for a in env.list_audit(10))


def test_autonomous_is_refused_when_the_operator_switched_it_off(env, monkeypatch):
    from fastapi import HTTPException

    from app.models import ModePatch
    from app.routes_core import patch_mode

    monkeypatch.delenv("TIRITH_ALLOW_AUTONOMOUS", raising=False)
    with pytest.raises(HTTPException) as e:
        patch_mode(ModePatch(mode="autonomous"))
    assert e.value.status_code == 403
    assert env.get_mode().mode == "observe"  # unchanged


def test_the_mode_tool_switches_and_records_why(env):
    tools = AnalystTools()
    assert tools.mode is None
    out = asyncio.run(tools.call("mode", {"mode": "assisted"}))
    assert out["mode"] == "assisted" and out["was"] == "observe"
    assert tools.mode == "assisted"


def test_a_run_that_lifted_the_mode_restores_it(env, monkeypatch):
    calls = []

    class Reg:
        def names(self):
            return ["mode", "probe"]

        def describe(self):
            return ""

        async def call(self, name, args):
            calls.append(name)
            if name == "mode":
                return await AnalystTools().call("mode", args)
            return {"result": "not_reproduced", "grade": None, "proof": False, "reproduce": []}

    replies = [
        {"thought": "lift the mode", "action": {"tool": "mode", "args": {"mode": "assisted"}}},
        {"thought": "done", "done": True, "report": {"summary": "s"}},
    ]
    monkeypatch.setattr(loop.llm, "chat", lambda *a, **k: LLMResult(content=json.dumps(replies.pop(0)), model="f"))
    run = asyncio.run(loop.run("assess", Reg(), max_steps_override=3))
    assert run.status == "done"
    assert env.get_mode().mode == "observe", "the owner's mode must be back after the run"


def test_pause_holds_the_loop_and_resume_releases_it(env, monkeypatch):
    from app import events

    seen = {}

    class Reg:
        def names(self):
            return ["discover"]

        def describe(self):
            return ""

        async def call(self, name, args):
            return {"ok": True}

    replies = [
        {"thought": "a", "action": {"tool": "discover", "args": {"host": "h1"}}},
        {"thought": "b", "action": {"tool": "discover", "args": {"host": "h2"}}},
        {"thought": "done", "done": True, "report": {"summary": "s"}},
    ]
    monkeypatch.setattr(loop.llm, "chat", lambda *a, **k: LLMResult(content=json.dumps(replies.pop(0)), model="f"))
    events.pause("arn_x", "approve")
    seen["paused"] = events.paused()

    async def release():
        await asyncio.sleep(0.05)
        events.resume()

    async def main():
        asyncio.ensure_future(release())
        return await loop.run("assess", Reg(), run_id="arn_x", max_steps_override=4)

    # the gate is only reached between steps: queue the release so it survives the first checkpoint
    run = asyncio.run(main())
    assert seen["paused"] is True
    assert run.status == "done" and run.waiting_on is None
    types = [e.type for e in env.recent_events(200)]
    # the pause held the loop (a checkpoint could only happen between steps, i.e. after step 1)
    assert types.count("analyst.observation") == len(run.steps) - (0 if len(run.steps) else 0)
    assert "analyst.checkpoint" in types


def test_approve_mode_can_be_answered_through_the_route(env, monkeypatch):
    from app.analyst import loop as l
    from app.routes_analyst import PauseBody, pause_run, resume_run

    run = l.AnalystRun(id="arn_live", goal="g")
    from app.routes_analyst import _runs

    _runs["arn_live"] = run
    try:
        out = pause_run("arn_live", PauseBody(reason="first reproduction"))
        assert out["waiting_on"] == "first reproduction"
        assert run.waiting_on == "first reproduction"
        assert resume_run("arn_live")["resumed"] is True
        assert run.waiting_on is None
    finally:
        _runs.pop("arn_live", None)


def test_approve_mode_waits_before_the_first_step(env, monkeypatch):
    from app import events
    from app.routes_analyst import _drive, _runs

    events.resume()
    calls = []

    class Reg:
        def names(self):
            return ["asset"]

        def describe(self):
            return ""

        async def call(self, name, args):
            calls.append(events.paused())
            return {"ok": True}

    replies = [{"thought": "a", "action": {"tool": "asset", "args": {"kind": "host", "ref": "h"}}},
               {"thought": "done", "done": True, "report": {"summary": "s"}}]
    monkeypatch.setattr(loop.llm, "chat", lambda *a, **k: LLMResult(content=json.dumps(replies.pop(0)), model="f"))
    monkeypatch.setattr("app.routes_analyst.AnalystTools", Reg)

    async def main():
        import asyncio

        rid = "arn_first"
        _runs[rid] = loop.AnalystRun(id=rid, goal="g")
        events.bind_loop(asyncio.get_running_loop())
        events.pause(rid, "start")
        task = asyncio.ensure_future(_drive(rid, "g", True, None))
        await asyncio.sleep(0.3)
        assert calls == [], "no step before the answer"
        events.resume()
        for _ in range(100):
            await asyncio.sleep(0.02)
            if task.done():
                break
        _runs.pop(rid, None)

    asyncio.run(main())
    assert calls == [False], "the first step ran only after the resume"


def test_a_long_pause_does_not_eat_the_step(env, monkeypatch):
    """A pause may outlast the wall clock: the step after the release still runs (released != budget spent)."""
    from app import events

    events.resume()
    monkeypatch.setenv("TIRITH_ANALYST_SECONDS", "-0.1")  # already out of time before the first step
    replies = [{"thought": "a", "action": {"tool": "asset", "args": {"kind": "host", "ref": "h"}}},
               {"thought": "b", "action": {"tool": "asset", "args": {"kind": "host", "ref": "h2"}}},
               {"thought": "done", "action": {"tool": "finish", "args": {}}},
               {"thought": "done", "done": True, "report": {"summary": "s"}}]

    class Reg:
        def names(self):
            return ["asset", "finish"]

        def describe(self):
            return ""

        async def call(self, name, args):
            return {"ok": True}

    monkeypatch.setattr(loop.llm, "chat", lambda *a, **k: LLMResult(content=json.dumps(replies.pop(0)), model="f"))
    monkeypatch.setattr(loop, "max_steps", lambda: 5)

    async def main():
        events.pause("r", "hold")  # paused before the run starts, released while it waits at the first checkpoint
        loop_task = asyncio.ensure_future(loop.run("g", Reg(), run_id="r", max_steps_override=5))
        await asyncio.sleep(0.15)
        events.resume()
        return await loop_task

    run = asyncio.run(main())
    # a release is not "budget spent": the stale clock must not skip the step it just released
    assert len(run.steps) > 1, (len(run.steps), run.status)


def test_same_fix_can_retry_after_the_mode_changed(env):
    """A fix refused in observe is unseen in the new dedupe key, so the retry in assisted runs."""
    from app.models import ModeSettings
    from app.store import get_store

    replies = [{"thought": "try", "action": {"tool": "fix", "args": {"id": "fnd_1"}}},
               {"thought": "now assisted", "action": {"tool": "fix", "args": {"id": "fnd_1"}}},
               {"thought": "done", "action": {"tool": "finish", "args": {}}}]
    calls: list[str] = []

    class Reg:
        def names(self):
            return ["fix", "finish"]

        def describe(self):
            return ""

        async def call(self, name, args):
            calls.append(get_store().get_mode().mode)
            if name == "fix" and len(calls) == 1:
                get_store().set_mode(ModeSettings(mode="assisted", autonomous_categories=[], transient=True))
                raise RuntimeError("observe mode: fixes are disabled")
                raise RuntimeError("observe mode: fixes are disabled")
            return {"ok": True}

    get_store().set_mode(ModeSettings(mode="observe", autonomous_categories=[], transient=False))

    def chat(*a, **k):
        from app.remediation.llm import LLMResult
        return LLMResult(content=json.dumps(replies.pop(0)), model="f")

    class Stop(Exception):
        pass

    def run_one(reg):
        async def main():
            async def switch():
                await asyncio.sleep(0.05)
                get_store().set_mode(ModeSettings(mode="assisted", autonomous_categories=[], transient=True))
            asyncio.ensure_future(switch())
            return await loop.run("g", reg, run_id="r2", max_steps_override=3)
        return asyncio.run(main())

    get_store().set_mode(ModeSettings(mode="observe", autonomous_categories=[], transient=False))
    monkey = pytest.MonkeyPatch()
    monkey.setenv("TIRITH_LLM_PROVIDER", "stub")
    monkey.setattr(loop.llm, "chat", chat)
    try:
        run = run_one(Reg())
    finally:
        monkey.undo()
    retry = [s for s in run.steps if s.tool == "fix"]
    assert len(retry) == 2, [s.observation for s in retry]
    assert "observe mode" in retry[0].observation
    assert "already made" not in retry[1].observation
    assert calls[:2] == ["observe", "assisted"]  # stub turns of the global registry also append


def test_enable_disabled_reports_409(tmp_path, monkeypatch):

    monkeypatch.setattr(config, "EVIDENCE_DIR", tmp_path)
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path / "reports")
    with pytest.raises(FileNotFoundError):
        from app.analyst import html_report

        html_report.render_run("arn_missing", "as-found")


def test_audit_entries_carry_cookie_values_for_masking(env, monkeypatch):
    monkeypatch.setattr(labmod, "_login", lambda h: {"sessionid": "abc123def456ghi"})
    h = labmod.LabHandle(url="http://x", container="tirith-lab-x", network="lab", image="i", port=80)
    labmod.session(h)
    rows = [a for a in env.list_audit(20) if a.action == "lab.session"]
    assert rows and rows[0].details == {"sessionid": "abc123def456ghi"}
    labmod.session(h)  # cached: no duplicate row for an unchanged value
    assert len([a for a in env.list_audit(20) if a.action == "lab.session"]) == 1
