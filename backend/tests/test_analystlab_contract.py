import asyncio
import json

from app.analystlab import demo, lab, loop, regression, tools
from app.remediation.llm import LLMResult


def test_model_claim_without_response_is_not_evidence(tmp_store, tmp_path, monkeypatch):
    monkeypatch.setattr(loop.config, "EVIDENCE_DIR", tmp_path)

    def planner(*args, **kwargs):
        return LLMResult(json.dumps({
            "done": True, "verdict": "flag_exposed", "summary": "Unverified claim",
            "evidence": [{"request": "GET /invented", "status": 200, "note": "invented"}],
        }), model="test-planner")

    result = asyncio.run(loop.run("Assess the lab", chat=planner))
    assert result.verdict == "inconclusive"
    assert result.report["evidence"] == []
    assert result.report["model_claimed"] == "flag_exposed"


def test_changing_reason_does_not_repeat_network_request(tmp_store, tmp_path, monkeypatch):
    monkeypatch.setattr(loop.config, "EVIDENCE_DIR", tmp_path)
    decisions = iter([
        {"action": {"tool": "http.get", "args": {"handle": "docker-lab", "path": "/", "reason": reason}}}
        for reason in ("first", "same request with different prose")
    ] + [{"done": True, "verdict": "inconclusive"}])
    calls = []

    def execute(name, args, ctx):
        calls.append(args)
        return True, json.dumps({"response": {"status": 403, "body": "Denied"}}), []

    monkeypatch.setattr(tools, "execute", execute)
    result = asyncio.run(loop.run("Assess the lab", max_steps=3,
        chat=lambda *a, **kw: LLMResult(json.dumps(next(decisions)), model="test-planner")))
    assert len(calls) == 1
    assert result.steps[1].ok is False


def test_unknown_tool_is_refused_before_resolving_destination(tmp_store, monkeypatch):
    def unexpected(*args):
        raise AssertionError("unknown tool reached the destination resolver")

    monkeypatch.setattr(tools, "resolve", unexpected)
    ok, observation, _ = tools.execute("unregistered", {"handle": "docker-lab", "path": "/"}, tools.Ctx())
    assert not ok
    assert "unknown tool" in observation


def test_comparison_replays_actual_model_selected_request(tmp_store, tmp_path, monkeypatch):
    monkeypatch.setattr(demo.config, "EVIDENCE_DIR", tmp_path)
    finding = regression.ensure_demo_finding()
    request = "/flag?as=demo-admin&view=compact"
    sc = demo.Scenario(id="labdemo_test_replay", goal="test", status="done",
        baseline={"status": 403, "flag": False},
        analyst_evidence=[{"request": "GET " + request, "as_user": "demo-low", "status": 200, "flag": True}],
        artifacts={"finding": finding.id})
    monkeypatch.setattr(demo, "_runs", {sc.id: sc})
    monkeypatch.setattr(lab, "resolve", lambda name: name)
    requests = []

    def recheck(ref, finding, selected, *, label):
        requests.append(selected)
        return {"result": "not_reproduced" if label == "patched" else "confirmed", "request": selected}

    monkeypatch.setattr(demo, "_recheck", recheck)
    demo.check(sc.id)
    assert requests == [request, request]
