"""Projection probes: severity comes from the response, and the proof gate refuses unproven severity."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from app import config
from app.analyst import loop, probe
from app.analystlab.http import Response
from app.models import Asset, Finding
from app.remediation.llm import LLMResult


@pytest.fixture()
def store(tmp_path, monkeypatch):
    from app.store import Store, set_store

    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / sub if sub else tmp_path)
    config.ensure_dirs()
    st = Store(tmp_path / "t.db")
    set_store(st)
    return st


def _resp(status=200, body="") -> Response:
    return Response("GET", "/x", {}, status, {"content-type": "text/html"}, body, 5)


# -- projection ------------------------------------------------------------------------------

def test_projection_takes_the_parameter_and_keeps_the_other_query_values():
    p = probe.plan_for("SQL injection in login", "http://lab:5006/lab?q=hello&page=2", "GET /lab?q=hello&page=2")
    assert p and p.weakness == "sqli" and p.param == "q" and p.benign == "hello"
    assert p.base == {"page": "2"}
    assert p.payload == "'" and p.source == "scanner"


def test_a_path_segmented_xss_is_still_planned_but_ssrf_without_a_parameter_is_not():
    assert probe.plan_for("Reflected XSS (CWE-79)", "http://lab:5006/lab/marker").weakness == "xss"
    assert probe.plan_for("SSRF (CWE-918)", "http://lab:5006/fetch") is None


def test_a_model_proposal_is_parsed_and_unsafe_values_fall_back():
    from app.store import Store, set_store

    set_store(Store(Path(tempfile.mkdtemp()) / "t.db"))
    text = "weakness: sqli\npath: /login\nparam: user\npayload: admin'--\nsignal: syntax error"
    p = probe.plan_for("sqli", "http://lab:5006/", proposal=text)
    assert p.source == "model" and p.param == "user" and p.payload == "admin'--"
    bad = probe.plan_for("sqli", "http://lab:5006/?u=1", proposal="payload: a b c\npath: not/absolute")
    assert bad is not None and bad.source == "scanner"  # the model plan was rejected as a whole


# -- signals / verdicts ----------------------------------------------------------------------

def test_sqli_is_critical_only_for_a_database_signal(monkeypatch):
    plan = probe.Plan("sqli", "GET", "/login", "u", benign="1", payload="'", signal="'")
    bodies = iter([_resp(200, "<form>id 1</form>"), _resp(500, "sqlite3.OperationalError: near \"'\"")])
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: next(bodies))
    ev = probe.run_ok(plan, identity="x")
    assert ev.verdict == "confirmed" and ev.grade == "critical" and ev.proved


def test_a_page_that_echoes_its_parameter_unescaped_still_proves_xss(monkeypatch):
    """Search-style pages echo on both requests; only the marker tells the two apart."""
    # `q=ring` is recorded, but ssti keeps the *class* control `{{7*6}}` (a bare benign token also echoes on a
    # vulnerable ssti page and would mask the hit).
    plan = probe.plan_for("Server-side template injection (CWE-94)", "http://lab:5006/lab?name=Ana")
    assert plan.benign == "{{7*6}}" and plan.payload == "{{7*7}}"
    seq = iter([_resp(200, "Hello, {{7*6}}"), _resp(200, "Hello, 49")])
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: next(seq))
    ev = probe.run_ok(plan)
    assert ev.verdict == "confirmed" and ev.grade == "critical"
    assert plan.benign != plan.payload


def test_page_break_search_that_escapes_the_probe_is_not_proof(monkeypatch):
    plan = probe.plan_for("Reflected cross-site scripting (CWE-79)", "http://lab:5006/lab?q=ring")
    seq = iter([_resp(200, "you searched tirithctl"), _resp(200, "you searched &lt;tirith-script&gt;")])
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: next(seq))
    assert probe.run_ok(plan).verdict == "not_reproduced"


def test_a_signal_that_also_appears_on_the_control_is_not_a_proof(monkeypatch):
    plan = probe.Plan("lfi", "GET", "/read", "file", benign="index", payload="../../etc/passwd", signal="x")
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: _resp(200, "root:x:0:0:root:/root:/bin/bash"))
    ev = probe.run_ok(plan)
    assert ev.verdict in ("suspected", "not_reproduced") and not ev.proved


def test_echo_only_xss_is_suspected_and_reproduce_steps_name_the_identity(monkeypatch):
    plan = probe.Plan("xss", "GET", "/q", "q", benign="hi", payload="<tirith-script>", signal="<tirith-script>")
    seq = iter([_resp(200, "you searched &lt;tirith-script&gt;"), _resp(200, "you searched <tirith-script>")])
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: next(seq))
    ev = probe.run_ok(plan, identity="tester")
    assert ev.verdict == "confirmed" and ev.grade == "high"
    steps = "\n".join(ev.lines())
    assert "control first" in steps and "X-Demo-User: tester" in steps


def test_a_dead_app_is_an_error_not_a_pass(monkeypatch):
    monkeypatch.setattr(probe.http, "request", lambda *a, **k: _resp(0))
    ev = probe.run("ref", probe.Plan("sqli", "GET", "/", "q", payload="'", signal="'"))
    assert ev.verdict == "error" and not ev.proved


# -- the gate --------------------------------------------------------------------------------

def test_projection_needs_a_class_word_in_the_evidence(monkeypatch):
    from app.analyst import probe as p2

    assert p2.plan_for("Login form", "http://lab:5006/login?user=1") is None
    assert p2.plan_for("sqli on login", "http://lab:5006/login?user=1").weakness == "sqli"


def _finding(st) -> Finding:
    asset = st.save_asset(Asset(kind="url", ref="http://lab:5006", name="lab"))
    f, _ = st.upsert_finding(Finding(scan_id="s", asset_id=asset.id, fingerprint="fp", tool="zap", rule_id="40018",
                                    title="SQL injection (CWE-89)", severity="critical", category="dast",
                                    url="http://lab:5006/login?user=1", confidence=0.9))
    return f


def _planner(monkeypatch, replies):
    seq = list(replies)
    monkeypatch.setattr(loop.llm, "chat",
                        lambda *a, **k: LLMResult(content=json.dumps(seq.pop(0) if seq else {"thought": "x", "done": True}),
                                                  model="fake"))


class Registry:
    """Stand-in for AnalystTools with a scripted probe verdict."""

    def __init__(self, result: dict):
        self.result = result
        self.calls = []

    def names(self):
        return ["probe"]

    def describe(self):
        return "- probe(...)"

    async def call(self, name, args):
        self.calls.append(args)
        return self.result


def _done_with(issue: dict):
    return {"thought": "found it", "done": True,
            "report": {"summary": "s", "issues": [{**issue, "fix_status": "proposed"}]}}


def test_an_unproven_high_is_downgraded_and_the_probe_is_run_for_the_model(store, monkeypatch):
    f = _finding(store)
    monkeypatch.setattr("app.remediation.lab.get_lab_target", lambda asset: object())
    monkeypatch.setattr(probe, "env_details", lambda target: {})
    _planner(monkeypatch, [_done_with({"title": "SQLi in login", "severity": "critical", "where": f.url,
                                       "finding_id": f.id, "evidence": "error page"})])
    reg = Registry({"result": "not_reproduced", "grade": None, "proof": False, "reproduce": []})
    run = asyncio.run(loop.run("assess", reg, max_steps_override=3))
    issue = run.report["issues"][0]
    assert reg.calls, "the gate must try a probe for a finding issue"
    assert "path: /login" in reg.calls[0]["proposal"] and "param: user" in reg.calls[0]["proposal"]
    assert issue["severity"] == "suspected" and issue["proof"] == "not_reproduced"
    assert "probe says not_reproduced" in issue["evidence"]


def test_a_working_probe_keeps_the_grade_and_stores_the_steps(store, monkeypatch):
    f = _finding(store)
    monkeypatch.setattr("app.remediation.lab.get_lab_target", lambda asset: object())
    monkeypatch.setattr(probe, "env_details", lambda target: {})
    _planner(monkeypatch, [_done_with({"title": "SQLi in login", "severity": "medium", "where": f.url,
                                       "finding_id": f.id})])
    reg = Registry({"result": "confirmed", "grade": "critical", "proof": True,
                    "reproduce": ["control GET /login?user=1", "probe GET /login?user='"]})
    run = asyncio.run(loop.run("assess", reg, max_steps_override=3))
    issue = run.report["issues"][0]
    assert issue["proof"] == "confirmed" and issue["severity"] == "critical"  # graded up to what was shown
    assert issue["grade"] == "critical", "the grade must travel with the issue or the page demotes it"
    assert len(issue["reproduce"]) == 2
    assert "method: GET" in issue["prove"]


def test_a_report_without_any_probe_is_not_regraded(store, monkeypatch):
    monkeypatch.setattr(loop, "proof_gate", _no_gate)
    _planner(monkeypatch, [_done_with({"title": "SQLi in login", "severity": "critical", "where": "http://x/y?q=1",
                                       "fix_status": "proposed"})])
    run = asyncio.run(loop.run("assess", FakeFacts(), max_steps_override=2))
    issue = run.report["issues"][0]
    assert issue["severity"] == "critical" and "proof" not in issue


async def _no_gate(run_obj, registry):
    return None


class FakeFacts(Registry):
    def __init__(self):
        super().__init__({})

    def names(self):
        return ["findings", "posture"]

    def describe(self):
        return "- findings(...)"


def test_an_issue_without_a_class_plan_is_marked_unproven_but_kept(store, monkeypatch):
    _planner(monkeypatch, [_done_with({"title": "Missing CSP header", "severity": "low", "where": "web:8000/login"})])
    reg = Registry({})
    run = asyncio.run(loop.run("assess", reg, max_steps_override=3))
    issue = run.report["issues"][0]
    assert issue["proof"] == "unproven" and issue["severity"] == "low"
    assert not reg.calls


def test_approve_mode_holds_after_the_first_reproduction(store, monkeypatch):
    _planner(monkeypatch, [
        {"thought": "probe", "action": {"tool": "probe", "args": {"title": "xss", "url": "http://lab:5006/q?q=1"}}},
        _done_with({"title": "xss", "severity": "high", "where": "http://lab:5006/q?q=1"}),
    ])
    reg = Registry({"result": "confirmed", "grade": "high", "proof": True, "reproduce": ["a"]})
    waits = []

    async def fake_checkpoint(timeout=0):
        waits.append(1)
        loop.events.resume()

    monkeypatch.setattr(loop.events, "checkpoint", fake_checkpoint)
    run = asyncio.run(loop.run("assess", reg, max_steps_override=3, pause_after_proof=True))
    assert waits and run.status == "done"
    assert run.waiting_on is None
    # the pause is emitted on the event feed the chat/dashboard reads
    from app.store import get_store

    types = [e.type for e in get_store().recent_events(50)]
    assert "analyst.checkpoint" in types and "analyst.resumed" in types


def test_a_report_render_shows_proof_state_and_steps():
    from app.analyst import html_report

    run = {"id": "arn_x", "goal": "g", "status": "done", "steps": [],
           "report": {"summary": "s", "issues": [
               {"title": "SQLi", "severity": "critical", "where": "http://lab:5006/login?u=1", "proof": "confirmed",
                "grade": "critical", "prove": "method: GET\npath: /login\nparam: u\npayload: '\nsignal: syntax error",
                "reproduce": ["control", "probe"]},
               {"title": "XXE", "severity": "high", "where": "http://lab:5006/x", "proof": "not_reproduced"}]}}
    doc = html_report.render(run, [], "as-found")
    assert "1 reproduced issue." in doc
    assert "pf-confirmed" in doc and "<dt>payload</dt>" in doc
    assert "Not reproduced" in doc
    assert "1 more could not be reproduced here." in doc


def test_report_file_is_written_next_to_the_run(store, monkeypatch, tmp_path):
    _planner(monkeypatch, [_done_with({"title": "Missing CSP", "severity": "low", "where": "web:8000"})])
    run = asyncio.run(loop.run("assess", Registry({}), max_steps_override=2))
    assert Path(run.report_path).is_file()


def test_a_live_handle_keeps_its_destination_and_sends_from_given_executor(monkeypatch):
    """A live handle is not re-verified per request; the URL is its own host:port, and an explicit
    executor is the container the client runs in."""
    from app.analystlab import http as labhttp
    from app.analystlab.lab import LabRef
    from app.remediation.sh import Result

    seen: list[list[str]] = []
    monkeypatch.setattr(labhttp, "verify", lambda c, v: pytest.fail("a live handle is not re-verified"))
    monkeypatch.setattr(labhttp, "audit", lambda *a, **k: None)
    monkeypatch.setattr(labhttp, "docker", lambda argv, **kw: seen.append(argv) or Result(0, "TIRITH_STATUS: 200\n", ""))
    ref = LabRef(handle="live:127.0.0.1:8090", container="peer", variant="live", image="", network="lab",
                 port=8080, host="172.19.0.4", verified_at="live")
    r = labhttp.request(ref, "GET", "/", executor="borrower")
    assert r.status == 200
    assert seen[0][:4] == ["exec", "-i", "borrower", "python"]
    assert seen[0][-2:] == ["http://172.19.0.4:8080/", ""]


def test_a_live_handle_without_a_container_uses_a_local_client(monkeypatch):
    """A native copy or a live handle has no container: the client is a plain local process."""
    from app.analystlab import http as labhttp
    from app.analystlab.lab import LabRef
    from app.remediation.sh import Result

    seen: list[list[str]] = []
    monkeypatch.setattr(labhttp, "audit", lambda *a, **k: None)
    monkeypatch.setattr(labhttp, "run_local",
                        lambda argv, **kw: seen.append(argv) or Result(0, "TIRITH_STATUS: 200\n", ""))
    ref = LabRef(handle="live:127.0.0.1:8090", variant="live", port=8090, verified_at="live")
    r = labhttp.request(ref, "GET", "/")
    assert r.status == 200
    assert seen[0][0] == "python" and not any("docker" in a for a in seen[0])
    assert seen[0][-2:] == ["http://127.0.0.1:8090/", ""]


def test_a_lan_live_handle_goes_out_from_here_not_a_container(monkeypatch):
    """A LAN box is invisible to a container namespace: the client runs in-process and keeps the address
    (a container handle on the supposedly-live ref must not be used)."""
    from app.analystlab import http as labhttp
    from app.analystlab.lab import LabRef
    from app.remediation.sh import Result

    seen: list[list[str]] = []
    monkeypatch.setattr(labhttp, "audit", lambda *a, **k: None)
    monkeypatch.setattr(labhttp, "run_local",
                        lambda argv, **kw: seen.append(argv) or Result(0, "TIRITH_STATUS: 200\n", ""))
    ref = LabRef(handle="live:192.168.50.129:8162", variant="live", container="stale", host="192.168.50.129",
                 port=8162, verified_at="live")
    assert labhttp.request(ref, "GET", "/").status == 200
    assert seen[0][:1] == ["python"]
    assert seen[0][-2:] == ["http://192.168.50.129:8162/", ""]



def test_a_live_port_that_does_not_answer_is_refused_not_sent(monkeypatch):
    """No loopback connect means no handle: nothing is requested over a port nobody listens on."""
    from app.analystlab import copies
    from app.analystlab import http as labhttp
    from app.analystlab import live

    monkeypatch.setattr(copies, "waits", lambda host, port, *a: False)
    monkeypatch.setattr(labhttp, "request", lambda *a, **k: pytest.fail("no request without a connect"))
    with pytest.raises(labhttp.RequestRefused, match="does not answer"):
        live.live_ref("http://127.0.0.1:8090")


def test_a_live_handle_needs_only_a_loopback_connect(monkeypatch):
    """Acceptance is the connect plus any real HTTP answer under 500 -- no container in the path."""
    from app.analystlab import copies
    from app.analystlab import http as labhttp
    from app.analystlab import live

    monkeypatch.setattr(copies, "waits", lambda host, port, *a: (host, port) == ("127.0.0.1", 8090))
    monkeypatch.setattr(labhttp, "request", lambda ref, m, p, **k: labhttp.Response(m, p, {}, 403, {}, "no", 1))
    ref = live.live_ref("http://localhost:8090/")
    assert (ref.host, ref.port, ref.container, ref.variant) == ("127.0.0.1", 8090, "", "live")
    assert ref.handle == "live:localhost:8090" and ref.verified_at == "live"
