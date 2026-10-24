"""reproduce: controlled request replay against the lab copy (docker mocked, scripted responses)."""

from __future__ import annotations

import re

import pytest

from app.models import Finding
from app.remediation import lab, reproduce
from app.remediation.sh import Result

TIRITH_EVIDENCE = ("I have started the attack as a usual user\n"
                   "I have tried to get 1 number from table\n"
                   "Sqli attack successful!\nevidence: http://localhost:8080/sql/?name=test'")


@pytest.fixture(autouse=True)
def no_session(monkeypatch):
    monkeypatch.setattr(lab, "session", lambda h, refresh=False: {"sessionid": "labonly", "csrftoken": "c"})
    monkeypatch.setenv("TIRITH_REPRO_LLM", "0")
    monkeypatch.setenv("TIRITH_REPRO", "1")


def handle():
    return lab.LabHandle(url="http://c:8000/", network="tirith-lab", container="c", image="i", port=8000,
                         django_settings="pygoat.settings")


def finding(**kw):
    base = dict(scan_id="s", asset_id="a", fingerprint="fp", tool="zap", rule_id="zap-40018", title="SQL Injection",
                severity="high", category="dast", file=None, snippet=TIRITH_EVIDENCE, cwe="CWE-89",
                url="http://localhost:8080/sql/?name=test'", confidence=0.7)
    base.update(kw)
    return Finding(**base)


def responder(body_for):
    """Fake run(): answers each `docker exec ... sh -c 'curl ...'` with body_for(params)."""
    calls: list[dict[str, str]] = []

    def fake(args, timeout=300, cwd=None, input=None):
        from urllib.parse import parse_qsl, urlsplit

        if args[:3] == ["docker", "exec", "-i"] or args[:2] == ["docker", "exec"]:
            cmd = args[-1]
            m = re.search(r"-w '\\nTIRITH_REPRO_STATUS:%\{http_code\}' '?(http://127\.0\.0\.1:\d+[^\s']*)", cmd)
            url = m.group(1) if m else ""
            form = re.search(r"--data-binary '([^']*)'", cmd)
            params = (dict(parse_qsl(form.group(1))) if form
                      else dict(parse_qsl(urlsplit(url).query)))
            calls.append(params)
            body = body_for(params)
            if isinstance(body, tuple):
                return Result(0, f"HTTP/1.1 {body[0]} X\r\nContent-Type: text/html\r\n\r\n{body[1]}\nTIRITH_REPRO_STATUS:{body[0]}", "")
            return Result(0, f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}\nTIRITH_REPRO_STATUS:200", "")
        return Result(0, "", "")

    fake.calls = calls
    return fake


def test_sqli_confirmed_only_on_probe(monkeypatch):
    fake = responder(lambda p: "SQLITE_ERROR near 1\n" if "'" in (p.get("name") or "") else "item 1")
    monkeypatch.setattr(reproduce, "run", fake)
    v = reproduce.reproduce(finding(), handle())
    assert v.result == "confirmed" and v.check == "reproduce-sqli"
    assert fake.calls[0].get("name", "") == "" and "'" in fake.calls[1]["name"]  # control first, then probe
    assert len(fake.calls) == 2
    labels = [e.label for e in v.evidence]
    assert "matched excerpt" in labels and any("control" in e.content for e in v.evidence if e.kind == "response")


def test_control_failing_means_unsupported_not_confirmed(monkeypatch):
    fake = responder(lambda p: "SQLITE_ERROR: no such table")  # endpoint always errors
    monkeypatch.setattr(reproduce, "run", fake)
    v = reproduce.reproduce(finding(), handle())
    assert v.result == "unsupported" and len(fake.calls) == 1  # never sends a probe that would prove nothing


def test_echo_is_not_execution_for_xss(monkeypatch):
    # PyGoat echoes the input: the literal payload comes back escaped, never as an element.
    def page(p):
        from html import escape
        return "<html><p>You searched: " + escape("ab" + p.get("q", "")) + "</p></html>"

    fake = responder(page)
    monkeypatch.setattr(reproduce, "run", fake)
    f = finding(title="Cross Site Scripting", cwe="CWE-79", rule_id="zap-40012",
                snippet="GET http://localhost:8080/xss/?q=test%3C", url="http://localhost:8080/xss/?q=test%3C")
    v = reproduce.reproduce(f, handle())
    assert v.result == "not_reproduced" and "would prove nothing" not in " ".join(e.content for e in v.evidence)


def test_xss_execution_confirmed(monkeypatch):
    fake = responder(lambda p: "<div><script>alert(1)</script></div>" if "script" in p.get("q", "") else "<div></div>")
    monkeypatch.setattr(reproduce, "run", fake)
    f = finding(title="Cross Site Scripting", cwe="CWE-79", rule_id="zap-40012",
                snippet="GET http://localhost:8080/xss/?q=test%3C", url="http://localhost:8080/xss/?q=test%3C")
    v = reproduce.reproduce(f, handle())
    assert v.result == "confirmed" and v.check == "reproduce-xss"


def test_ssti_and_cmdi_signals(monkeypatch):
    fake = responder(lambda p: ("<p>49</p>" if p.get("name") == "{{7*7}}" else
                                f"<pre>{reproduce.CMDI_SAFE}</pre>" if (p.get("host") or "").endswith(reproduce.CMDI_SAFE)
                                else "<p>7*7</p>"))
    monkeypatch.setattr(reproduce, "run", fake)
    ssti = finding(title="Server Side Template Injection", cwe="CWE-1336", rule_id="zap-90035",
                   snippet="GET http://localhost:8080/ssti/?name=x%7B%7B", url="http://localhost:8080/ssti/?name=x%7B%7B")
    assert reproduce.reproduce(ssti, handle()).result == "confirmed"
    cmdi = finding(title="OS Command Injection", cwe="CWE-78", rule_id="zap-90020",
                   snippet="GET http://localhost:8080/ping/?host=127.0.0.1;", url="http://localhost:8080/ping/?host=127.0.0.1;")
    assert reproduce.reproduce(cmdi, handle()).result == "confirmed"


def test_no_lab_no_evidence_url_and_unknown_class_are_unsupported(monkeypatch):
    monkeypatch.setattr(reproduce, "run", pytest.fail)
    assert reproduce.reproduce(finding(), None).result == "unsupported"
    assert reproduce.reproduce(finding(snippet="", url=""), handle()).result == "unsupported"
    generic = finding(title="Missing Anti-clickjacking Header", cwe="CWE-693", rule_id="zap-10020")
    assert reproduce.reproduce(generic, handle()).result == "unsupported"


def test_cloud_tunnel_host_is_not_replayed(monkeypatch):
    monkeypatch.setattr(reproduce, "run", pytest.fail)
    f = finding(snippet="GET https://abc123.ngrok-free.app/sql/?name=test",
                url="https://abc123.ngrok-free.app/sql/?name=test")
    v = reproduce.reproduce(f, handle())
    assert v.result == "unsupported" and "not the lab copy" in v.evidence[-1].content


def test_model_proposal_must_match_shape_and_falls_back(monkeypatch):
    import json

    from app.remediation import llm

    fake = responder(lambda p: "SQLITE_ERROR" if "'" in (p.get("name") or "") else "ok")
    monkeypatch.setattr(reproduce, "run", fake)
    monkeypatch.setenv("TIRITH_REPRO_LLM", "1")

    def chat(bad):
        def _c(messages, **kw):
            return {"payload": bad, "reason": "x"}, llm.LLMResult(content=json.dumps({"payload": bad}), model="m")
        return _c

    monkeypatch.setattr(llm, "chat_json", chat("'; DROP TABLE users; --\n; rm -rf /"))
    v = reproduce.reproduce(finding(), handle())
    assert v.result == "confirmed"  # fixed payload used after the rejected proposal
    assert any("proposal rejected" in e.content for e in v.evidence if e.label == "plan")
    assert all("rm -rf" not in str(c) for c in fake.calls)

    fake.calls.clear()
    monkeypatch.setattr(llm, "chat_json", chat("1' OR '1'='1"))
    v = reproduce.reproduce(finding(), handle())
    assert v.result == "confirmed"
    assert fake.calls[1]["name"] == "1' OR '1'='1"  # accepted proposal is the one sent


def test_secret_params_are_redacted_in_request_evidence(monkeypatch):
    fake = responder(lambda p: "SQLITE_ERROR" if "'" in (p.get("q") or "") else "ok")
    monkeypatch.setattr(reproduce, "run", fake)
    f = finding(snippet="GET http://localhost:8080/s/?q=test&password=hunter2",
                url="http://localhost:8080/s/?q=test%27&password=hunter2")
    v = reproduce.reproduce(f, handle())
    reqs = "\n".join(e.content for e in v.evidence if e.kind == "request")
    assert "hunter2" not in reqs and "password=%2A%2A%2A" in reqs
    assert "sessionid=labonly" not in "\n".join(e.content for e in v.evidence)  # lab cookie never stored


def test_request_cap(monkeypatch):
    fake = responder(lambda p: "ok")
    monkeypatch.setattr(reproduce, "run", fake)
    monkeypatch.setattr(reproduce, "MAX_REQUESTS", 2)
    monkeypatch.setenv("TIRITH_REPRO_LLM", "1")

    from app.remediation import llm

    def _c(messages, **kw):
        return {"payload": "1' OR '1'='1"}, llm.LLMResult(content="{}", model="m")

    monkeypatch.setattr(llm, "chat_json", _c)
    reproduce.reproduce(finding(), handle())
    assert len(fake.calls) == 2