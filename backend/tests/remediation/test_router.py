from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.remediation import install

from .conftest import django_finding


def client():
    app = FastAPI()
    install(app)
    return TestClient(app)


def test_explain_endpoint_streams_events(store, asset):
    f = django_finding(store, asset)
    r = client().post(f"/api/findings/{f.id}/explain")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"summary", "root_cause", "exploitability", "fix_plan"}
    types = [e.type for e in store.recent_events(20)]
    assert "ai.thinking" in types and types[-1] == "ai.summary"
    assert store.get_finding(f.id).ai_summary == body["summary"]


def test_validate_endpoint(store, asset):
    f = django_finding(store, asset)
    r = client().post(f"/api/findings/{f.id}/validate")
    assert r.status_code == 200 and r.json()["result"] == "confirmed"


def test_fix_refused_in_observe(store, asset):
    f = django_finding(store, asset)
    r = client().post(f"/api/findings/{f.id}/fix", json={"mode": "assisted"})
    assert r.status_code == 403 and "observe" in r.json()["detail"]


def test_unknown_ids(store):
    c = client()
    assert c.post("/api/findings/nope/explain").status_code == 404
    assert c.get("/api/fixes/nope").status_code == 404
    assert c.post("/api/fixes/nope/rollback").status_code == 404


def test_lab_hook_installed():
    from app.remediation import lab
    from app.scanners import tools

    client()
    assert tools.get_lab_target is lab.get_lab_target


def test_github_and_policy_errors_map_to_502_and_403(store, monkeypatch):
    from app.remediation import fix

    c = client()
    monkeypatch.setattr(fix, "rollback_fix", lambda fid: (_ for _ in ()).throw(fix.PolicyError("nope")))
    assert c.post("/api/fixes/x/rollback").status_code == 403
    monkeypatch.setattr(fix, "rollback_fix", lambda fid: (_ for _ in ()).throw(fix.GitHubError("down")))
    assert c.post("/api/fixes/x/rollback").status_code == 502
    monkeypatch.setattr(fix, "apply_fix", lambda fid: (_ for _ in ()).throw(fix.PolicyError("nope")))
    assert c.post("/api/fixes/x/apply").status_code == 403
    monkeypatch.setattr(fix, "apply_fix", lambda fid: (_ for _ in ()).throw(fix.GitHubError("down")))
    assert c.post("/api/fixes/x/apply").status_code == 502
