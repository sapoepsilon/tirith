"""Access control: bearer token on /api/* and the WebSocket, startup refusal, CORS, /mode policy, ?replay=."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import config
from app import main as main_mod

TOKEN = "test-api-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def env(monkeypatch, tmp_path, tmp_store):
    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / "data" / sub if sub else tmp_path / "data")
    monkeypatch.setenv("TIRITH_API_TOKEN", TOKEN)
    for v in ("TIRITH_ALLOW_NO_AUTH", "TIRITH_ALLOW_AUTONOMOUS"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(main_mod, "api_health",
                        lambda: {"ok": True, "service": "tirith-backend", "docker": False, "missing_tools": ["nmap"]})
    import app.routes_core as rc
    monkeypatch.setattr(rc, "docker_available", lambda: False)
    return monkeypatch


@pytest.fixture()
def client(env):
    with TestClient(main_mod.app) as c:
        yield c


def test_health_is_public_on_both_paths(client):
    for path in ("/health", "/api/health"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert set(r.json()) == {"ok", "service", "docker", "missing_tools"}
        assert r.json()["ok"] is True and r.json()["service"] == "tirith-backend"
        assert "nmap" in r.json()["missing_tools"]  # real check: the CLIs are not installed here


@pytest.mark.parametrize("path", ["/api/assets", "/api/scope", "/api/mode", "/api/audit", "/api/events/recent",
                                  "/api/lab", "/api/findings", "/openapi.json", "/docs"])
def test_routes_require_token(client, path):
    r = client.get(path)
    assert r.status_code == 401 and r.json() == {"detail": "missing or invalid bearer token"}
    assert r.headers["www-authenticate"].startswith("Bearer")
    assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(path, headers={"Authorization": TOKEN}).status_code == 401  # scheme required


def test_valid_token_passes(client):
    assert client.get("/api/assets", headers=AUTH).status_code == 200
    assert client.get("/api/mode", headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200
    # Non-GET on a public path is not public.
    assert client.post("/api/health").status_code == 401


def test_remediation_routes_protected(client):
    assert client.post("/api/findings/nope/explain").status_code == 401
    assert client.post("/api/findings/nope/explain", headers=AUTH).status_code == 404


def test_ws_requires_token(client):
    for path in ("/ws/events", "/api/ws/events"):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(path):
                pass
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(path, headers={"Authorization": "Bearer nope"}):
                pass


def test_ws_header_and_subprotocol_auth(client, tmp_store):
    from app.events import emit
    emit("scan.started", "one")
    emit("scan.finished", "two")
    with client.websocket_connect("/api/ws/events?replay=2", headers=AUTH) as ws:
        assert [ws.receive_json()["message"] for _ in range(2)] == ["one", "two"]
    with client.websocket_connect("/ws/events?replay=1", subprotocols=["tirith.v1", f"bearer.{TOKEN}"]) as ws:
        assert ws.accepted_subprotocol == "tirith.v1"
        assert ws.receive_json()["message"] == "two"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events", subprotocols=["tirith.v1", "bearer.wrong"]):
            pass


@pytest.mark.parametrize("raw", ["abc", "-5", "", "1e3", "99999999999999999999"])
def test_ws_bad_replay_values(client, tmp_store, raw):
    from app.events import emit
    for i in range(3):
        emit("scan.started", f"e{i}")
    with client.websocket_connect(f"/ws/events?replay={raw}", headers=AUTH) as ws:
        emit("scan.finished", "live")
        msg = ws.receive_json()
        # Bad values replay nothing; huge values clamp to the buffer (first replayed event is e0).
        assert msg["message"] == ("e0" if raw.startswith("999") else "live")


def test_replay_count():
    assert main_mod._replay_count(None) == 0
    assert main_mod._replay_count("x") == 0
    assert main_mod._replay_count("-1") == 0
    assert main_mod._replay_count(" 7 ") == 7
    assert main_mod._replay_count("100000") == main_mod.REPLAY_MAX


def test_refuses_to_start_without_token(env):
    env.delenv("TIRITH_API_TOKEN")
    with pytest.raises(RuntimeError, match="TIRITH_API_TOKEN"):
        with TestClient(main_mod.app):
            pass
    # Without startup (no lifespan) requests still fail closed.
    assert TestClient(main_mod.app).get("/api/assets").status_code == 503


def test_allow_no_auth_dev_mode(env):
    env.delenv("TIRITH_API_TOKEN")
    env.setenv("TIRITH_ALLOW_NO_AUTH", "1")
    with TestClient(main_mod.app) as c:
        assert c.get("/api/assets").status_code == 200


def test_cors_origins(env):
    env.setenv("TIRITH_CORS_ORIGINS", "https://dash.example.com, *")
    assert config.cors_origins() == ["https://dash.example.com"]  # wildcard is never honoured
    env.delenv("TIRITH_CORS_ORIGINS")
    assert config.cors_origins() == []


def test_no_cors_headers_by_default(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


# -- PUT /mode policy ---------------------------------------------------------
def test_mode_assisted_ok(client, tmp_store):
    r = client.put("/api/mode", json={"mode": "assisted", "autonomous_categories": ["dependency_bump"]}, headers=AUTH)
    assert r.status_code == 200 and r.json()["mode"] == "assisted"
    assert tmp_store.get_mode().mode == "assisted"


def test_mode_rejects_unknown_mode(client):
    assert client.put("/api/mode", json={"mode": "yolo"}, headers=AUTH).status_code == 422


@pytest.mark.parametrize("cats", [["code_patch"], ["dependency_bump", "secret_removal"], ["*"]])
def test_mode_rejects_other_categories(client, tmp_store, cats):
    r = client.put("/api/mode", json={"mode": "assisted", "autonomous_categories": cats}, headers=AUTH)
    assert r.status_code == 422 and "dependency_bump" in r.json()["detail"]
    assert tmp_store.get_mode().mode == "observe"
    assert tmp_store.list_audit(1)[0].allowed is False


def test_mode_autonomous_needs_env(client, env, tmp_store):
    body = {"mode": "autonomous", "autonomous_categories": ["dependency_bump"]}
    r = client.put("/api/mode", json=body, headers=AUTH)
    assert r.status_code == 403 and "TIRITH_ALLOW_AUTONOMOUS" in r.json()["detail"]
    assert tmp_store.get_mode().mode == "observe"
    assert tmp_store.recent_events(1)[-1].type == "policy.denied"
    env.setenv("TIRITH_ALLOW_AUTONOMOUS", "1")
    r = client.put("/api/mode", json={**body, "autonomous_categories": ["dependency_bump", "dependency_bump"]}, headers=AUTH)
    body = r.json()
    body.pop("transient", None)  # switched by hand => restored after the next run
    assert r.status_code == 200 and body == {"mode": "autonomous", "autonomous_categories": ["dependency_bump"]}
