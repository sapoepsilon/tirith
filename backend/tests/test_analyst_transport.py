"""The request transport without a daemon: a fake app on 127.0.0.1 answers a control + probe.

`test_probe.py` covers the Docker side of `http.request`; these cover the local side, which is the
whole path once the copies run in the guest. The client is the real one (real interpreter, real
argv, real stdin script), only the app is a fixture.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from app.analyst import probe
from app.analystlab import http, lab, live


class _App(BaseHTTPRequestHandler):
    """Echoes the `q` parameter; a quote in it is reported as a database error (a sqli signal)."""

    def do_GET(self):  # noqa: N802 - stdlib name
        q = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        body = f"<html><p>q={q}</p>{'SQL syntax error' if chr(39) in q else ''}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep the test output quiet
        pass


@pytest.fixture()
def app_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@contextmanager
def _no_daemon(monkeypatch):
    """No container anywhere: `docker_available` says no, and any `docker` call trips a failure."""
    monkeypatch.setattr("app.scanners.docker.docker_available", lambda: False)

    def no_docker(*a, **k):
        raise AssertionError("docker used without a daemon")

    monkeypatch.setattr(http, "docker", no_docker)
    yield


def test_control_and_probe_through_the_local_client(app_server, monkeypatch):
    host, port = app_server.split(":")
    with _no_daemon(monkeypatch):
        ref = lab.LabRef(handle="docker-lab", variant="live", host=host, port=int(port), verified_at="live")
        plan = probe.Plan("sqli", path="/search", param="q", benign="1", payload="'", signal="'")
        ev = probe._probe(ref, plan)
    assert ev.verdict == "confirmed" and ev.grade == "critical"
    assert ev.control.status == 200 and "'" not in ev.control.query["q"]
    assert ev.probe.query["q"] == "'" and "SQL syntax error" in ev.probe.body


def test_local_client_forwards_allow_listed_headers(app_server, monkeypatch):
    host, port = app_server.split(":")
    with _no_daemon(monkeypatch):
        ref = lab.LabRef(handle="docker-lab", variant="live", host=host, port=int(port), verified_at="live")
        r = http.request(ref, "GET", "/search", query={"q": "<tirith-script>"},
                         headers={"x-demo-user": "demo-low"}, label="test")
    assert r.status == 200 and "q=<tirith-script>" in r.body
    r2 = http.request(ref, "GET", "/nope", query={"x": "y"})
    assert r2.status == 200 and not r2.error


def test_live_handle_over_loopback_is_the_same_client(app_server, monkeypatch):
    from app.scope import Scope
    monkeypatch.setattr("app.scope.load_scope", lambda: Scope(url_hosts=[app_server]))
    with _no_daemon(monkeypatch):
        ref = live.live_ref(f"http://{app_server}/")
        assert ref.container == "" and (ref.host, ref.port) == tuple(_addr(app_server))
        r = http.get(ref, "/")
    assert r.status == 200


def _addr(hostport: str) -> tuple[str, int]:
    host, port = hostport.split(":")
    return host, int(port)

@pytest.mark.parametrize("flag", [None, True, "true", False])
def test_http_live_argument_is_optional_boolean(flag):
    from app.analyst.tools import _check_args, _http
    args = {"url": "http://192.168.50.129:8162/", "path": "/"}
    if flag is not None:
        args["live"] = flag
    result = _check_args(_http(), args)
    assert result.get("live", False) is (flag in (True, "true"))


def test_live_alias_uses_requested_address_and_retires(monkeypatch):
    from app.scope import Scope
    scope = Scope(url_hosts=["192.0.2.1:8162"],
                  url_aliases={"192.0.2.1:8162": ["192.0.2.2:8162"]})
    monkeypatch.setattr("app.scope.load_scope", lambda: scope)
    monkeypatch.setattr(live, "resolve_local", lambda host: False)
    connects = []
    monkeypatch.setattr(live.copies, "waits", lambda host, port: connects.append((host, port)) or True)
    monkeypatch.setattr(http, "request", lambda *a, **k: http.Response("GET", "/", {}, 200, {}, "", 0))
    ref = live.live_ref("http://192.0.2.2:8162/")
    assert ref.host == "192.0.2.2" and ref.container == ""
    assert connects == [("192.0.2.2", 8162)]
    scope.url_hosts.clear()
    with pytest.raises(http.RequestRefused, match="not in scope"):
        live.live_ref("http://192.0.2.2:8162/")
    assert len(connects) == 1


def test_unlisted_loopback_live_url_is_denied_before_connect(monkeypatch):
    from app.scope import Scope
    monkeypatch.setattr("app.scope.load_scope", lambda: Scope())
    monkeypatch.setattr(live.copies, "waits", lambda *a: pytest.fail("unscoped connect"))
    with pytest.raises(http.RequestRefused, match="not in scope"):
        live.live_ref("http://127.0.0.1:12345/")
