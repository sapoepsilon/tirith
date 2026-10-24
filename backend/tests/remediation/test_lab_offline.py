"""An asset lab copy with no container runtime: a local process on a free loopback port.

The acceptance for this path is `import app.main` with docker off PATH plus a boot that serves:
nothing here calls `docker`, and teardown leaves no process behind.
"""

from __future__ import annotations

import os

import pytest

from app.remediation import lab

APP = """import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"cwd": os.getcwd(), "port": self.server.server_port}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
"""


@pytest.fixture()
def offline(monkeypatch):
    monkeypatch.setattr(lab, "host_mode", lambda: False)

    def _fail(*a, **k):
        raise AssertionError("docker used without a daemon")

    def no_docker(args, **k):
        # No image to inspect: the profile comes from the checkout, the process from its argv.
        return lab.Result(rc=1, out="", err="docker: not found") if args[:2] == ["image", "inspect"] else _fail()

    monkeypatch.setattr(lab, "docker", no_docker)
    lab._registry.clear()


def test_native_boot_serves_the_copy_on_loopback(tmp_path, offline, monkeypatch):
    src = tmp_path / "app"
    src.mkdir()
    (src / "app.py").write_text(APP)
    monkeypatch.setattr(lab, "detect_profile",
                        lambda s, t: lab.Profile(port=8000, argv=[os.sys.executable, "app.py"]))
    h, _ = lab.start("tag", src, "asset:x", "host")
    try:
        code = lab.wait_ready(h, timeout=30)
        assert code == 200 and h.url == f"http://127.0.0.1:{h.port}/"
        req, resp = lab.get_page(h, "/")
        assert req.split()[1] == "/" and f'"cwd": "{src}"' in resp
    finally:
        h.stop()
    assert not lab.copies.pid_alive(h.proc)


def test_native_handle_is_reused_until_the_process_dies(tmp_path, offline, monkeypatch):
    src = tmp_path / "app"
    src.mkdir()
    (src / "app.py").write_text(APP)
    h = lab.LabHandle(url="http://127.0.0.1:0/", network="host", port=0, proc=0)
    started = lab.copies.spawn_detached([os.sys.executable, "app.py"], src, {"PORT": "0"})
    h.proc = started.pid
    lab._registry_put("k", h)
    try:
        assert lab.running("k") is h
        h.stop()
        assert lab.running("k") is None
    finally:
        lab.copies.stop_pid(started.pid)