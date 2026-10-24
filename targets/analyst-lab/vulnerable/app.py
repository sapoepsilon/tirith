"""Intentionally vulnerable training target (dummy data, owner-authorised).

The flaw is a broken access-control check (CWE-639): the page chooses its identity from `?as=`
and never compares it with the caller's identity. Read-only; nothing here touches the filesystem
or a shell. See ../README.md for the demo scenario and the patched twin in ../patched.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = os.environ.get("DEMO_FLAG", "flag{dummy_ctf_flag_analyst_demo_9f3a}")
USERS = {
    "demo-low": "low",
    "demo-admin": "admin",
}
MAX_BODY = 64 * 1024


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>"
            f"<body><h1>{title}</h1>{body}</body></html>")


class Handler(BaseHTTPRequestHandler):
    server_version = "analyst-lab/1.0"
    sys_version = ""

    def _send(self, status: int, body: str, extra: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8")[:MAX_BODY]
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _identity(self) -> str:
        """Who the caller claims to be. The demo stands in for a session cookie."""
        return (self.headers.get("X-Demo-User") or "").strip()

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        if path == "/":
            links = "".join(f"<li>{u} ({r})</li>" for u, r in USERS.items())
            self._send(200, _page("Analyst demo target", f"<p>Signed in as <b>{self._identity() or 'apprentice'}</b></p>"
                                                          f"<ul>{links}</ul><p><a href='/flag'>flag</a></p>"))
        elif path == "/health":
            self._send(200, json.dumps({"ok": True, "app": "analyst-lab", "variant": "vulnerable"}))
        elif path == "/flag":
            self._flag(query)
        else:
            self._send(404, _page("Not found", "<p>No such page.</p>"))

    def _flag(self, query: dict[str, list[str]]) -> None:
        # The flaw: the page's identity comes from the request, and nothing compares it with the
        # caller. `GET /flag` as demo-low is 403; `GET /flag?as=demo-admin` is 200.
        who = (query.get("as") or [self._identity()] or ["apprentice"])[0]
        if USERS.get(who) != "admin":
            self._send(403, _page("Not authorized", "<p>You are not allowed to read the flag.</p>"))
            return
        self._send(200, _page("Flag", f"<p>Welcome, {who}.</p><pre>{FLAG}</pre>"))

    def log_message(self, fmt: str, *args) -> None:  # quiet, one line, never the body
        print(f"analyst-lab: {self.requestline}", flush=True)


def main() -> None:
    host = os.environ.get("BIND", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()