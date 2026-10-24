"""Intentionally vulnerable demo target for Tirith (dummy data, owner-authorised).

Same contract as ../analyst-lab (same `analystlab/lab.py` boot rules) but six independent flaws instead
of one, so a demo can show a breadth of findings in a single scan. Each flaw has its own marker string
and its own damage payload; nothing here touches the internet. See ../README.md.

    /search?q=          reflected XSS        (CWE-79)
    /item?id=           SQL injection        (CWE-89, sqlite3 error) -> also dumps the `secrets` table
    /render?name=       SSTI                 (CWE-94, evaluates {{ 7*7 }} and {{ secret }})
    /ping?host=         command injection    (CWE-78, /bin/sh -c) -> creates /tmp/pwned in the container
    /read?file=         path traversal       (CWE-22, cat of any path)
    /admin?level=       authz bypass         (CWE-639, chooses its own role from the request)

Diagnostics (same scanner signature as analyst-lab's /health):
    /health             {"ok": true, "app": "analyst-lab", "variant": "vulnerable", "flaws": 6}
    /__meta             the same JSON, for humans

Write endpoint (used by the "fix" half of a demo; input is not sanitised):
    POST /feedback      form field `message`, stored in memory and echoed back
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FLAG = os.environ.get("DEMO_FLAG", "flag{breach_lab_all_six_9d31}")
ROOT = os.environ.get("DEMO_ROOT", "/srv/data")
VARIANT = os.environ.get("DEMO_VARIANT", "vulnerable")
MAX_BODY = 64 * 1024

PAGES = {
    "/": "Home", "/search": "Search", "/item": "Item", "/render": "Template", "/ping": "Ping",
    "/read": "File reader", "/admin": "Admin console", "/feedback": "Feedback",
}
_SEED = [  # (title, secret) — dummy rows the SQL injection is supposed to reach
    ("deploy token", "tok_demo_5f1c2a"),
    ("grafana key", "glsa_demo_77be01"),
    ("admin password", "not-a-real-password"),
]
_FEEDBACK: list[str] = []


def _page(title: str, body: str, nav: bool = True) -> str:
    links = "".join(f"<li><a href='{h}?{q}'>{n}</a></li>" for h, q, n in (
        ("/search", "q=ring", "search"), ("/item", "id=1", "item"), ("/render", "name=Ana", "template"),
        ("/ping", "host=127.0.0.1", "ping"), ("/read", "file=readme.txt", "file"), ("/admin", "level=user", "admin"),
        ("/feedback", "", "feedback"))) if nav else ""
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>"
            f"<body><h1>{title}</h1>{body}{'<ul>' + links + '</ul>' if links else ''}</body></html>")


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("create table items (id integer primary key, title text)")
    con.executemany("insert into items (id, title) values (?, ?)", [(1, "ring"), (2, "sword"), (3, "cloak")])
    con.execute("create table secrets (id integer primary key, name text, value text)")
    con.executemany("insert into secrets (name, value) values (?, ?)", _SEED)
    return con


def _tpl(src: str) -> str:
    """`{{ expr }}` against a tiny scope. Hand-rolled on purpose: the flaw is the eval, not a parser."""
    scope: dict[str, object] = {"secret": _SEED[0][1], "flag": FLAG}

    def one(m: re.Match[str]) -> str:
        try:
            return str(eval(m.group(1), {"__builtins__": {}}, scope))  # noqa: S307 - the flaw
        except Exception as e:  # noqa: BLE001 - the app shows its own errors
            return f"<ERROR {type(e).__name__}>"

    return re.sub(r"\{\{(.*?)\}\}", one, src)


class Handler(BaseHTTPRequestHandler):
    server_version = "breach-lab/1.0"
    sys_version = ""

    def _send(self, status: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")[:MAX_BODY]
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _q(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}

    # ------------------------------------------------------------------ GET
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = urlsplit(self.path).path
        q = self._q()
        handler = {
            "/": self._home, "/health": self._health, "/__meta": self._health, "/search": self._search,
            "/item": self._item, "/render": self._render, "/ping": self._ping, "/read": self._read,
            "/admin": self._admin, "/feedback": self._feedback_page,
        }.get(path)
        if handler is None:
            self._send(404, _page("Not found", "<p>No such page.</p>"))
            return
        handler(q)

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/feedback":
            self._send(405, _page("Method not allowed", "<p>Use GET.</p>"))
            return
        length = min(int(self.headers.get("content-length") or 0), MAX_BODY)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), keep_blank_values=True)
        # The flaw: stored raw and rendered as HTML (stored XSS on the write path).
        _FEEDBACK.append((form.get("message") or [""])[0])
        self._feedback_page({})

    # ------------------------------------------------------------------ pages
    def _home(self, _q: dict[str, str]) -> None:
        likes = len(_FEEDBACK)
        self._send(200, _page("Breach lab", f"<p>Six flaws, one app. Feedback so far: <b>{likes}</b>.</p>"))

    def _health(self, _q: dict[str, str]) -> None:
        self._send(200, json.dumps({"ok": True, "app": "analyst-lab", "variant": VARIANT, "flaws": 6}),
                   "application/json")

    def _search(self, q: dict[str, str]) -> None:
        term = q.get("q", "")
        self._send(200, _page("Search", f"<p>Results for <b>{term or '(nothing)'}</b>:</p>"  # unescaped
                                        f"<p>0 hits in 0.002s</p>"))  # noqa: E501

    def _item(self, q: dict[str, str]) -> None:
        raw = q.get("id", "1")
        # The flaw: the value is pasted into the statement; an unparseable value leaks the sqlite error.
        sql = f"select id, title from items where id = {raw}"
        try:
            rows = _db().execute(sql).fetchall()
        except sqlite3.Error as e:
            self._send(500, _page("Item", f"<p>SQL failed:</p><pre>{e}</pre><p>Query: <code>{sql}</code></p>"))
            return
        body = "".join(f"<li>#{r[0]} {r[1]}</li>" for r in rows) or "<li>no item</li>"
        self._send(200, _page("Item", f"<ul>{body}</ul><p>Query: <code>{sql}</code></p>"))

    def _render(self, q: dict[str, str]) -> None:
        src = q.get("name") or "Hello"
        self._send(200, _page("Template", f"<p>{_tpl(src)}</p>"))

    def _ping(self, q: dict[str, str]) -> None:
        host = q.get("host") or "127.0.0.1"
        # The flaw: one string handed to a shell. `;id` runs a second command, same as the marker below.
        out = subprocess.run(["/bin/sh", "-c", f"ping -c 1 -W 1 {host} 2>&1; id"],  # noqa: S603
                             capture_output=True, text=True, timeout=10).stdout
        self._send(200, _page("Ping", f"<pre>{out[-4000:]}</pre>"))

    def _read(self, q: dict[str, str]) -> None:
        name = q.get("file") or "readme.txt"
        target = os.path.join(ROOT, name)
        # The flaw: join only, no normalisation or jail check.
        try:
            with open(target, encoding="utf-8", errors="replace") as fh:  # noqa: PTH123
                body = fh.read(8000)
            self._send(200, _page("File", f"<p>{name}</p><pre>{body}</pre>"))
        except OSError as e:
            self._send(404, _page("File", f"<p>{name}: {e.strerror}</p>"))

    def _admin(self, q: dict[str, str]) -> None:
        level = q.get("level") or "guest"
        # The flaw: the page trusts the role the caller names; nothing compares it with the caller.
        if level != "admin":
            self._send(403, _page("Admin", f"<p>Role <b>{level}</b>: console locked (try level=admin).</p>"))
            return
        rows = "".join(f"<li>{n}: {v}</li>" for n, v in _SEED)
        self._send(200, _page("Admin", f"<p>Console open as <b>admin</b>.</p><ul>{rows}</ul><pre>{FLAG}</pre>"))

    def _feedback_page(self, _q: dict[str, str]) -> None:
        items = "".join(f"<li>{m}</li>" for m in _FEEDBACK[-20:])
        self._send(200, _page("Feedback", "<form method='post' action='/feedback'>"
                                           "<input name='message' value='hello'> <button>send</button></form>"
                                           f"<ul>{items}</ul>"))

    def log_message(self, fmt: str, *args) -> None:  # quiet, one line, never the body
        print(f"breach-lab: {self.requestline}", flush=True)


def main() -> None:
    os.makedirs(ROOT, exist_ok=True)
    with open(os.path.join(ROOT, "readme.txt"), "w", encoding="utf-8") as fh:
        fh.write("breach-lab data root\n-------------------\nreadme.txt, notes.txt\n")
    with open(os.path.join(ROOT, "notes.txt"), "w", encoding="utf-8") as fh:
        fh.write("demo notes: nothing here is real\n")
    ThreadingHTTPServer((os.environ.get("BIND", "0.0.0.0"), int(os.environ.get("PORT", "8080"))),
                        Handler).serve_forever()


if __name__ == "__main__":
    main()