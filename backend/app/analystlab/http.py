"""The only network path for the analyst lab: ONE request, sent from a client that can see the app.

`local_exec(<interpreter>, ["-", <method>, <url>, <identity>, <name>=<value> headers…])` with the
fixed client script on stdin. Where a container runtime holds the copy the exec is
`docker exec -i <container> python - …`; otherwise the same argv runs as a local process in this
guest. Both strings are identical: loopback is loopback for the client and for the destination.

The client is plain stdlib Python (no curl, no script from the model), and the URL appears only as
a value the script fetches once.

Policy, all before the exec (there is no other network call anywhere in this module):
  - the destination is `<loopback>:<port>` from `lab.LabRef`; the model never supplies a host,
    URL, port or method;
  - `path` must be a plain absolute path (no scheme/authority/`..`/`//`/control bytes), the query is
    ≤8 parameters of `[A-Za-z0-9._~-%]` (percent-encoding is how a probe payload travels), the only
    header values the model can set are the demo identity and the content type/accept (capped length);
  - values are already percent-encoded by the caller and are never re-encoded here (`%3C` must reach
    the app as a `<`, not as `%253C`);
  - writes are form-encoded POSTs by default and `PUT`/`PATCH`/`DELETE` are allowed for explicit
    reproductions (every write applies to the lab copy only);
  - no redirect following (the client refuses to follow; a 3xx is returned and marked), no proxies
    (urllib with a direct opener, never env proxies), output capped;
  - one exec per request, hard timeout; a failed exec is reported as "no answer", not raised.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from ..audit import audit
from ..remediation.sh import docker
from ..scanners.docker import run_local
from . import live as livemod
from .lab import LabRef, verify

MAX_BYTES = 65536
MAX_PARAMS = 8
MAX_QUERY_CHARS = 512
PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,300}$")
PARAM_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,40}$")
PARAM_VALUE = re.compile(r"^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2}){0,200}$")
IDENTITY = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
# Header names the analyst may set. `X-Demo-User` carries the synthetic identity; the rest are the
# ordinary content-type/accept a browser would send so a form POST is actually parsed as one.
ALLOWED_HEADERS = frozenset({"x-demo-user", "content-type", "accept", "cookie"})
HEADER_VALUE = re.compile(r"^[\x20-\x7e]{0,300}$")
FORM = "application/x-www-form-urlencoded"
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
STATUS_RE = re.compile(r"^TIRITH_STATUS:\s*(\d{3})")
REDIRECT = (301, 302, 303, 307, 308)


class RequestRefused(RuntimeError):
    """A scope/argument refusal. Raised before any exec."""


@dataclass
class Response:
    method: str
    path: str
    query: dict[str, str]
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    redirect: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path, "query": self.query, "status": self.status,
                "headers": self.headers, "body": self.body, "elapsed_ms": self.elapsed_ms,
                "redirect": self.redirect, "error": self.error or None}


def check_path(path: str) -> str:
    path = (path or "").strip()
    if not PATH_RE.match(path) or ".." in path.split("/") or "//" in path:
        raise RequestRefused(f"path {path!r} is not a plain absolute path (no scheme, host, '..' or '//')")
    return path


def _latin(v: str) -> bool:
    """A raw printable ASCII value (a probe payload like `admin'--`): encoded here, once."""
    return 0 < len(v) <= 200 and all(0x20 <= ord(c) < 0x7F for c in v)


def check_query(query: dict[str, str]) -> dict[str, str]:
    if not isinstance(query, dict):
        raise RequestRefused("query must be an object of name -> value")
    if len(query) > MAX_PARAMS:
        raise RequestRefused(f"at most {MAX_PARAMS} query parameters")
    out: dict[str, str] = {}
    for k, v in query.items():
        if not isinstance(k, str) or not PARAM_NAME.match(k):
            raise RequestRefused(f"invalid parameter name {k!r}")
        if not isinstance(v, str) or not (PARAM_VALUE.match(v) or _latin(v)):
            raise RequestRefused(f"invalid value for {k!r}: printable ASCII, up to 200 chars")
        out[k] = v
    if len("&".join(f"{k}={v}" for k, v in out.items())) > MAX_QUERY_CHARS:
        raise RequestRefused("query too long")
    return out


def check_identity(who: str | None) -> str:
    if not who:
        return ""
    if not IDENTITY.match(who):
        raise RequestRefused(f"invalid identity {who!r}")
    return who


def check_method(method: str | None, *, form: bool = False) -> str:
    m = (method or "").strip().upper() or ("POST" if form else "GET")
    if m not in METHODS:
        raise RequestRefused(f"method {method!r} is not one of {', '.join(METHODS)}")
    return m


def check_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Allow-listed headers, lower-cased. The identity header is only ever the fixed demo shapes."""
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        name = k.strip().lower()
        if name not in ALLOWED_HEADERS:
            raise RequestRefused(f"header {k!r} not allowed; allowed: {sorted(ALLOWED_HEADERS)}")
        if not isinstance(v, str) or not HEADER_VALUE.match(v):
            raise RequestRefused(f"invalid value for header {k!r}")
        if name == "x-demo-user":
            check_identity(v.strip())
            v = v.strip()
        out[name] = v
    return out


def target_url(ref: LabRef, path: str, query: dict[str, str] | None = None) -> str:
    url = ref.app_url + quote(path, safe="/._~-")
    q = check_query(query or {})
    if q:
        url += "?" + "&".join(f"{quote(k, safe='._-')}={v}" for k, v in q.items())
    return url


def off_box(ref: LabRef) -> bool:
    """Does the destination sit outside this machine (a LAN box)? A container's namespace cannot see it,
    and the copy's container is then not reachable from the client either, so the request goes local."""
    return ref.variant == "live" and not livemod.resolve_local(ref.host)


def client_addr(ref: LabRef) -> str:
    """The connect address. Loopbacks collapse to 127.0.0.1 (the client cannot use `localhost` inside a
    container); anything else, a copy or a live box, is used as it is."""
    return "127.0.0.1" if ref.host in livemod.LOOPBACKS else ref.host


def client_container(ref: LabRef) -> str:
    """Where the exec runs: the copy's container, or blank (in-process) for an off-box destination."""
    if off_box(ref):
        return ""
    return ref.container


def client_url(ref: LabRef, path: str, query: dict[str, str] | None = None) -> str:
    """Same as `target_url`, at the address the client can actually reach."""
    addr = client_addr(ref)
    ref = LabRef(**{**ref.__dict__, "host": addr}) if addr != ref.host else ref
    return target_url(ref, path, query)


def local_exec(interpreter: str, argv: list[str], script: str, *, container: str = "",
               timeout: int = 20) -> Result:
    """Run a fixed argv exactly once: inside `container` when one holds the copy, else in-process.

    `python -` = "run the script on stdin", which works the same through `docker exec -i` and for a
    local process, so the caller builds one argv for both."""
    if container:
        return docker(["exec", "-i", container, interpreter, *argv], timeout=timeout, input=script)
    return run_local([interpreter, *argv], timeout=timeout, input=script)


_CLIENT = r"""
import sys, urllib.request, urllib.error, urllib.parse
method, url, who = sys.argv[1], sys.argv[2], sys.argv[3]
pairs = [a.split("=", 1) for a in sys.argv[4:]]
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
hdr = {"Accept": "text/html,*/*", "User-Agent": "tirith-analystlab/1"}
data = None
for k, v in pairs:
    hdr[k] = v
if method in ("POST", "PUT", "PATCH") and hdr.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
    body = url.split("?", 1)[1] if "?" in url else ""
    data = urllib.parse.quote(body, safe="").encode()
    hdr["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
req = urllib.request.Request(url, data=data, headers=hdr, method=method)
try:
    r = op.open(req, timeout=8)
    code, headers, body = r.status, r.headers, r.read(65536)
except urllib.error.HTTPError as e:
    code, headers, body = e.code, e.headers, e.read(65536)
except Exception as e:
    print("TIRITH_ERR: %s: %s" % (type(e).__name__, e)); sys.exit(3)
print("TIRITH_STATUS: %d" % code)
for k, v in (headers.items() if headers else []):
    if k.lower() != "set-cookie":
        print("%s: %s" % (k, v))
print("TIRITH_BODY_MARK")
sys.stdout.write(body.decode("utf-8", "replace"))
"""


def request(ref: LabRef, method: str, path: str, *, query: dict[str, str] | None = None,
            as_user: str | None = None, headers: dict[str, str] | None = None, label: str = "",
            executor: str = "") -> Response:
    """One request from the copy's client to its loopback. Nothing else is contacted.

    `executor` is the container the exec actually runs in when one is given (a live copy may still be
    held by a container); default is `ref.container`, and blank means "run the client right here".
    `ref.app_url` decides the destination in every case."""
    import time

    m = check_method(method)
    path = check_path(path)
    qs = check_query(query or {})
    who = check_identity(as_user)
    hdrs = check_headers(headers)
    if not ref.live:  # a live handle is re-checked only by its builder (`live.live_ref`)
        ref = verify(ref.container, ref.variant)
    url = client_url(ref, path, qs)
    argv = ["-", m, url, who] + [f"{k}={v}" for k, v in hdrs.items()]
    container = executor or client_container(ref)
    audit("analystlab.request", target=f"{ref.handle}:{url}", actor="analyst",
          details={"handle": ref.handle, "container": container or "local", "identity": who or None,
                   "method": m, "label": label or None})
    t0 = time.monotonic()
    r = local_exec("python", argv, _CLIENT, container=container)
    ms = int((time.monotonic() - t0) * 1000)
    if not r.ok:
        return Response(m, path, qs, 0, {}, "", ms, False, error=(r.tail(200) or "no answer"))
    return parse(r.out, path, qs, ms, method=m)


def get(ref: LabRef, path: str, *, query: dict[str, str] | None = None, as_user: str | None = None,
        headers: dict[str, str] | None = None, label: str = "") -> Response:
    return request(ref, "GET", path, query=query, as_user=as_user, headers=headers, label=label)


def post(ref: LabRef, path: str, *, form: dict[str, str] | None = None, as_user: str | None = None,
         headers: dict[str, str] | None = None) -> Response:
    hdrs = {"content-type": FORM, **(headers or {})}
    return request(ref, "POST", path, query=form, as_user=as_user, headers=hdrs)

def parse(out: str, path: str, qs: dict[str, str], ms: int, *, method: str = "GET") -> Response:
    """Split the client's fixed frame (status line, headers, body marker) back into a Response."""
    lines = out.splitlines()
    status = 0
    headers: dict[str, str] = {}
    body = ""
    for i, line in enumerate(lines):
        m = STATUS_RE.match(line)
        if m:
            status = int(m.group(1))
            rest = lines[i + 1:]
            try:
                at = rest.index("TIRITH_BODY_MARK")
                heads, body_lines = rest[:at], rest[at + 1:]
            except ValueError:
                heads, body_lines = rest, []
            for h in heads:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers[k.strip()] = v.strip()
            body = "\n".join(body_lines)[:MAX_BYTES]
            break
    if not status:
        return Response(method, path, qs, 0, {}, "", ms, False, error=(out.strip()[:200] or "no answer"))
    return Response(method, path, qs, status, headers, body, ms, status in REDIRECT)
