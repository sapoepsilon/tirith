"""Turn a scanner/classifier observation into a runnable, severity-graded reproduction plan, and run it.

Two properties make the result usable as evidence:

  1. **Severity comes from the signal, not the label.** A SQLi counts as critical only when the response
     proves real database access (a DB error, or our own computed row marker); echo-only findings are
     `suspected`, and a `suspected` reproduction is not proof that the flaw is reachable exploitably.
  2. **Every request is paired with a benign control** sent first. A signal that also appears for the
     control (echo pages, "always errors" endpoints) proves nothing, so the verdict is `not_reproduced`.

The projection can be *given* by the model as a payload, but it is parsed by fixed code here: method,
path, parameter, payload and expected signal are re-derived, and anything unparsable falls back to the
class's built-in payload. A proposal can add signal; it cannot manufacture a pass.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import parse_qs, urlsplit

from ..analystlab import http
from ..analystlab.lab import LabRef
from ..remediation import lab as labmod

CLASSES = ("sqli", "xss", "ssti", "cmdi", "ssrf", "lfi", "idor")
GRADES = ("critical", "high", "suspected")

# One fixed probing payload per class. Each carries its own "did it work" signal, so the payload
# string is the marker wherever the marker is safe to send (see `_verified`).
PAYLOADS: dict[str, str] = {
    "sqli": "'",
    "xss": "<tirith-script>",
    "ssti": "{{7*7}}",
    "cmdi": ";id",
    "ssrf": "http://169.254.169.254/latest/meta-data/",
    "lfi": "../../../../etc/passwd",
    "idor": "",  # numeric bump of the observed value, never a fixed string
}
# What a scanner should report instead of the marker itself. The control request sends this, so a page that
# echoes anything the user typed cannot make the control look "already unescaped".
BENIGN: dict[str, str] = {"xss": "tirithctl", "ssti": "{{7*6}}"}
# Payloads that may be sent as a path segment when the finding has no parameter of its own.
# `'`, `{%22` and `;` are all safe in a path; a full URL is not, so SSRF never qualifies.
PATH_SAFE = frozenset({"sqli", "xss", "ssti", "cmdi", "lfi", "idor"})
PARAM_HINTS = ("id", "q", "s", "name", "p", "page", "file", "path", "url", "naam", "search", "cat", "slug")
FORM_HINT = re.compile(r"\b(POST|PUT|PATCH)\s+\S+", re.I)
GRADE_ORDER = {g: i for i, g in enumerate(GRADES)}


@dataclass
class Plan:
    weakness: str
    method: str = "GET"
    path: str = "/"
    param: str | None = None
    benign: str = ""
    payload: str = ""
    signal: str = ""
    source: str = ""  # "scanner" | "model" | "built-in"
    base: dict[str, str] = field(default_factory=dict)  # the finding's other parameters, always sent
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Evidence:
    """One exchange: the control and the probe, plus the class's verdict on both."""

    plan: Plan
    control: http.Response
    probe: http.Response
    control_hits: str
    probe_hits: str
    verdict: str  # confirmed | suspected | not_reproduced | error
    grade: str  # critical | high | suspected | ""
    confidence: float
    identity: str = ""
    cookie: str = ""

    @property
    def proved(self) -> bool:
        return self.verdict == "confirmed" and self.grade in ("critical", "high")

    def lines(self) -> list[str]:
        """Reproduction steps a reader can rerun by hand (in the requester's own shell/F12)."""
        q = "&".join(f"{k}={v}" for k, v in self.probe.query.items())
        url = f"{self.probe.path}{'?' + q if q else ''}"
        ctl_q = "&".join(f"{k}={v}" for k, v in self.control.query.items())
        ctl = f"{self.plan.path}{'?' + ctl_q if ctl_q else ''}"
        steps = [
            f"Send the control first: `{self.plan.method} {ctl}` (benign value {self.plan.benign!r}). "
            f"Observe: HTTP {self.control.status or 'no answer'}.",
            f"Send the probe: `{self.plan.method} {url}` (value {self.plan.payload!r}). "
            f"Observe: HTTP {self.probe.status or 'no answer'}.",
            f"Expect the signal `{self.plan.signal}` in the probe response and not in the control response. "
            f"Result here: {self.verdict} (grade {self.grade or '-'}).",
        ]
        if self.control_hits:
            steps.append(f"Control already shows: {self.control_hits}")
        if self.probe_hits:
            steps.append(f"Probe shows: {self.probe_hits}")
        if self.identity:
            steps.append(f"Send these as a signed-in lab user: header `X-Demo-User: {self.identity}`.")
        elif self.cookie:
            steps.append("Send these with the lab copy's logged-in session cookie.")
        return steps


def quote_light(v: str) -> str:
    return "".join(c if c.isalnum() or c in "._~-/" else f"%{ord(c):02X}" for c in v)


_CLASS_WORDS = {"SQLI": "sqli", "XSS": "xss", "SSTI": "ssti", "CMDI": "cmdi", "SSRF": "ssrf",
                "LFI": "lfi", "IDOR": "idor"}


def classify(text: str) -> str | None:
    """Weakness class of a title/evidence text. A bare class word (`sqli`, `xss`) counts too: that is
    how the analyst names a class it found itself, before any scanner wrote a CWE into a title."""
    t = (text or "").upper()
    for token in re.findall(r"\b[A-Z]{3,5}\b", t):
        if token in _CLASS_WORDS:
            return _CLASS_WORDS[token]
    for key, cls in (("CWE-89", "sqli"), ("SQL INJ", "sqli"), ("CWE-79", "xss"), ("CROSS SITE", "xss"),
                     ("CWE-94", "ssti"), ("CWE-1336", "ssti"), ("CWE-78", "cmdi"), ("COMMAND", "cmdi"),
                     ("CWE-918", "ssrf"), ("CWE-22", "lfi"), ("PATH TRAVERSAL", "lfi"), ("CWE-639", "idor"),
                     ("ACCESS CONTROL", "idor"), ("CWE-284", "idor"), ("CWE-862", "idor")):
        if key in t:
            return cls
    return None


def _param_from(url: str) -> str | None:
    q = parse_qs(urlsplit(url if "://" in url else "http://" + url).query)
    return next((k for k, v in q.items() if v and v[0] not in ("", "1")), None) or next(iter(q), None)


_REQ = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(\S+)")
EVIDENCE_URL = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+(\S+)")


def evidence_url(url: str | None, snippet: str | None = None) -> str:
    """The exact request a finding records: snippet `METHOD <url>` (ZAP) or the stored url."""
    m = EVIDENCE_URL.search(snippet or "")
    return ((m.group(1) if m else "") or (url or "")).strip()


# --------------------------------------------------------------------------- model proposals
_SPEC = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:weakness|request|method|path|param(?:eter)?|benign|control|payload|probe|"
    r"signal|expected)\s*[:=]\s*(.+?)\s*$")
def parse_spec(text: str | None) -> dict[str, str]:
    """A `weakness: … / request: METHOD /path?x=y / payload: …` block (fence and prose tolerant)."""
    out: dict[str, str] = {}
    for m in _SPEC.finditer(text or ""):
        k = "param" if m.group(0).strip().lower().startswith("param") else m.group(0).split(":", 1)[0].split("=")[0].split()[-1].lower()
        if k.startswith("control"):
            k = "benign"
        if k.startswith("probe"):
            k = "payload"
        if k.startswith("expected"):
            k = "signal"
        out[k] = m.group(1).strip().strip("`'\"")
    if "request" in out:
        r = _REQ.search(out["request"])
        if r:
            out.setdefault("method", r.group(1).upper())
            out.setdefault("path", r.group(2))
            p = _param_from(r.group(2))
            if p:
                out.setdefault("param", p)
    return out


def _model_plan(text: str, cls: str) -> Plan | None:
    """Turn a proposal into a Plan, keeping only the values that survive validation. None = unusable."""
    spec = parse_spec(text)
    if not spec:
        return None
    payload = spec.get("payload") or spec.get("payload_block") or ""
    payload = payload.strip().strip("`'\"")
    if not payload or len(payload) > 120 or any(c in payload for c in "\n\r"):
        return None
    signal = spec.get("signal") or payload
    method = (spec.get("method") or "").upper()
    path = spec.get("path") or "/"
    try:
        path = http.check_path(path)
        method = http.check_method(method, form=bool(FORM_HINT.search(text or "")))
        http.check_query({spec["param"]: "x"} if spec.get("param") else {})
    except http.RequestRefused:
        return None
    p = Plan(cls, method=method, path=path, param=spec.get("param"), benign=spec.get("benign") or "1",
             payload=payload, signal=signal[:200], source="model")
    return p


# --------------------------------------------------------------------------- projection
def plan_for(title: str, url: str | None, evidence_text: str | None = None, *,
             proposal: str | None = None) -> Plan | None:
    """Project a finding/observation onto a runnable class probe. None when no class applies."""
    text = f"{title}\n{evidence_text or ''}"
    cls = classify(text)
    if cls is None:
        return None
    model = _model_plan(proposal or "", cls) if proposal else None
    if model is not None:
        if not model.param and not model.payload:
            model.payload = PAYLOADS[cls]
        if not model.benign and cls in BENIGN:
            model.benign = BENIGN[cls]
        return model
    # An unparsable proposal must not become "no check": fall through to the scanner projection, and
    # only give up when there is no request to project onto either.
    if not url:
        return None
    param = _param_from(url)
    path = urlsplit(url if "://" in url else "http://" + url).path or "/"
    if not param and cls not in PATH_SAFE:
        return None
    benign = ""
    q = parse_qs(urlsplit(url if "://" in url else "http://" + url).query)
    if param and q.get(param):
        benign = q[param][0]
    if param and not benign and param.lower() in PARAM_HINTS:
        benign = "1"
    if not param and not path:
        return None
    # A parameter-bearing URL only exists on GET requests, whatever the snippet styling says.
    method = "GET"
    payload = PAYLOADS[cls]
    rest = {k: v[0] for k, v in q.items() if k != param and v and v[0]}
    if param and cls in BENIGN:
        benign = BENIGN[cls]  # a bare echo of any token is what a reflecting page proves nothing with
    p = Plan(cls, method=method, path=path, param=param, benign=benign or "1",
             payload=payload, signal=payload, source="scanner", base=rest)
    if param and not benign:
        p.notes.append(f"no benign value of `{param}` was recorded; the control uses `{p.benign}`")
    return p


# --------------------------------------------------------------------------- signals
def _escaped(markup: str) -> str:
    return markup.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _row_count(body: str) -> int | None:
    """A computed marker the probe can change without printing anything: digit count in the body."""
    d = sum(c.isdigit() for c in body)
    return d if d >= 2 else None


def _verified(cls: str, p: Plan, r: http.Response, payload_sent: str, *, benign: bool) -> str:
    """Text describing the class signal actually present in a response ('' when absent).

    The computed row marker is only a signal on the probe; on the control every page has digits, so
    counting there would make the control "hit" and void the contrast."""
    if not r.status:
        return ""
    b = r.body or ""
    low = b.lower()
    if cls == "sqli":
        for token in ("syntax error", "sql", "query", "sqlite", "psycopg", "mysql"):
            if token in low:
                return f"database error mentioning {token!r}"
        n = _row_count(b) if not benign else None
        if n is not None:
            return f"computed row marker {n}"
        if str(r.status).startswith("5"):
            return f"HTTP {r.status} on a database-backed input"
        return ""
    if cls == "xss":
        # An escaped copy means the marker is text in the page; an unescaped one means live markup.
        if payload_sent and payload_sent in b and _escaped(payload_sent) not in b:
            return f"marker text {payload_sent!r} echoed unescaped"
        return ""
    if cls == "ssti":
        if "49" in b and "7*7" in b:
            return "arithmetic claimed 49 and the expression was printed"
        if "49" in b:
            return "arithmetic result 49"
        return ""
    if cls == "cmdi":
        if "uid=" in b or "gid=" in b:
            return "identity output uid=/gid="
        return ""
    if cls == "ssrf":
        if "ami-" in b or "instance-id" in low:
            return "cloud metadata (ami-/instance-id) returned"
        return ""
    if cls == "lfi":
        if "root:x:0" in b or "daemon:" in b or "/bin/" in b:
            return "passwd-style content returned"
        return ""
    if cls == "idor":
        if r.status == 200 and b.strip():
            return f"HTTP {r.status} with a different body"
        return ""
    return ""


def _executor(ref: LabRef | None) -> str:
    """Where the client runs: the copy's own container, or "" for this guest (native copy, live)."""
    if ref is None:
        return ""
    from ..analystlab import live as livemod

    return livemod.container_of(ref)


async def resolve_async(target: LabRef | str, *, live: bool = False) -> LabRef | None:
    """`resolve`, off the loop when a live check has to happen (it connects)."""
    return await asyncio.to_thread(resolve, target, live=live)


def resolve(target: LabRef | str, *, live: bool = False) -> LabRef | None:
    """A handle as-is, the live service for a URL (`live=True`), or the first running lab copy for it.

    With `live`, a reachability failure is not "no handle": it raises `http.RequestRefused` so the caller can
    fall back to the copy and say why.

    An address that is never a lab copy (`live.always_served`: the guest loopback, a LAN box) resolves live
    either way -- returning None there only ever means "no Dockerfile", which is wrong for a running service."""
    if isinstance(target, LabRef):
        return target
    from ..analystlab import lab as app_lab
    from ..analystlab import live as livemod

    if live or livemod.always_served(target):
        return livemod.live_ref(target)
    refs = app_lab.known_handles_for(target)
    return refs[0] if refs else None


def run_ok(p: Plan, *, identity: str | None = None, cookie: str = "") -> Evidence:
    """Run without a container: the caller has mocked `http.request` (`ref` is not verified)."""
    return _probe(None, p, identity=identity, cookie=cookie)


def run(target: LabRef | str, p: Plan, *, identity: str | None = None, cookie: str = "",
        live: bool = False) -> Evidence:
    """`target` is a LabRef or a URL of a running lab copy (or of the live service with `live=True`)."""
    ref = resolve(target, live=live)
    return _probe(ref, p, identity=identity, cookie=cookie)


def _probe(ref: LabRef | None, p: Plan, *, identity: str | None = None, cookie: str = "") -> Evidence:
    """Send the control and the probe, one parameter varied, same method/path. Never raises.

    `identity` is the demo `X-Demo-User` (structural, header-only servers); `cookie` an already
    logged-in lab session. Both are sent on every request so the pair is a like-for-like comparison."""
    base = dict(p.base)
    who = identity or ""
    executor = _executor(ref)

    def send(value: str | None) -> http.Response:
        q = dict(base)
        if p.param and value is not None:
            q[p.param] = value
        hdr: dict[str, str] = {}
        if who:
            hdr["x-demo-user"] = who
        if cookie:
            hdr["cookie"] = cookie
        return http.request(ref, p.method, p.path, query=q, headers=hdr, executor=executor,
                            label=f"probe {p.weakness} ({p.source})")

    def ev(*args, **kw) -> Evidence:
        e = Evidence(*args, **kw)
        e.identity, e.cookie = who, cookie
        return e

    try:
        control = send(p.benign)
    except http.RequestRefused as e:
        return ev(p, http.Response(p.method, p.path, {}, 0, {}, "", 0, error=str(e)),
                  http.Response(p.method, p.path, {}, 0, {}, "", 0, error=str(e)), "", "", "error", "", 0.0)
    probe_value = p.payload
    if p.weakness == "idor" and not p.payload:
        probe_value = str(_bump(p.benign))
        p.payload = probe_value
        p.signal = p.signal or f"a different resource than {p.benign}"
    try:
        probe = send(probe_value)
    except http.RequestRefused as e:
        return ev(p, control, http.Response(p.method, p.path, {}, 0, {}, "", 0, error=str(e)), "", "", "error", "", 0.0)
    if not control.status or control.status >= 500:
        return ev(p, control, probe, "", "", "error", "", 0.0)
    c_hit = _verified(p.weakness, p, control, p.benign, benign=True)
    p_hit = _verified(p.weakness, p, probe, probe_value, benign=False)
    if c_hit and not p_hit:
        return ev(p, control, probe, c_hit, "", "not_reproduced", "", 0.3)
    if not p_hit:
        return ev(p, control, probe, c_hit, "", "not_reproduced", "", 0.0)
    if c_hit:
        # Both show it: only a changed body for this one parameter says the input is the cause.
        if probe.body.strip() != control.body.strip():
            return ev(p, control, probe, c_hit, p_hit, "suspected", "suspected", 0.5)
        return ev(p, control, probe, c_hit, p_hit, "not_reproduced", "", 0.2)
    grade = _grade(p.weakness, p, probe)
    return ev(p, control, probe, "", p_hit, "confirmed", grade, 0.85 if grade == "critical" else 0.7)


def _grade(cls: str, p: Plan, r: http.Response) -> str:
    """critical = the response proves real access; high = strong signal; suspected = echo only."""
    b = r.body or ""
    if cls == "sqli":
        low = b.lower()
        if any(t in low for t in ("syntax error", "sqlite", "psycopg", "mysql")) or r.status >= 500:
            return "critical"
        if "sql" in low:
            return "high"
        return "suspected"
    if cls == "ssti":
        return "critical" if "49" in b else "suspected"
    if cls == "cmdi":
        return "critical" if ("uid=" in b or "gid=" in b) else "suspected"
    if cls == "lfi":
        return "critical" if "root:x:0" in b else "suspected"
    if cls == "ssrf":
        return "critical" if ("ami-" in b or "instance-id" in b.lower()) else "suspected"
    if cls == "idor":
        return "high"
    if cls == "xss":
        return "high" if "unescaped" in _verified(cls, p, r, p.payload, benign=False) else "suspected"
    return "suspected"


def _bump(value: str) -> int | str:
    try:
        return str(int(value) + 1)
    except (TypeError, ValueError):
        return f"{value}1" if value else "1"


def env_details(target: LabRef | str) -> dict[str, str]:
    """How to reach one lab copy with the app's own identity: cookie for cookie servers, a constant
    `X-Demo-User` for header servers, nothing when the app has no login at all."""
    ref = resolve(target)
    if ref is None:
        return {}
    from ..analystlab import lab as labapp

    jar = labmod.session_of(ref)
    if jar:
        return {"cookie": "; ".join(f"{k}={v}" for k, v in jar.items())}
    handles = labapp.known_handles()
    return {"identity": labapp.MODEL_IDENTITY} if ref.handle in handles else {}


__all__ = ["CLASSES", "GRADES", "Evidence", "Plan", "classify", "env_details", "evidence_url", "plan_for",
           "parse_spec", "resolve", "run"]
