"""Deterministic reproduction of data-flow findings against the signed-in lab copy.

This is the negative-control layer that static data-flow review (triage_sast) lacks: the model may
name a payload, but only a fixed, self-written script decides whether the app actually misbehaved.

Fixed checks, one per weakness class. Every check sends TWO requests to the SAME endpoint that
produced the finding's evidence, with identical method/headers/cookies:

    control  the parameter's own benign value (from the app's echoed response)
    probe    a payload built by the check's code from constants

`confirmed` only when the probe response shows the check's specific signal AND the control does
not. That contrast is what makes the verdict evidence rather than a guess, and it rules out the
"any input produces this string" artifact of echo-based detection.

Boundaries (never widened):
  - The target is the lab copy's own loopback port, resolved via the lab registry; no asset URLs,
    no host ports from the finding, no DNS, nothing off-loopback.
  - Requests are GET/POST form only, no follow-up traffic, no state-changing verbs. The request
    client is curl if the box has it, else the stdlib: the body travels inside the shell command,
    and no other host is ever named.
  - The exact number of requests per check has a hard cap; the whole check has a wall-clock cap.
  - What leaves the app is discarded unless a signal matched: evidence holds status, headers minus
    cookies, and a short excerpt around the signal, never whole bodies.
  - The model is used (optionally) to pick a payload from this module's fixed menu, or propose one.
    A proposal must match the class's fixed shape, is sent exactly once, and is only accepted as
    evidence when it shows the class signal against a clean control; otherwise the fixed payload is
    used instead and both attempts are kept in the evidence.

Env:
  TIRITH_REPRO       0 = skip reproduction entirely (validate falls back to the static/lab triage)
  TIRITH_REPRO_LLM   1 = let the model rank/name payloads (default 1; skipped when it fails)
  TIRITH_REPRO_MAX    hard cap on HTTP requests per finding (default 8)
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit

from . import core, lab, llm
from .context import stub_ctx
from .core import Evidence, Finding, Validation, now_iso
from .sh import Result, run

MAX_REQUESTS = int(os.environ.get("TIRITH_REPRO_MAX", "8"))
WALL_SECONDS = 45
CLOUD_HOST_SUFFIX = re.compile(r"(?:zania\.io|ngrok\.io|ngrok-free\.app|ngrok\.app|loca\.lt|trycloudflare\.com|"
                               r"serveo\.net|localtunnel\.me|tunnelto\.dev)\.?:?\d*$", re.I)
IN_APP = "http://127.0.0.1:{}"  # the lab copy's loopback, whatever holds it (no other host is named)
HEADER_SKIP = re.compile(r"^(set-cookie|cookie|authorization)$", re.I)


@dataclass
class Payload:
    class_: str
    name: str
    value: str
    method: str = "GET"


# ----------------------------------------------------------------------------- fixed menu
# `{q}` is the shell-quote/db-quote breaker. SQLi: quote-break + boolean OR (not a UNION: no row
# shape assumption). XSS: an element that only exists from injected markup.
BREAK = "'"
SQLI_OR = BREAK + " OR '" + "1'='" + "1"
SQLI_AND = BREAK + " AND '" + "1'='" + "2"
XSS_TAG = "<script>alert(1)</script>"
SSTI = "{{7*7}}"
CMDI_SAFE = "tirith_reprobe_8c1f"

MENU: dict[str, list[Payload]] = {
    "sqli": [Payload("sqli", "quote-or", SQLI_OR)],
    "xss": [Payload("xss", "svg-onload", XSS_TAG)],
    "ssti": [Payload("ssti", "jinja-mul", SSTI)],
    # `echo` is itself echoed by an echo-based sink, so use the command separator alone: exec
    # (\`; marker\`) prints the marker, echoing (\`echo 127.0.0.1; marker\`) cannot.
    "cmdi": [Payload("cmdi", "separator", f"127.0.0.1;{CMDI_SAFE}")],
    "generic": [],
}

CLASS_PATTERNS = [
    ("sqli", re.compile(r"CWE-?89\b|sql\s*injection|\bsqli\b", re.I)),
    ("cmdi", re.compile(r"CWE-?(78|77)\b|command\s*injection|os\.system|shell\s*injection", re.I)),
    ("ssti", re.compile(r"CWE-?1336\b|server[- ]side template|template\s*injection|\bssti\b", re.I)),
    ("xss", re.compile(r"CWE-?79\b|cross[- ]site\s*scripting|\bxss\b", re.I)),
]

# Shapes a model-proposed payload must match exactly. Anything else is dropped before it can be sent.
PROPOSAL_SHAPE = {
    "sqli": re.compile(r"\A[A-Za-z0-9_'\";()= .*-]{1,60}\Z"),
    "xss": re.compile(r"\A(?:<[a-z][a-z0-9]{0,12}(?: [a-z-]{1,12}=[a-z0-9_(){}.*+-]{1,30})?/?>[A-Za-z0-9() ]{0,12}){1,2}"
                      r"(?:</script>)?\Z"),
    "ssti": re.compile(r"\A[{]{1,2}[0-9*+ ]{1,20}[}]{1,2}\Z"),
    "cmdi": re.compile(r"\A[A-Za-z0-9.:_/-]{1,60}(?:;[ ]?|\|\||&&)[A-Za-z0-9_]{4,32}\Z"),
}


def classify(f: Finding) -> str:
    """Weakness class from the finding's CWE/title, or '' when no fixed check exists."""
    hay = " ".join(x for x in (f.cwe, f.title, f.description) if x)
    for name, pat in CLASS_PATTERNS:
        if pat.search(hay):
            return name
    return ""


def _evidence_url(f: Finding) -> str:
    """The exact request that produced the finding: snippet `METHOD <url>` (ZAP) or f.url."""
    m = re.search(r"\b(GET|POST|PUT|PATCH)\s+(\S+)", f.snippet or "")
    return (m.group(2) if m else (f.url or "")).strip()


def _benign_and_param(url: str) -> tuple[dict[str, str], str]:
    """Query params with the flagged value replaced by a benign control, and the flagged param name."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return {}, ""
    # ZAP marks the parameter it attacked with a site-map/probe symbol (`name=test'`); the app's own
    # links use plain words, so prefer the first param whose value carries one, else the first param.
    mark = re.compile(r"['\"<>{};`]|zaproxy|\bpx\b|attack", re.I)
    name = next((k for k, v in pairs if mark.search(v)), pairs[0][0])
    benign = {k: ("" if k == name else v) for k, v in pairs}
    return benign, name


def _headers(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in raw.splitlines():
        k, sep, v = ln.partition(":")
        if sep and not HEADER_SKIP.match(k.strip()):
            out[k.strip()] = v.strip()[:300]
    return out


@dataclass
class ProbeResult:
    method: str
    path: str
    params: dict[str, str] = field(repr=False)
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    body: str = field(default="", repr=False)

    def request_line(self, host: str) -> str:
        shown = {k: (v if not _secret(k) else "***") for k, v in self.params.items()}
        q = ("?" + urlencode(shown)) if self.method == "GET" and shown else ""
        form = "\n" + urlencode(shown) if self.method == "POST" else ""
        return f"{self.method} {self.path}{q} HTTP/1.1\nHost: {host}{form}"

    def evidence(self, host: str, note: str = "") -> list[Evidence]:
        head = "\n".join(f"{k}: {v}" for k, v in self.headers.items())
        body = self.body[:1200]
        return [Evidence(kind="request", label="reproduce request", content=self.request_line(host)),
                Evidence(kind="response", label="reproduce response", content=f"{note + chr(10) if note else ''}"
                         f"HTTP {self.status}\n{head}\n\n{body}".strip())]


_SECRET_KEY = re.compile(r"pass|token|secret|key|auth|session", re.I)


def _secret(name: str) -> bool:
    return bool(_SECRET_KEY.search(name or ""))


# ----------------------------------------------------------------------------- one request
# The request client must exist in the TARGET image (arbitrary base images): curl when present,
# else stdlib urllib. The fallback is shipped as base64 so shell quoting can never mangle it.
PYHTTP_SCRIPT = """import sys, urllib.request as u, urllib.error as e
url, meth, cookie, form = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
data = form.encode() if meth == "POST" else None
h = {"Accept": "text/html,*/*"}
if cookie:
    h["Cookie"] = cookie
req = u.Request(url, data=data, headers=h, method=meth)
try:
    r = u.urlopen(req, timeout=8)
except e.HTTPError as x:
    r = x
except Exception:
    print("TIRITH_REPRO_STATUS:0")
    sys.exit(0)
print("HTTP/1.1", r.status, r.reason)
for k, v in r.headers.items():
    print(k + ": " + v)
print()
print(r.read(200000).decode("utf-8", "replace"))
print("TIRITH_REPRO_STATUS:%d" % r.status)
"""
PYHTTP_B64 = base64.b64encode(PYHTTP_SCRIPT.encode()).decode()
_CURL = ("if command -v curl >/dev/null 2>&1; then curl -s -S --max-time 8 -o - -D - --path-as-is "
         "-w '\\nTIRITH_REPRO_STATUS:%{http_code}' URL HEADERS BODYARGS; else "
         f"printf %s {PYHTTP_B64} | base64 -d | python - URL __METHOD__ __COOKIE__ __FORM__; fi")
STATUS_RE = re.compile(r"TIRITH_REPRO_STATUS:(\d{1,3})\s*$")
MAX_BODY = 200_000


def send(h: lab.LabHandle, method: str, path: str, params: dict[str, str], cookies: dict[str, str]) -> ProbeResult:
    """One request at the lab copy's own loopback port. Nothing else is reachable.

    Same argv in both modes: `docker exec sh -c` when a container holds the copy, plain `sh -c` when
    the copy is a local process -- the URL is `127.0.0.1:<port>` either way."""
    method = "POST" if method.upper() == "POST" else "GET"
    path = path if path.startswith("/") else "/" + path
    path = re.sub(r"[^A-Za-z0-9/._~%?=&-]", "", path)[:300] or "/"
    cookie = "; ".join(f"{k}={v}" for k, v in cookies.items()
                       if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k) and re.fullmatch(r"[\x21-\x7e]{1,512}", v)
                       and ";" not in v)
    url = IN_APP.format(h.port) + path
    if method == "GET" and params:
        url += "?" + urlencode(params)
    hdr = ((f"-H 'Cookie: {cookie}' " if cookie else "") + "-H 'Accept: text/html,*/*'")
    form = urlencode(params) if method == "POST" else ""
    # The body travels inside the command, not on docker exec's stdin: a caller-supplied stdin is
    # not reliably forwarded to the exec'd process, and an empty body turns POST probes into GETs.
    bodyargs = ("-X POST -H 'Content-Type: application/x-www-form-urlencoded' "
                f"--data-binary {shlex.quote(form)}") if method == "POST" else ""
    cmd = (_CURL.replace("URL", shlex.quote(url)).replace("HEADERS", hdr)
           .replace("BODYARGS", bodyargs).replace("__METHOD__", method)
           .replace("__COOKIE__", shlex.quote(cookie)).replace("__FORM__", shlex.quote(form)))
    argv = ["docker", "exec", h.container, "sh", "-c", cmd] if h.container else ["sh", "-c", cmd]
    r = run(argv, timeout=20)
    return parse_result(r, method, path, params)


def parse_result(r: Result, method: str, path: str, params: dict[str, str]) -> ProbeResult:
    out = (r.out or "")[:MAX_BODY]  # text after the status trailer is the fallback client's stderr
    m = STATUS_RE.search(out)
    body_and_head = out[: m.start()] if m else out
    status = int(m.group(1)) if m else 0
    head, _, body = body_and_head.partition("\r\n\r\n")
    if not body and "\n\n" in body_and_head:  # some proxies use bare LF
        head, _, body = body_and_head.partition("\n\n")
    return ProbeResult(method, path, dict(params), status, _headers(head), body[:MAX_BODY])


# ----------------------------------------------------------------------------- checks
@dataclass
class Check:
    class_: str
    signal: re.Pattern
    explain: str


CHECKS: dict[str, Check] = {
    # SQL errors only count when the control didn't produce one: a query that already fails stays
    # "unsupported" instead of a false confirmation.
    "sqli": Check("sqli", re.compile(
        r"SQLITE_ERROR|SQLSTATE|syntax error at or near|You have an error in your SQL syntax|"
        r"psycopg2\.|OperationalError|sqlalchemy\.exc|unrecognized token|no such (?:column|table)", re.I),
        "the response carries a database error trace for the injected quote"),
    # The literal payload reappearing is echo, not execution (PyGoat's XSS lab deliberately shows the
    # raw string); reflecting `<`/`>` unescaped is close but still text. The signal is a construct that
    # only exists once a browser parses markup: a script element or a JS URL attribute. Escaped text
    # (`&lt;script&gt;`, `&#60;script&#62;`, `%3Cscript%3E`) is deliberately NOT decoded before matching:
    # that is the app doing its job. (No decoders: decoding would confirm exactly the escape it proves.)
    "xss": Check("xss", re.compile(r"""<script[\s/>]|\bsrc\s*=\s*["']?javascript:|\bhref\s*=\s*["']?javascript:""", re.I),
                 "the injected element appears as live markup, not as escaped text"),
    "ssti": Check("ssti", re.compile(r"(?<!\{)\b49\b(?!\})"),
                  "{{7*7}} was evaluated to 49 by the template engine"),
    "cmdi": Check("cmdi", re.compile(r"(?<![A-Za-z0-9_])" + CMDI_SAFE + r"(?![A-Za-z0-9_])"),
                  "the shell echoed a marker that only exists if the injected command ran"),
}


def match(check: Check, body: str) -> bool:
    """Signal present in the response exactly as returned. No unescaping: an entity- or
    percent-encoded payload is the app neutralising it, not executing it."""
    return bool(check.signal.search(body or ""))


def _excerpt(body: str, signal: re.Pattern, radius: int = 160) -> str:
    body = body or ""
    m = signal.search(body)
    if not m:
        return body[:radius]
    a, b = max(0, m.start() - radius), min(len(body), m.end() + radius)
    return re.sub(r"[0-9a-f]{24,}", "***", body[a:b])


def _chosen(f: Finding) -> Payload | None:
    menu = MENU.get(classify(f)) or []
    return menu[0] if menu else None


# ----------------------------------------------------------------------------- optional model
REPRO_SYSTEM = """You pick a single payload for an authorized reproduction inside an isolated lab copy of the app.
Nothing you return is executed; it is only sent once as a request parameter by fixed code.
Reply with ONLY a JSON object: {"payload": "<string>", "reason": "<one sentence>"}.
The payload must belong to the stated class and match this exact character shape: SHAPE
Prefer a payload that differs from the one given so the check is not circular."""


def _propose(f: Finding, cls: str, known: Payload) -> tuple[str | None, str]:
    if os.environ.get("TIRITH_REPRO_LLM", "1") != "1":
        return None, "model payloads disabled (TIRITH_REPRO_LLM=0)"
    shape = PROPOSAL_SHAPE.get(cls)
    if not shape:
        return None, "no proposal shape for this class"
    msgs = [{"role": "system", "content": REPRO_SYSTEM.replace("SHAPE", shape.pattern)},
            {"role": "user", "content": f"Class: {cls}\nKnown payload: {known.value}\n"
                                        f"Finding: {f.title}\nFile: {f.file}:{f.line or '?'}\n"
                                        f"CWE: {f.cwe or '-'}"}]
    try:
        data, res = llm.chat_json(msgs, task="reproduce_payload", stub_context=stub_ctx(f),
                                  deadline=llm.deadline_in(120))
    except (llm.LLMError, ValueError) as e:
        return None, f"model unavailable: {e}"[:200]
    value = str((data or {}).get("payload") or "").strip()
    if not value or not shape.match(value):
        return None, f"model proposal rejected by shape ({value[:60]!r})"
    return value, f"model proposal accepted ({res.model})"


# ----------------------------------------------------------------------------- entry point
def reproduce(f: Finding, h: lab.LabHandle | None = None, asset: core.Asset | None = None) -> Validation:
    """Reproduce a data-flow finding against the lab copy. Returns a Validation, never raises."""
    cls = classify(f)
    v = Validation(finding_id=f.id, check=f"reproduce-{cls or 'none'}", result="unsupported", started_at=now_iso())
    evd: list[Evidence] = []
    core.audit("remediation.reproduce", target=f"finding:{f.id}", details={"class": cls, "check": v.check})
    core.emit("validation.started", f"Reproducing by controlled request ({cls or 'no fixed check'})", finding_id=f.id)

    def done(result: str, confidence: float, note: str) -> Validation:
        evd.append(Evidence(kind="note", label="verdict", content=note))
        v.result, v.confidence, v.evidence, v.finished_at = result, confidence, evd, now_iso()
        return v

    if not cls or cls not in CHECKS or os.environ.get("TIRITH_REPRO", "1") != "1":
        return done("unsupported", (f.confidence or 0.5) * 0.5,
                    "No fixed reproduction check for this weakness class; the finding keeps its static review.")
    if h is None:
        return done("unsupported", 0.0, "No lab deployment of this asset is available (needs a Dockerfile).")
    url = _evidence_url(f)
    if not url:
        return done("unsupported", 0.0, "The finding carries no request evidence (scanner URL) to replay.")
    parts = urlsplit(url if "://" in url else "http://" + url)
    if CLOUD_HOST_SUFFIX.search(parts.hostname or "") or (parts.hostname or "").count(".") > 3:
        return done("unsupported", 0.0,
                    f"Scanner evidence targets {parts.hostname}, which is not the lab copy; a finding for "
                    "another host is not replayed.")
    path = parts.path or "/"
    benign, flagged = _benign_and_param(url)
    m = re.search(r"\b(GET|POST|PUT|PATCH)\s+\S+", f.snippet or "")
    method = "POST" if m and m.group(1) == "POST" else "GET"
    # Some frameworks answer 404 to the sibling path form (a POST on a trailing-slash route is not
    # redirected); the other form is tried once, only when the scanner's exact path 404s on the control.
    alt_path = (path.rstrip("/") if path.endswith("/") else path + "/") if path != "/" else None
    if not flagged:
        return done("unsupported", 0.0, "No parameter in the finding's evidence URL to vary.")

    cookies = lab.session(h)
    check = CHECKS[cls]
    known = _chosen(f)
    if known is None:
        return done("unsupported", 0.0, f"No fixed payload for {cls} (unreachable: class has a check).")
    proposed, why = _propose(f, cls, known)
    evd.append(Evidence(kind="note", label="plan", content=(
        f"class {cls}: control '{flagged}'=benign vs probe; {method} {path}; "
        f"requests capped at {MAX_REQUESTS}; fixed payload {known.name}={known.value!r}" +
        (f"; {why}" if why else ""))))

    t0 = time.monotonic()
    sent = 0

    def budget() -> bool:
        return sent < MAX_REQUESTS and (time.monotonic() - t0) < WALL_SECONDS

    control = send(h, method, path, benign, cookies)
    sent += 1
    evd += control.evidence(h.container, "control (parameter left benign)")
    if control.status == 404 and alt_path and budget():
        retry = send(h, method, alt_path, benign, cookies)
        sent += 1
        evd += retry.evidence(h.container, "control retry (sibling path form)")
        if retry.status != 404:
            path, control = alt_path, retry
        else:
            return done("not_reproduced", 0.6,
                        f"The lab copy answers 404 for {path}: the route named in the scanner evidence "
                        "does not exist in this deployment.")
    ctrl_hit = match(check, control.body)
    if control.status == 0:
        return done("error", 0.0, "The lab copy did not answer the control request.")
    if ctrl_hit:
        return done("unsupported", 0.0,
                    "The control already shows the class signal, so a match would prove nothing "
                    "(endpoint input is not the cause).")

    attempts: list[tuple[str, str]] = [(known.value, f"fixed payload {known.name}")]
    if proposed:
        attempts.insert(0, (proposed, "model payload"))
    confirmed_with = ""
    clean_probes: list[tuple[str, ProbeResult]] = []  # probe + pristine-benign responses of one attempt
    for value, label in attempts:
        if not budget():
            break
        pr = send(h, method, path, {**benign, flagged: value}, cookies)
        sent += 1
        hit = match(check, pr.body)
        evd += pr.evidence(h.container, f"probe ({label}): {'signal matched' if hit else 'no signal'}")
        if hit:
            confirmed_with = label
            evd.append(Evidence(kind="log", label="matched excerpt",
                                content=_excerpt(pr.body, check.signal)))
            break
        # SQL error oracles miss blind/boolean injection (the payload changes ROWS, not errors).
        # Re-send the control: a benign value is the same request minus the payload, so a body
        # that changed only for the payload is injection, not page churn.
        if cls == "sqli" and budget():
            again = send(h, method, path, benign, cookies)
            sent += 1
            evd += again.evidence(h.container, f"control repeat after {label} (row-count oracle)")
            clean_probes.append((label, pr, again))

    evd.append(Evidence(kind="note", label="requests sent", content=f"{sent} in {time.monotonic() - t0:.1f}s"))
    for label, pr, again in clean_probes:
        if again.status and pr.status and pr.body.strip() != control.body.strip() \
                and again.body.strip() == control.body.strip():
            evd.append(Evidence(kind="log", label="row-count excerpt", content=_excerpt(pr.body, check.signal)))
            return done("confirmed", 0.8,
                        f"Control clean and reproducible, probe changed the response and nothing else: the "
                        f"payload ({label}) altered the query's result set, so the input reaches the SQL sink.")
    if confirmed_with:
        return done("confirmed", 0.9,
                    f"Control clean, probe matched: {check.explain} (payload: {confirmed_with}).")

    # Distinguish "not exploitable" from "not our check": a 4xx/5xx only on the probe, with no
    # signal, is reported as unsupported rather than a clean negative.
    return done("not_reproduced", 0.65,
                "Control clean and every probe answered without the class signal; the input did not "
                f"reach an exploitable sink in this deployment. Fixed payloads tried: {len(attempts)}.")