"""The analyst's tool surface: named, schema-validated functions over Tirith's existing machinery.

Nothing here is new capability — every tool delegates to a component that already enforces scope,
writes to the audit log and records evidence:

    discover  -> app.scanners.discovery          (read-only port/service probe on a host asset)
    scan      -> app.scanners.runner             (semgrep/gitleaks/trivy/zap on an asset)
    findings  -> store                           (read what the scans found)
    validate  -> app.remediation.triage          (evidence-based validation)
    reproduce -> app.remediation.reproduce       (controlled replay, negative control)
    http      -> app.analystlab.http             (ONE raw request inside the isolated lab)
    probe     -> app.analyst.probe               (severity-graded projection probe, control + probe)
    evidence  -> app.evidence.screenshots        (screenshot a URL target)
    fix       -> app.remediation.fix             (patch -> PR -> verify; observe mode refuses, apply opts in)
    mode      -> app.routes_core._apply_mode     (observe | assisted | autonomous; audited as api)
    asset     -> store / scope                   (register an asset the owner already scoped)

The model chooses tool + args; this module validates the argument schema (unknown args are rejected
rather than ignored) and returns a compact JSON observation. It never accepts a command string.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .. import posture
from . import probe
from ..audit import audit
from ..models import OPEN_STATUSES, Asset, Scan, severity_counts
from ..scope import enforce
from ..store import get_store


class ToolError(RuntimeError):
    """A refusal or bad argument the model should see as an observation."""


@dataclass
class Tool:
    name: str
    summary: str
    args: dict[str, str]  # name -> "str|int|list[str]" (+ "?" when optional)
    run: Callable[[dict[str, Any]], Awaitable[Any]]


def _check_args(tool: Tool, args: dict[str, Any]) -> dict[str, Any]:
    unknown = set(args) - set(tool.args)
    if unknown:
        raise ToolError(f"unknown argument(s) {sorted(unknown)} for {tool.name}; allowed: {sorted(tool.args)}")
    out: dict[str, Any] = {}
    for name, spec in tool.args.items():
        optional = spec.endswith("?")
        typ = spec.rstrip("?")
        if name not in args or args[name] in (None, "", []):
            if optional:
                continue
            raise ToolError(f"missing required argument {name!r} for {tool.name}")
        val = args[name]
        if typ == "int":
            if isinstance(val, bool) or not isinstance(val, (int, str)) or not str(val).isdigit():
                raise ToolError(f"{name} must be an integer")
            out[name] = int(val)
        elif typ == "bool":
            if isinstance(val, bool):
                out[name] = val
            elif str(val).strip().lower() in ("true", "yes", "1", "false", "no", "0"):
                out[name] = str(val).strip().lower() in ("true", "yes", "1")
            else:
                raise ToolError(f"{name} must be a boolean")
        elif typ == "dict[str,str]":
            if not isinstance(val, dict) or not all(isinstance(x, str) for x in val.values()):
                raise ToolError(f"{name} must be an object of name -> string")
            out[name] = val
        elif typ == "list[str]":
            if isinstance(val, str):
                out[name] = [val]
            elif isinstance(val, list) and all(isinstance(x, str) for x in val):
                out[name] = val
            else:
                raise ToolError(f"{name} must be a list of strings")
        else:
            if not isinstance(val, str):
                raise ToolError(f"{name} must be a string")
            out[name] = val
    return out


class AnalystTools:
    """One instance per run: remembers which assets exist so the model can refer to them by name."""

    def __init__(self, *, mode: str | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for t in (_discover(), _asset(), _scan(), _findings(), _validate(), _reproduce(), _http(), _probe(),
                  _evidence(), _fix(), _mode(self), _posture()):
            self._tools[t.name] = t
        self.mode = mode

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> str:
        lines = []
        for name in self.names():
            t = self._tools[name]
            args = ", ".join(f"{k}: {v}" for k, v in t.args.items()) or "none"
            lines.append(f"- {name}({args}) — {t.summary}")
        return "\n".join(lines)

    async def call(self, name: str, args: dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError(f"unknown tool {name!r}")
        clean = _check_args(tool, args or {})
        audit("analyst.tool", target=name, details={"args": clean})
        return await tool.run(clean)


# ----------------------------------------------------------------------------- helpers
async def _wait_scan(scan_id: str, *, timeout: int = 240, interval: float = 1.0) -> None:
    """Poll until the scan leaves queued/running, or the timeout passes (the scan keeps running)."""
    st = get_store()
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        scan = st.get_scan(scan_id)
        if scan is None or scan.status not in ("queued", "running"):
            return
        await asyncio.sleep(interval)

def _asset_by(kind: str | None, ref: str | None = None, asset_id: str | None = None, name: str | None = None) -> Asset:
    st = get_store()
    if asset_id:
        a = st.get_asset(asset_id)
        if a is None:
            raise ToolError(f"no asset {asset_id}")
        return a
    for cand in (ref, name):
        if not cand:
            continue
        if kind:
            a = st.find_asset(kind, cand)
            if a:
                return a
        for a in st.list_assets():
            if cand in (a.name, a.ref, a.id):
                return a
    raise ToolError(f"asset not found (kind={kind!r} ref={ref!r} name={name!r}); call asset to register one first")


def _none_reason(url: str) -> str:
    """Why `resolve(url)` had no handle: never ran, never verified, or simply not asked to go live."""
    from ..analystlab import lab as app_lab
    from ..analystlab import live as livemod

    if not livemod.always_served(url):
        return (f"no lab copy serves {url}: nothing is running on that address. Pass `live: true` for one "
                f"request at the URL itself")
    known = app_lab.known_handles_for(url)
    if not known:
        return (f"no lab copy for {url} was ever booted, and the service is not verified as live. Re-run "
                f"`scan` first, or pass `live: true`")
    return (f"the lab copy of {url} is stopped (or was never booted in this run). Pass `live: true` to send "
            f"the request at the live service instead")


def _finding(finding_id: str):
    f = get_store().get_finding(finding_id)
    if f is None:
        raise ToolError(f"no finding {finding_id}")
    return f


def _summary(f) -> dict:
    return {"id": f.id, "asset_id": f.asset_id, "title": f.title, "severity": f.severity, "status": f.status, "tool": f.tool,
            "component": f.component, "cwe": f.cwe, "url": f.url, "file": f.file, "line": f.line,
            "priority": round(f.priority, 1)}


# ----------------------------------------------------------------------------- tools
def _discover() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..scanners import discovery

        asset = _asset_by("host", a.get("host"))
        d = await discovery.discover(asset)
        return {"host": d.host, "open_ports": [s.port for s in d.open],
                "services": [s.to_dict() for s in d.open],
                "urls": [u for s in d.open if (u := discovery.url_for(d.host, s))]}

    return Tool("discover", "Read-only port/service discovery on a host asset (allow-listed ports only)",
                {"host": "str"}, run)


def _asset() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        kind, ref = a["kind"], a["ref"].strip()
        ok, reason = enforce("asset.create", kind, ref, actor="analyst")
        if not ok:
            raise ToolError(f"out of scope: {reason}")
        st = get_store()
        existing = st.find_asset(kind, ref)
        if existing:
            return {"id": existing.id, "name": existing.name, "kind": existing.kind, "ref": existing.ref, "new": False}
        created = st.save_asset(Asset(kind=kind, ref=ref, name=a.get("name") or ref.rsplit("/", 1)[-1]))
        return {"id": created.id, "name": created.name, "kind": created.kind, "ref": created.ref, "new": True}

    return Tool("asset", "Register an in-scope asset (host | url | local_path | github_repo)",
                {"kind": "str", "ref": "str", "name": "str?"}, run)


def _scan() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..scanners import runner

        asset = _asset_by(a.get("kind"), a.get("ref"), name=a.get("name"))
        if asset.kind == "host":
            return await _scan_host(asset, a.get("tools"))
        ok, reason = enforce("scan.run", asset.kind, asset.ref, actor="analyst")
        if not ok:
            raise ToolError(f"out of scope: {reason}")
        st = get_store()
        scan = Scan(asset_id=asset.id, tools=runner.plan_tools(asset, a.get("tools")))
        st.save_scan(scan)
        runner.start_scan(scan)
        # Scans are async; wait for this one (bounded) so the model sees results, not "still running".
        await _wait_scan(scan.id, timeout=int(a.get("wait_s") or 240))
        done = st.get_scan(scan.id)
        return {"scan_id": scan.id, "status": done.status if done else "unknown",
                "tools": done.tools if done else {}, "counts": done.counts if done else {},
                "error": done.error if done else None}

    return Tool("scan", "Run scanners on an asset (code: semgrep/gitleaks/trivy; URL: zap). Waits for completion",
                {"kind": "str?", "ref": "str?", "name": "str?", "tools": "list[str]?", "wait_s": "int?"}, run)


async def _scan_host(host_asset: Asset, tools: list[str] | None) -> Any:
    """A host has no scannable payload of its own: discover its web services, then ZAP each in-scope one.

    Hosts whose only open port is not a web service (SSH, a database) produce no scan target — that
    is reported plainly rather than pretending a scan happened."""
    from ..scanners import discovery, runner

    d = await discovery.discover(host_asset)
    urls: list[str] = []
    skipped: list[str] = []
    for svc in d.open:
        u = discovery.url_for(d.host, svc)
        if not u:
            continue
        ok, reason = enforce("scan.run", "url", u, actor="analyst")
        (urls if ok else skipped).append(u if ok else f"{u} ({reason})")
    scans = []
    for u in urls:
        st = get_store()
        target = st.find_asset("url", u) or st.save_asset(Asset(kind="url", ref=u, name=u))
        scan = Scan(asset_id=target.id, tools=runner.plan_tools(target, tools or ["zap"]))
        st.save_scan(scan)
        runner.start_scan(scan)
        await _wait_scan(scan.id, timeout=180)
        done = st.get_scan(scan.id)
        scans.append({"url": u, "scan_id": scan.id, "status": done.status if done else "unknown",
                      "counts": done.counts if done else {}, "error": done.error if done else None})
    return {"host": d.host, "open_ports": [s.port for s in d.open], "scanned": scans,
            "not_scannable": [f"{s.port} ({s.scheme or 'no http'})" for s in d.open if not discovery.url_for(d.host, s)],
            "out_of_scope_urls": skipped,
            "note": "a host exposes services; SSH/database ports are reported, not scanned"}


def _scoped_asset(a: dict[str, Any]) -> Asset | None:
    """The asset a findings/posture call is about, or None for "all assets"."""
    if a.get("asset_id") or a.get("ref") or a.get("name"):
        return _asset_by(a.get("kind"), a.get("ref"), asset_id=a.get("asset_id"), name=a.get("name"))
    return None


def _scope(asset: Asset | None) -> dict[str, Any]:
    # Echoed in every findings/posture observation so the model never compares an asset's posture
    # with an all-assets listing (the cause of "posture says 0 critical, findings shows criticals").
    if asset is None:
        return {"asset_id": None, "asset": "ALL assets"}
    return {"asset_id": asset.id, "asset": asset.name or asset.ref, "kind": asset.kind}


def _findings() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        st = get_store()
        asset = _scoped_asset(a)
        status = a.get("status") or ",".join(OPEN_STATUSES)  # default = what posture counts as open
        if status == "all":
            status = None
        rows = st.list_findings(asset_id=asset.id if asset else None, severity=a.get("severity"), status=status)
        shown = rows[: int(a.get("limit") or 25)]
        return {"scope": _scope(asset), "status_filter": status or "all",
                "total": len(rows), "counts": severity_counts(rows),
                "count": len(shown), "findings": [_summary(f) for f in shown]}

    return Tool("findings", "List findings, highest priority first. Default: open findings (same set posture "
                            "counts); status='all' includes fixed/not_reproduced. Without asset_id/ref/name it "
                            "covers ALL assets",
                {"asset_id": "str?", "kind": "str?", "ref": "str?", "name": "str?", "severity": "str?",
                 "status": "str?", "limit": "int?"}, run)


def _validate() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..remediation import core, triage

        f = _finding(a["finding_id"])
        asset = core.get_asset(f.asset_id)
        src = core.source_dir(asset) if asset else None
        v = await asyncio.to_thread(triage.validate_finding, f, src, asset, a.get("lab"))
        return {"check": v.check, "result": v.result, "confidence": v.confidence,
                "evidence": [{"kind": e.kind, "label": e.label, "content": e.content[:400]} for e in v.evidence[:6]]}

    return Tool("validate", "Validate a finding with evidence (dependency/secret/data-flow/lab check)",
                {"finding_id": "str", "lab": "str?"}, run)


def _reproduce() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..remediation import core, reproduce

        f = _finding(a["finding_id"])
        asset = core.get_asset(f.asset_id)
        from ..remediation import lab as lab_mod

        h = await asyncio.to_thread(lab_mod.get_lab_target, asset) if asset else None
        ev_url = probe.evidence_url(f.url, f.snippet)
        plan = probe.plan_for(f.title, ev_url, f.snippet, proposal=a.get("proposal")) if ev_url else None
        if plan is not None:
            env = await asyncio.to_thread(probe.env_details, h) if h else {}
            e, where = await _probe_where(a.get("live"), ev_url, plan, env)
            return {"check": f"probe-{plan.weakness}", "result": e.verdict, "confidence": e.confidence,
                    "grade": e.grade or None, "proof": e.proved, "where": where,
                    "plan": {**plan.to_dict(), "base": plan.base},
                    "reproduce": e.lines(),
                    "as": e.identity or ("cookie" if e.cookie else "-"),
                    "control": {"status": e.control.status, "signal": e.control_hits},
                    "probe": {"status": e.probe.status, "signal": e.probe_hits},
                    "evidence": [{"kind": "request", "label": "control", "content": e.lines()[0]},
                                 {"kind": "request", "label": "probe", "content": e.lines()[1]}]}
        v = await asyncio.to_thread(reproduce.reproduce, f, h, asset)
        return {"check": v.check, "result": v.result, "confidence": v.confidence, "grade": None,
                "proof": v.result == "confirmed" and v.confidence >= 0.85,
                "verdict": v.evidence[-1].content if v.evidence else "",
                "evidence": [{"kind": e.kind, "label": e.label, "content": e.content[:400]} for e in v.evidence[:6]]}

    return Tool("reproduce", "Reproduce a data-flow finding against its lab copy (control + probe, severity-graded). "
                            "Optionally pass a `proposal` payload block: 'path: …\\nparam: …\\npayload: …\\nsignal: …'",
                {"finding_id": "str", "proposal": "str?"}, run)


def _http() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..analystlab import http as labhttp

        try:
            ref = await probe.resolve_async(a["url"], live=bool(a.get("live")))
        except Exception as e:  # noqa: BLE001 - a live reachability failure is the answer
            raise ToolError(f"live: {e}") from e
        if ref is None:
            raise ToolError(_none_reason(a["url"]))
        env = await asyncio.to_thread(probe.env_details, ref)
        hdrs = dict(a.get("headers") or {})
        if "identity" in env:
            hdrs.setdefault("x-demo-user", env["identity"])
        elif "cookie" in env:
            hdrs.setdefault("cookie", env["cookie"])
        r = await asyncio.to_thread(labhttp.request, ref, a.get("method") or "GET", a["path"],
                                    query=a.get("form") or {}, headers=hdrs)
        body = r.body[:1500]
        return {"url": a["url"], "handle": ref.handle, "method": r.method, "path": r.path, "query": r.query,
                "status": r.status, "headers": {k: v for k, v in r.headers.items() if k.lower() in
                                                ("content-type", "location", "www-authenticate")},
                "body": body, "redirect": r.redirect, "error": r.error or None,
                "as_user": "demo-low"}

    return Tool("http", "ONE raw request at the lab copy, or at the owner's live service with `live: true`. "
                        "Headers limited to "
                        "content-type/accept/x-demo-user; the identity is demo-low. Use it when no class probe applies",
                {"url": "str", "method": "str?", "path": "str", "form": "dict[str,str]?", "headers": "dict[str,str]?",
                 "live": "bool?"}, run)


async def _probe_where(live: Any, url: str, plan: probe.Plan, env: dict[str, str]) -> tuple[probe.Evidence, str]:
    """Resolve once; report the actual reachability failure without a copy fallback."""
    try:
        ref = await probe.resolve_async(url, live=bool(live))
    except Exception as e:
        raise ToolError(f"live: {e}") from e
    if ref is None:
        raise ToolError(_none_reason(url))
    env = {k: v for k, v in (await asyncio.to_thread(probe.env_details, ref)).items() if k == "cookie"}
    return await asyncio.to_thread(probe.run, ref, plan, **env), "live service" if ref.live else "lab copy"


def _probe() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        plan = probe.plan_for(a["title"], a["url"], a.get("evidence"), proposal=a.get("proposal"))
        if plan is None:
            raise ToolError("no fixed weakness class matches this title/evidence; use http instead")
        e, where = await _probe_where(a.get("live"), a["url"], plan, {})
        return {"class": plan.weakness, "result": e.verdict, "grade": e.grade or None, "proof": e.proved,
                "plan": plan.to_dict(), "reproduce": e.lines(), "as": e.identity or ("cookie" if e.cookie else "-"),
                "where": where,
                "control": {"status": e.control.status, "signal": e.control_hits},
                "probe": {"status": e.probe.status, "signal": e.probe_hits}}

    return Tool("probe", "Classify an observation into a fixed weakness class and prove it: a benign control and "
                         "then the probe, graded critical/high/suspected/not_reproduced. The target is the lab copy "
                         "unless `live: true`, which sends the pair at the owner's running service. Pass an optional "
                         "`proposal` block to supply the path, parameter and payload",
                {"title": "str", "url": "str", "evidence": "str?", "proposal": "str?", "live": "bool?"}, run)


def _evidence() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..evidence import screenshots

        url = a["url"]
        shot = await asyncio.to_thread(screenshots.capture, url, a.get("label") or url)
        return shot

    return Tool("evidence", "Screenshot a URL target in a headless browser (recorded as evidence)",
                {"url": "str", "label": "str?"}, run)


def _fix() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..remediation import fix

        f = _finding(a["finding_id"])
        # observe is a read-only day: a fix request means working, so the run lifts itself to assisted.
        ms = get_store().get_mode()
        if ms.mode == "observe":
            ms.transient = True
            get_store().set_mode(ms)
        fx = await asyncio.to_thread(fix.propose_fix, f.id, wait=True)
        out = {"fix_id": fx.id, "status": fx.status, "mode": fx.mode, "pr_url": fx.pr_url, "branch": fx.branch,
               "verification": fx.verification.model_dump() if fx.verification else None,
               "diff": (fx.diff or "")[:1200]}
        if a.get("apply"):
            applied = await asyncio.to_thread(fix.apply_fix, fx.id)
            out.update({"status": applied.status, "applied": True})
        return out

    return Tool("fix", "Patch a finding, verify it (rescan + lab boot) and open a PR. Lifts an observe-mode server to "
                       "assisted for this run. `apply: yes` also merges it (autonomous + dependency bump only)",
                {"finding_id": "str", "apply": "str?"}, run)


def _mode(reg: "AnalystTools") -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        from ..models import ModePatch
        from ..routes_core import patch_mode

        old = get_store().get_mode().mode
        if a.get("mode") and a["mode"] != old:
            try:
                m = patch_mode(ModePatch(mode=a["mode"]))
            except Exception as e:  # HTTPException: policy refusal (audited already)
                raise ToolError(f"refused: {getattr(e, 'detail', e)}") from e
        else:
            m = get_store().get_mode()
        reg.mode = m.mode
        return {"mode": m.mode, "autonomous_categories": m.autonomous_categories, "was": old}

    return Tool("mode", "Read or switch the remediation mode (observe = report only, assisted = PR for review, "
                        "autonomous = auto-apply dependency bumps). Switching is audited",
                {"mode": "str?"}, run)


def _posture() -> Tool:
    async def run(a: dict[str, Any]) -> Any:
        asset = _scoped_asset(a)
        p = posture.get_posture(asset.id if asset else None)
        d = p.model_dump()
        d.pop("history", None)  # the trend line is noise for a decision loop
        return {"scope": _scope(asset), **d}

    return Tool("posture", "Score, grade and open-finding counts for one asset (or ALL assets when none given); "
                           "counts match the findings tool for the same scope",
                {"asset_id": "str?", "kind": "str?", "ref": "str?", "name": "str?"}, run)


__all__ = ["AnalystTools", "Tool", "ToolError"]
