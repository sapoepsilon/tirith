"""Scan orchestration: scope check -> workdir -> tools in parallel -> normalize -> dedupe -> events."""

from __future__ import annotations

import asyncio
import logging
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from .. import config, posture
from ..focus import apply_profile, matches_any, resolve_profile
from ..assets import CloneError, ensure_clone, workdir_for
from ..scanners import discovery
from ..audit import audit
from ..events import emit
from ..models import TOOLS, Asset, Finding, Scan, now_iso, zero_counts
from ..scope import check_url, enforce, load_scope, url_host
from ..store import get_store
from . import tools as tools_mod
from .normalize import NORMALIZERS, Ctx

log = logging.getLogger("tirith.scan")

_asset_locks: dict[str, asyncio.Lock] = {}
_tasks: set[asyncio.Task] = set()

CODE_TOOLS = ("semgrep", "gitleaks", "trivy")
MAX_CONCURRENT_SCANS = 2
# Bumped when the fingerprint scheme changes: the first run per asset+tool afterwards lets new
# fingerprints adopt the matching stored findings (status/validation/fix_id/ai_summary survive).
FINGERPRINT_VERSION = "2"

_scan_sems: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = weakref.WeakKeyDictionary()


def _scan_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    sem = _scan_sems.get(loop)
    if sem is None:
        sem = _scan_sems[loop] = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
    return sem


@dataclass
class ToolRun:
    status: str  # done | failed | skipped
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    partial_files: set[str] = field(default_factory=set)  # files the tool could not fully analyze


def default_tools(asset: Asset) -> list[str]:
    if asset.kind == "url":
        return ["zap"]
    if asset.kind == "host":
        return ["nmap"]
    return list(TOOLS)


def plan_tools(asset: Asset, requested: list[str] | None) -> dict[str, str]:
    wanted = requested or default_tools(asset)
    return {t: ("pending" if t in wanted else "skipped") for t in TOOLS}


def start_scan(scan: Scan) -> asyncio.Task:
    t = asyncio.create_task(run_scan(scan.id), name=f"scan-{scan.id}")
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return t


async def _web_target(asset: Asset) -> str | None:
    """nikto target: the first discovered HTTP(S) service of the host, None when nothing web answers."""
    try:
        disc = await discovery.discover(asset)
    except PermissionError:
        return None
    for svc in disc.services:
        url = discovery.url_for(asset.ref, svc)
        if url:
            return url
    return None


async def _resolve_zap_target(asset: Asset) -> tuple[str | None, str | None, str, object | None]:
    """Returns (url, network, reason, lab). url None => skip ZAP. lab = the lab target object (for
    the session hook) when ZAP will run against the asset's isolated lab copy."""
    scope = load_scope()
    # Looked up at call time so the lab module can replace it; it blocks (docker build/run), so off-loop.
    lab = await asyncio.to_thread(tools_mod.get_lab_target, asset)
    if lab is not None:
        lt = tools_mod.LabTarget(url=lab) if isinstance(lab, str) else lab
        if lt.network and lt.network == scope.lab_network:
            return lt.url, lt.network, "lab target", lab
        ok, reason = check_url(lt.url, scope)
        return (lt.url, lt.network, "lab target", None) if ok else (None, None, f"lab target out of scope: {reason}", None)
    if asset.kind != "url":
        return None, None, "no lab deployment for this asset (no Dockerfile, or the lab did not boot: see lab.boot audit)", None
    ok, reason = check_url(asset.ref, scope)
    if not ok:
        return None, None, reason, None
    return asset.ref, None, reason, None


async def _lab_session(lab: object | None) -> dict[str, str]:
    """Signed-in cookies for the lab copy ({} on any failure: ZAP then runs unauthenticated)."""
    if lab is None:
        return {}
    try:
        cookies = await asyncio.to_thread(tools_mod.get_lab_session, lab)
    except Exception:  # noqa: BLE001
        log.exception("lab session hook failed")
        return {}
    return dict(cookies) if isinstance(cookies, dict) else {}


async def _lab_seeds(lab: object | None) -> list[str]:
    """Extra crawl start paths for the lab copy ([] on any failure)."""
    if lab is None:
        return []
    try:
        seeds = await asyncio.to_thread(tools_mod.get_lab_seeds, lab)
    except Exception:  # noqa: BLE001
        log.exception("lab seeds hook failed")
        return []
    return [str(p) for p in seeds] if isinstance(seeds, list) else []


def _normalize(tool: str, raw, scan: Scan, asset: Asset, src: Path | None) -> tuple[list[Finding], int]:
    """CPU-bound (+ source reads): runs off the event loop."""
    findings = NORMALIZERS[tool](raw, Ctx(scan_id=scan.id, asset_id=asset.id, src_root=src))
    return apply_profile(findings, resolve_profile(asset))


async def _run_tool(tool: str, scan: Scan, asset: Asset, src: Path | None) -> ToolRun:
    st = get_store()
    name = f"tirith-{scan.id}-{tool}"
    outdir = config.REPORTS_DIR / scan.id / tool

    lab, cookies, seeds = None, {}, []
    if tool == "zap":
        url, network, reason, lab = await _resolve_zap_target(asset)
        if not url:
            audit("scan.tool.skip", target=f"{asset.kind}:{asset.ref}", allowed=False, details={"tool": "zap", "reason": reason})
            emit("tool.finished", f"ZAP skipped: {reason}", level="info", scan_id=scan.id, data={"tool": tool, "status": "skipped", "reason": reason})
            return ToolRun("skipped")
        if network:
            cookies, seeds = await asyncio.gather(_lab_session(lab), _lab_seeds(lab))
        audit("scan.tool.zap", target=url, allowed=True,
              details={"network": network, "reason": reason, "authenticated": bool(cookies),
                       "cookie_names": sorted(cookies), "seed_paths": len(seeds)})  # names only, never values
    elif tool in ("nmap", "nikto"):
        target = asset.ref
        if tool == "nikto":
            target = await _web_target(asset)
            if not target:
                reason = "no web port discovered on the host"
                emit("tool.finished", f"{tool} skipped: {reason}", scan_id=scan.id, data={"tool": tool, "status": "skipped", "reason": reason})
                return ToolRun("skipped")
    elif src is None:
        reason = "no source tree for url asset"
        emit("tool.finished", f"{tool} skipped: {reason}", scan_id=scan.id, data={"tool": tool, "status": "skipped", "reason": reason})
        return ToolRun("skipped")

    scan.tools[tool] = "running"
    st.save_scan(scan)
    started, sdata = f"{tool} started on {asset.name}", {"tool": tool, "asset_id": asset.id}
    if tool == "zap" and lab is not None:
        started += " (lab copy, signed in as a lab test user)" if cookies else " (lab copy, unauthenticated)"
        sdata["authenticated"] = bool(cookies)
    emit("tool.started", started, scan_id=scan.id, data=sdata)
    try:
        if tool == "semgrep":
            res = await tools_mod.run_semgrep(src, name)
        elif tool == "gitleaks":
            res = await tools_mod.run_gitleaks(src, outdir, name)
        elif tool == "trivy":
            res = await tools_mod.run_trivy(src, name)
        elif tool == "nmap":
            res = await tools_mod.run_nmap(target, name)
        elif tool == "nikto":
            res = await tools_mod.run_nikto(target, name)
        else:
            res = await tools_mod.run_zap(url, outdir, name, network=network, cookies=cookies or None, seeds=seeds or None)
    except Exception as e:  # docker missing, etc.
        log.exception("tool %s crashed", tool)
        res = tools_mod.ToolOutput(error=f"{type(e).__name__}: {e}")

    if res.error or res.raw is None:
        err = res.error or "no report"
        emit("tool.finished", f"{tool} failed: {err[:300]}", level="error", scan_id=scan.id, data={"tool": tool, "status": "failed"})
        return ToolRun("failed", error=err)

    try:
        findings, dropped = await asyncio.to_thread(_normalize, tool, res.raw, scan, asset, src)
    except Exception as e:  # noqa: BLE001 - a malformed report fails this tool only
        log.exception("normalizing %s output failed", tool)
        err = f"report could not be normalized: {type(e).__name__}: {e}"
        emit("tool.finished", f"{tool} failed: {err[:300]}", level="error", scan_id=scan.id, data={"tool": tool, "status": "failed"})
        return ToolRun("failed", error=err)
    finally:
        res.raw = None  # gitleaks raw output holds secret values: drop it as soon as it is normalized
    if dropped:
        audit("scan.exclude", target=f"{asset.kind}:{asset.ref}", details={"tool": tool, "dropped": dropped, "scan_id": scan.id})
    if tool == "zap" and not network:
        # Report the URL the user knows, not the container-side alias.
        inner = tools_mod.container_reachable_url(url).rstrip("/")
        if inner != url.rstrip("/"):
            for f in findings:
                f.url = f.url.replace(inner, url.rstrip("/"), 1) if f.url else f.url
                f.snippet = f.snippet.replace(inner, url.rstrip("/")) if f.snippet else f.snippet
    return ToolRun("done", findings, partial_files=set(res.partial_files))


async def run_scan(scan_id: str) -> None:
    st = get_store()
    scan = st.get_scan(scan_id)
    if not scan:
        return
    asset = st.get_asset(scan.asset_id)
    lock = _asset_locks.setdefault(scan.asset_id, asyncio.Lock())
    async with lock, _scan_semaphore():
        try:
            await _run_scan_locked(scan, asset)
        except Exception as e:
            log.exception("scan %s crashed", scan_id)
            scan.status = "failed"
            scan.error = f"{type(e).__name__}: {e}"
            scan.finished_at = now_iso()
            for t, s in scan.tools.items():
                if s in ("pending", "running"):
                    scan.tools[t] = "failed"
            st.save_scan(scan)
            emit("scan.finished", f"Scan failed: {scan.error}", level="error", scan_id=scan.id, data={"status": "failed"})


async def _run_scan_locked(scan: Scan, asset: Asset | None) -> None:
    st = get_store()
    if asset is None:
        raise RuntimeError("asset not found")
    scan.status = "running"
    scan.started_at = now_iso()
    st.save_scan(scan)
    planned = [t for t, s in scan.tools.items() if s == "pending"]
    emit("scan.started", f"Scan started on {asset.name} ({', '.join(planned)})", scan_id=scan.id,
         data={"asset_id": asset.id, "tools": planned})

    ok, reason = enforce("scan.run", asset.kind, asset.ref, actor="scanner", scan_id=scan.id)
    if not ok:
        scan.status = "failed"
        scan.error = f"out of scope: {reason}"
        scan.tools = {t: ("skipped" if s == "skipped" else "failed") for t, s in scan.tools.items()}
        scan.finished_at = now_iso()
        st.save_scan(scan)
        emit("scan.finished", f"Scan blocked: {reason}", level="error", scan_id=scan.id, data={"status": "failed"})
        return

    src: Path | None = None
    if asset.kind == "github_repo" and any(t in planned for t in CODE_TOOLS):
        emit("tool.started", f"Cloning {asset.ref}", scan_id=scan.id, data={"tool": "git", "asset_id": asset.id})
        try:
            src = await ensure_clone(asset)
        except CloneError as e:
            raise RuntimeError(str(e)) from None
        emit("tool.finished", f"Cloned {asset.ref}", level="success", scan_id=scan.id, data={"tool": "git", "status": "done"})
    elif asset.kind == "local_path":
        src = workdir_for(asset)
        if not src or not src.is_dir():
            raise RuntimeError(f"local path not found: {asset.ref}")

    counts = zero_counts()
    new_total = 0
    resolved = 0
    prof = resolve_profile(asset)

    def _keep(partial: set[str]):
        # Never mark fixed what this run did not look at: excluded paths, files the tool failed on.
        def keep(f: Finding) -> bool:
            return bool(f.file) and (f.file in partial or matches_any(f.file, prof.exclude))
        return keep

    def _persist(tool: str, run: ToolRun) -> tuple[list[tuple[Finding, bool]], int]:
        """Off-loop: batch upsert + resolution, each in one transaction."""
        uniq: dict[str, Finding] = {}
        for f in run.findings:
            uniq.setdefault(f.fingerprint, f)
        fpv_key = f"scan:fpv:{asset.id}:{tool}"
        adopt = st.get_kv(fpv_key) != FINGERPRINT_VERSION
        stored = st.upsert_findings(list(uniq.values()), adopt_legacy=adopt)
        n_resolved = st.resolve_missing(asset.id, tool, set(uniq), keep=_keep(run.partial_files))
        st.set_kv(fpv_key, FINGERPRINT_VERSION)
        return stored, n_resolved

    async def one(tool: str) -> None:
        nonlocal new_total, resolved
        run = await _run_tool(tool, scan, asset, src)
        status, err = run.status, run.error
        if status == "done":
            try:
                stored, n_resolved = await asyncio.to_thread(_persist, tool, run)
            except Exception as e:  # noqa: BLE001 - one tool's failure must not orphan the others
                log.exception("persisting %s results failed", tool)
                status, err = "failed", f"{type(e).__name__}: {e}"
                emit("tool.finished", f"{tool} failed: {err[:300]}", level="error", scan_id=scan.id,
                     data={"tool": tool, "status": "failed"})
            else:
                new_n = 0
                for f, is_new in stored:
                    counts[f.severity] += 1
                    if is_new:
                        new_n += 1
                        emit(
                            "finding.new", f"[{f.severity}] {f.title}" + (f" ({f.file}" + (f":{f.line}" if f.line else "") + ")" if f.file else ""),
                            level="warn" if f.severity in ("critical", "high") else "info",
                            scan_id=scan.id, finding_id=f.id,
                            data={"tool": tool, "severity": f.severity, "category": f.category, "rule_id": f.rule_id,
                                  "file": f.file, "line": f.line, "cve": f.cve, "package": f.package},
                        )
                new_total += new_n
                resolved += n_resolved
                partial = f", {len(run.partial_files)} file(s) partially analyzed" if run.partial_files else ""
                emit("tool.finished", f"{tool} finished: {len(stored)} findings ({new_n} new){partial}", level="success",
                     scan_id=scan.id, data={"tool": tool, "status": "done", "findings": len(stored), "new": new_n,
                                            "resolved": n_resolved, "partial_files": sorted(run.partial_files)})
        scan.tools[tool] = status
        if err:
            scan.error = (scan.error + "; " if scan.error else "") + f"{tool}: {err[:300]}"
        scan.counts = dict(counts)
        await asyncio.to_thread(st.save_scan, scan)

    results = await asyncio.gather(*(one(t) for t in planned), return_exceptions=True)
    for tool, r in zip(planned, results):
        if isinstance(r, BaseException):
            log.error("tool %s crashed: %r", tool, r)
            scan.tools[tool] = "failed"
            scan.error = (scan.error + "; " if scan.error else "") + f"{tool}: {type(r).__name__}: {r}"[:300]

    ran = [t for t in planned if scan.tools.get(t) != "skipped"]
    failed = [t for t in ran if scan.tools.get(t) == "failed"]
    scan.status = "failed" if ran and len(failed) == len(ran) else "done"
    scan.counts = dict(counts)
    scan.finished_at = now_iso()
    st.save_scan(scan)
    total = sum(counts.values())
    msg = f"Scan {'finished' if scan.status == 'done' else 'failed'}: {total} findings ({new_total} new"
    msg += f", {resolved} resolved)" if resolved else ")"
    if failed:
        msg += f"; failed tools: {', '.join(failed)}"
    emit("scan.finished", msg, level="success" if scan.status == "done" and not failed else ("warn" if scan.status == "done" else "error"),
         scan_id=scan.id, data={"status": scan.status, "counts": scan.counts, "tools": scan.tools, "new": new_total, "resolved": resolved})
    audit("scan.finished", target=f"{asset.kind}:{asset.ref}", details={"scan_id": scan.id, "status": scan.status, "counts": scan.counts})
    posture.record(asset.id, scan_id=scan.id)


__all__ = ["start_scan", "run_scan", "plan_tools", "default_tools", "url_host"]
