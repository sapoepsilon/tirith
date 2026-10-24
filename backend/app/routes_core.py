"""Core REST routes (prefix /api): health, assets, scans, findings, posture, mode, audit, events."""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Query

from . import config
from . import posture as posture_mod
from .audit import audit
from .events import emit
from .focus import resolve_profile
from .models import Asset, AssetCreate, AssetUpdate, Finding, ModePatch, ModeSettings, Posture, Scan, ScanCreate
from .scanners.docker import docker_available, missing_tools
from .scanners.runner import plan_tools, start_scan
from .scope import enforce, load_scope
from .store import get_store

router = APIRouter()


@router.get("/health")
def health():
    """Scanner CLIs are optional: a missing one is reported, never a failed health."""
    missing = missing_tools(tuple(dict.fromkeys(config.BIN.values())))
    return {"ok": True, "service": "tirith-backend", "docker": docker_available(), "missing_tools": missing}


@router.get("/scope")
def get_scope():
    return load_scope().to_dict()


# -- assets ------------------------------------------------------------------
@router.get("/assets", response_model=list[Asset])
def list_assets():
    return get_store().list_assets()


@router.post("/assets", response_model=Asset)
def create_asset(body: AssetCreate):
    ref = body.ref.strip()
    if body.kind == "local_path":
        ref = os.path.realpath(os.path.expanduser(ref)) if os.path.isabs(os.path.expanduser(ref)) else ref
    elif body.kind == "github_repo":
        ref = ref.removeprefix("https://github.com/").removesuffix(".git").strip("/")
    elif body.kind == "url":
        ref = ref.rstrip("/")
    ok, reason = enforce("asset.create", body.kind, ref, actor="api")
    if not ok:
        raise HTTPException(status_code=403, detail=f"out of scope: {reason}")
    if body.kind == "local_path" and not os.path.isdir(ref):
        raise HTTPException(status_code=400, detail=f"local path does not exist: {ref}")
    st = get_store()
    existing = st.find_asset(body.kind, ref)
    if existing and any(v is not None for v in (body.focus, body.exclude, body.sub_apps)):
        existing = st.save_asset(existing.model_copy(update={
            k: v for k, v in (("focus", body.focus), ("exclude", body.exclude), ("sub_apps", body.sub_apps)) if v is not None}))
    if existing:
        return existing
    name = body.name or (ref.rsplit("/", 1)[-1] if body.kind != "url" else ref)
    return st.save_asset(Asset(kind=body.kind, ref=ref, name=name, focus=body.focus or [],
                               exclude=body.exclude or [], sub_apps=body.sub_apps or []))


@router.get("/assets/{asset_id}", response_model=Asset)
def get_asset(asset_id: str):
    a = get_store().get_asset(asset_id)
    if not a:
        raise HTTPException(404, "asset not found")
    return a


@router.patch("/assets/{asset_id}", response_model=Asset)
def update_asset(asset_id: str, body: AssetUpdate):
    """Set name / focus / exclude / sub_apps (takes effect on the next scan)."""
    st = get_store()
    a = st.get_asset(asset_id)
    if not a:
        raise HTTPException(404, "asset not found")
    upd = body.model_dump(exclude_none=True)
    a = st.save_asset(a.model_copy(update=upd))
    audit("asset.update", target=f"{a.kind}:{a.ref}", actor="api", details=upd)
    return a


@router.get("/assets/{asset_id}/profile")
def get_asset_profile(asset_id: str):
    """Effective focus/exclude/sub_apps (asset fields, else the scope.yaml asset_profiles match)."""
    a = get_store().get_asset(asset_id)
    if not a:
        raise HTTPException(404, "asset not found")
    return resolve_profile(a).model_dump()


# -- scans -------------------------------------------------------------------
@router.post("/scans", response_model=Scan)
async def create_scan(body: ScanCreate):
    st = get_store()
    asset = st.get_asset(body.asset_id)
    if not asset:
        raise HTTPException(404, "asset not found")
    ok, reason = enforce("scan.create", asset.kind, asset.ref, actor="api")
    if not ok:
        raise HTTPException(status_code=403, detail=f"out of scope: {reason}")
    scan = Scan(asset_id=asset.id, tools=plan_tools(asset, body.tools))
    st.save_scan(scan)
    start_scan(scan)
    return scan


@router.get("/scans", response_model=list[Scan])
def list_scans(asset_id: str | None = None):
    return get_store().list_scans(asset_id)


@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str):
    s = get_store().get_scan(scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    return s


# -- findings ----------------------------------------------------------------
@router.get("/findings", response_model=list[Finding])
def list_findings(
    scan_id: str | None = None,
    asset_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    component: str | None = Query(None, description="main, periphery, lab (any lab sub-app) or lab:<dir>; comma list"),
    sort: str = Query("priority", pattern="^(priority|severity)$"),
    limit: int | None = Query(None, ge=1, le=5000),
):
    out = get_store().list_findings(scan_id=scan_id, asset_id=asset_id, severity=severity, status=status, tool=tool,
                                    component=component, sort=sort)
    return out[:limit] if limit else out


@router.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str):
    f = get_store().get_finding(finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


# -- posture -----------------------------------------------------------------
@router.get("/posture", response_model=Posture)
def get_posture(asset_id: str | None = None):
    if asset_id and not get_store().get_asset(asset_id):
        raise HTTPException(404, "asset not found")
    return posture_mod.get_posture(asset_id)


# -- mode --------------------------------------------------------------------
@router.get("/mode", response_model=ModeSettings)
def get_mode():
    return get_store().get_mode()


# The only remediation category that may ever be auto-applied. Modes are already a closed Literal on the model.
ALLOWED_AUTONOMOUS_CATEGORIES = ("dependency_bump",)


def _deny_mode(status: int, detail: str, body: ModeSettings) -> HTTPException:
    audit("mode.set", target=body.mode, actor="api", allowed=False,
          details={"reason": detail, "autonomous_categories": body.autonomous_categories})
    emit("policy.denied", f"Denied mode change to {body.mode}: {detail}", level="warn",
         data={"action": "mode.set", "mode": body.mode, "reason": detail})
    return HTTPException(status_code=status, detail=detail)


def _apply_mode(body: ModeSettings) -> ModeSettings:
    bad = [c for c in body.autonomous_categories if c not in ALLOWED_AUTONOMOUS_CATEGORIES]
    if bad:
        raise _deny_mode(422, f"autonomous_categories may only contain {list(ALLOWED_AUTONOMOUS_CATEGORIES)}; "
                              f"got {bad}", body)
    if body.mode == "autonomous" and not config.allow_autonomous():
        raise _deny_mode(403, "autonomous mode is disabled on this server (TIRITH_ALLOW_AUTONOMOUS is not set)", body)
    body = ModeSettings(mode=body.mode, autonomous_categories=list(dict.fromkeys(body.autonomous_categories)),
                        transient=True)
    st = get_store()
    old = st.get_mode()
    st.set_mode(body)
    audit("mode.set", target=body.mode, actor="api", details={"from": old.mode, "to": body.mode, "autonomous_categories": body.autonomous_categories})
    emit("mode.changed", f"Remediation mode: {old.mode} -> {body.mode}", data=body.model_dump())
    return body


@router.put("/mode", response_model=ModeSettings)
def put_mode(body: ModeSettings):
    return _apply_mode(body)


@router.patch("/mode", response_model=ModeSettings)
def patch_mode(body: ModePatch):
    """Partial switch, for chat: only `mode` (categories keep their stored value when omitted)."""
    old = get_store().get_mode()
    return _apply_mode(ModeSettings(mode=body.mode or old.mode,
                                    autonomous_categories=body.autonomous_categories
                                    if body.autonomous_categories is not None else old.autonomous_categories))


# -- audit / events ----------------------------------------------------------
@router.get("/audit")
def get_audit(limit: int = Query(100, ge=1, le=1000)):
    return [e.model_dump() for e in get_store().list_audit(limit)]


@router.get("/events/recent")
def recent_events(limit: int = Query(100, ge=1, le=1000)):
    return [e.model_dump(exclude_none=True) for e in get_store().recent_events(limit)]
