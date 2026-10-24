"""CONTRACT endpoints for explain / validate / fix / apply / rollback (mounted under /api)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from . import core, explain, fix, lab, llm, triage
from .core import Fix, Validation

router = APIRouter(tags=["remediation"])


class FixRequest(BaseModel):
    mode: str | None = None


class ValidateRequest(BaseModel):
    lab: bool | None = None


def _finding(finding_id: str):
    f = core.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


def _fix_errors(fn, *a, **kw):
    """CONTRACT error mapping: 403 policy, 404/409/422 from FixRefused, 502 GitHub/LLM."""
    try:
        return fn(*a, **kw)
    except fix.FixRefused as e:
        raise HTTPException(e.status_code, e.reason) from None
    except fix.PolicyError as e:  # subclass of GitHubError: must come first
        raise HTTPException(403, str(e)) from None
    except fix.GitHubError as e:
        raise HTTPException(502, str(e)) from None
    except llm.LLMError as e:
        raise HTTPException(502, f"LLM error: {e}") from None


def _src(f):
    asset = core.get_asset(f.asset_id)
    try:
        return asset, (core.source_dir(asset) if asset else None)
    except Exception:
        return asset, None


# Sync handlers: FastAPI runs them in its threadpool, so long LLM/docker work never blocks the loop.
@router.post("/findings/{finding_id}/explain")
def explain_finding(finding_id: str):
    f = _finding(finding_id)
    _, src = _src(f)
    try:
        return explain.explain_finding(f, src)
    except (llm.LLMError, ValueError) as e:
        raise HTTPException(502, f"LLM error: {e}") from None


@router.post("/findings/{finding_id}/validate", response_model=Validation)
def validate_finding(finding_id: str, body: ValidateRequest | None = None, lab_check: bool | None = Query(None, alias="lab")):
    f = _finding(finding_id)
    asset, src = _src(f)
    use_lab = lab_check if lab_check is not None else (body.lab if body else None)
    return triage.validate_finding(f, src, asset, use_lab=use_lab)


@router.post("/findings/{finding_id}/fix", response_model=Fix)
def fix_finding(finding_id: str, body: FixRequest | None = None, wait: bool = Query(False)):
    _finding(finding_id)
    return _fix_errors(fix.propose_fix, finding_id, mode=body.mode if body else None, wait=wait)


@router.get("/fixes/{fix_id}", response_model=Fix)
def get_fix(fix_id: str):
    fx = core.get_fix(fix_id)
    if not fx:
        raise HTTPException(404, "fix not found")
    return fx


@router.post("/fixes/{fix_id}/apply", response_model=Fix)
def apply_fix(fix_id: str):
    return _fix_errors(fix.apply_fix, fix_id)


@router.post("/fixes/{fix_id}/rollback", response_model=Fix)
def rollback_fix(fix_id: str):
    return _fix_errors(fix.rollback_fix, fix_id)


# --- extras (not in the contract; handy for the dashboard / demo) -------------
@router.get("/lab")
def lab_status():
    return {"network": lab.lab_network(), "running": [h.as_dict() for h in list(lab._registry.values())]}


@router.delete("/lab")
def lab_stop_all():
    n = lab.stop_all()
    core.audit("lab.stop_all", details={"stopped": n})
    return {"stopped": n}
