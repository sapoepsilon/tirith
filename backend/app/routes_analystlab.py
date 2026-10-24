"""Analyst-lab API (prefix /api, behind the same bearer auth as everything else).

  GET  /analystlab/status                 handles, client mode, last scenario
  POST /analystlab/reset                  stop both demo lab copies (and any scenario state)
  POST /analystlab/start {max_steps?, dry_run?}   boot+verify labs, baseline, model-planned run
  GET  /analystlab/runs/{id}              one scenario (memory, then artifact)
  POST /analystlab/runs/{id}/apply {mode?}        open a PR for the demo finding (explicit only)
  POST /analystlab/runs/{id}/check                deterministic same-request recheck on both variants
  POST /analystlab/validate/{finding_id}          access-control check on the demo asset's finding

Off unless TIRITH_ALLOW_ANALYST=1, exactly like the rest of the analyst surface.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import config
from .analystlab import demo, lab as labmod, regression
from .analystlab import loop as labloop

router = APIRouter(tags=["analystlab"])


class StartBody(BaseModel):
    max_steps: int | None = Field(default=None, ge=1, le=labloop.MAX_STEPS_HARD)
    dry_run: bool = False


def _enabled() -> None:
    if not config.analyst_enabled():
        raise HTTPException(403, "the analyst is disabled on this server (TIRITH_ALLOW_ANALYST is not set)")


@router.get("/analystlab/status")
def status() -> dict[str, Any]:
    _enabled()
    return labmod.status()


@router.post("/analystlab/reset")
def reset() -> dict[str, Any]:
    _enabled()
    try:
        return demo.reset()
    except labmod.HandleError as e:
        raise HTTPException(409, str(e)) from e


@router.post("/analystlab/start", status_code=202)
async def start(body: StartBody | None = None) -> dict[str, Any]:
    """202 + the scenario id at once: labs boot in a worker thread, the model loop runs in a task."""
    _enabled()
    b = body or StartBody()
    try:
        sc = await asyncio.to_thread(demo.start, max_steps=b.max_steps, dry_run=b.dry_run)
    except labmod.HandleError as e:
        raise HTTPException(409, str(e)) from e
    return {"id": sc.id, "status": sc.status, "stage": sc.stage, "poll": f"/api/analystlab/runs/{sc.id}"}


@router.get("/analystlab/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    _enabled()
    try:
        return demo.get(run_id)
    except FileNotFoundError as e:
        raise HTTPException(404, "analyst-lab scenario not found") from e


@router.post("/analystlab/runs/{run_id}/check")
async def check(run_id: str) -> dict[str, Any]:
    _enabled()
    try:
        demo.get(run_id)
    except FileNotFoundError as e:
        raise HTTPException(404, "analyst-lab scenario not found") from e
    try:
        return (await asyncio.to_thread(demo.check, run_id)).to_dict()
    except labmod.HandleError as e:
        raise HTTPException(409, str(e)) from e


@router.post("/analystlab/validate/{finding_id}")
async def validate(finding_id: str) -> dict[str, Any]:
    _enabled()
    from .store import get_store

    f = get_store().get_finding(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    if not regression.is_demo_finding(f):
        raise HTTPException(403, "the access-control check applies to the analyst-lab demo finding only")
    ref = labmod.asset_handle(f.asset_id) or labmod.for_asset(regression.ensure_demo_asset().id)
    if ref is None:
        raise HTTPException(409, "no verified demo lab copy; POST /api/analystlab/start first")
    try:
        v = await asyncio.to_thread(regression.validate, finding_id, ref)
    except regression.DemoFindingError as e:
        raise HTTPException(403, str(e)) from e
    return v.model_dump()