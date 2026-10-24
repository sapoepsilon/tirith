"""Analyst API: start a model-driven assessment, poll it, read its transcript.

  POST /api/analyst/runs {goal, max_steps?}   start (202-ish: returns the run, which then progresses)
  GET  /api/analyst/runs                      recent runs (newest first)
  GET  /api/analyst/runs/{run_id}             one run: status, every step, the final report
  GET  /api/analyst/stream                    SSE mirror of analyst.* events (the dashboard's progress feed)
  POST /api/evidence/screenshot {url}         capture one screenshot (same scope rules as the analyst)

Concurrency: one active run at a time (the DeepSeek box serves one request at a time, and two
analysts scanning the same hosts would race the store). A second POST returns 409.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import config
from .analyst import html_report, loop
from .analyst.tools import AnalystTools
from .events import emit
from .evidence import screenshots
from .models import new_id

router = APIRouter(tags=["analyst"])

_runs: dict[str, loop.AnalystRun] = {}
_active: set[str] = set()
# asyncio keeps only a weak reference to a task: without this, the run's task is garbage-collected
# mid-flight and the run sits at "running" with zero steps forever.
_tasks: set[asyncio.Task] = set()
_limits: dict[str, int | None] = {}  # per-run step budget override


class RunCreate(BaseModel):
    goal: str = Field(min_length=1, max_length=1000)
    max_steps: int | None = Field(default=None, ge=1, le=24)
    # "auto" runs straight through; "approve" holds after the first reproduction (and at the step cap)
    # so the user can answer in chat before anything is changed.
    mode: Literal["auto", "approve"] = "auto"
    charge: Literal["observe", "assisted", "autonomous"] | None = None  # this run only, restored after


class PauseBody(BaseModel):
    reason: str | None = Field(default=None, max_length=200)


class ShotRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2000)
    label: str | None = Field(default=None, max_length=80)


def _public(run: loop.AnalystRun) -> dict[str, Any]:
    return run.to_dict()


async def _drive(run_id: str, goal: str, pause_after: bool = False, charge: str | None = None) -> None:
    try:
        if charge:
            from .models import ModeSettings
            from .store import get_store

            current = get_store().get_mode()
            get_store().set_mode(ModeSettings(mode=charge, autonomous_categories=current.autonomous_categories,
                                              transient=charge != "observe"))
        tools = AnalystTools()
        finished = await loop.run(goal, tools, run_id=run_id, max_steps_override=_limits.get(run_id),
                                  pause_after_proof=pause_after)
        _runs[run_id] = finished
    finally:
        _active.discard(run_id)


@router.post("/analyst/runs", status_code=202)
async def start_run(body: RunCreate):
    if not config.analyst_enabled():
        raise HTTPException(403, "the autonomous analyst is disabled on this server (TIRITH_ALLOW_ANALYST is not set)")
    if _active:
        raise HTTPException(409, "an analyst run is already in progress; poll it before starting another")
    run_id = new_id("arn")
    _runs[run_id] = loop.AnalystRun(id=run_id, goal=body.goal)
    pause_after = body.mode == "approve"
    if pause_after:  # approve mode holds before the very first step too: nothing happens unasked for
        from .events import pause as set_pause

        set_pause(run_id, "starting; approve the first step")
    _limits[run_id] = body.max_steps
    _active.add(run_id)
    if body.charge == "autonomous" and not config.allow_autonomous():
        _runs.pop(run_id, None)
        raise HTTPException(403, "autonomous mode is disabled on this server (TIRITH_ALLOW_AUTONOMOUS is not set)")
    task = asyncio.create_task(_drive(run_id, body.goal, pause_after, body.charge), name=f"analyst-{run_id}")
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return _public(_runs[run_id])


@router.get("/analyst/runs")
def list_runs(limit: int = Query(20, ge=1, le=100)):
    return [_public(r) for r in list(_runs.values())[-limit:]][::-1]


@router.get("/analyst/runs/{run_id}")
def get_run(run_id: str):
    run = _runs.get(run_id)
    if run is not None:
        return _public(run)
    # Fall back to the run file so a restart (or a chat client asking later) can still read a finished run.
    f = config.EVIDENCE_DIR / "analyst" / f"{run_id}.json"
    if not f.is_file():
        raise HTTPException(404, "analyst run not found")
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError) as e:
        raise HTTPException(500, f"run file for {run_id} is unreadable: {type(e).__name__}") from e


@router.post("/analyst/runs/{run_id}/report")
def render_report(run_id: str, variant: str = Query("both", pattern="^(as-found|as-fixed|both)$")):
    """Render the HTML reports for a finished run and return their paths + the dashboard URLs."""
    # In-memory first, then the run file on disk, so an older run can still be reported on.
    run = _runs.get(run_id)
    run_file = config.EVIDENCE_DIR / "analyst" / f"{run_id}.json"
    if run is None and not run_file.is_file():
        raise HTTPException(404, "analyst run not found")
    if run is not None and run.status == "running":
        raise HTTPException(409, "the analyst is still working; the report is written when it finishes")
    out: dict[str, Any] = {"run_id": run_id, "variant": variant, "files": {}}
    for v in (["as-found", "as-fixed"] if variant == "both" else [variant]):
        try:
            p = html_report.render_run(run_id, v)
        except FileNotFoundError as e:
            raise HTTPException(404, str(e)) from e
        out["files"][v] = {"path": str(p), "url": f"/reports/{run_id}/{v}.html"}
    return out


@router.post("/analyst/runs/{run_id}/pause")
def pause_run(run_id: str, body: PauseBody | None = None):
    """Hold the run at its next checkpoint (the approval gate). Safe to call twice."""
    from .events import pause as set_pause

    run = _runs.get(run_id)
    if run is None:
        raise HTTPException(404, "analyst run not found")
    if run.status != "running":
        raise HTTPException(409, f"the run is {run.status}; nothing to pause")
    reason = (body.reason if body else None) or "waiting for the user's answer"
    set_pause(run_id, reason)
    run.waiting_on = reason
    emit("analyst.checkpoint", f"Paused: {reason}", level="warn", data={"run_id": run_id, "reason": reason})
    return {"run_id": run_id, "waiting_on": reason}


@router.post("/analyst/runs/{run_id}/resume")
def resume_run(run_id: str):
    """Answer the checkpoint: the paused run takes its next step after this call."""
    from .events import pauses, resume

    where = pauses()
    if run_id not in where:
        raise HTTPException(409, "this run is not waiting at a checkpoint")
    resume()
    run = _runs.get(run_id)
    if run is not None:
        run.waiting_on = None
    emit("analyst.resumed", "Checkpoint answered; the analyst continues", data={"run_id": run_id})
    return {"run_id": run_id, "resumed": True, "was_waiting_on": where.get(run_id) or ""}


@router.get("/analyst/stream")
async def stream():
    """Server-sent events for analyst progress (the dashboard subscribes here)."""
    from .events import subscribe, unsubscribe

    q = subscribe()

    async def gen():
        try:
            while True:
                ev = await q.get()
                if str(ev.get("type", "")).startswith("analyst."):
                    yield f"data: {json.dumps(ev)}\n\n"
        except asyncio.CancelledError:
            raise
        finally:
            unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/evidence/screenshot")
async def screenshot(body: ShotRequest):
    if not config.evidence_enabled():
        raise HTTPException(403, "screenshot evidence is disabled on this server (TIRITH_ALLOW_SHOTS is not set)")
    shot = await asyncio.to_thread(screenshots.capture, body.url, body.label)
    if not shot.get("ok"):
        raise HTTPException(403 if "out of scope" in str(shot.get("error")) else 502, str(shot.get("error")))
    return shot