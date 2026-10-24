"""Event bus: persisted to SQLite (for /events/recent) and fanned out to WebSocket subscribers.

`emit()` is safe to call from async code, sync code on the loop thread, or worker threads.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .models import Event
from .store import get_store

log = logging.getLogger("tirith.events")

_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


def _fanout(payload: dict) -> None:
    for q in list(_subscribers):
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            pass  # slow consumer: drop


def emit(
    type: str,
    message: str,
    level: str = "info",
    scan_id: str | None = None,
    finding_id: str | None = None,
    fix_id: str | None = None,
    data: dict[str, Any] | None = None,
) -> Event:
    ev = Event(type=type, level=level, message=message, scan_id=scan_id, finding_id=finding_id, fix_id=fix_id, data=data)
    try:
        get_store().add_event(ev)
    except Exception:  # never let event persistence break a scan
        log.exception("failed to persist event")
    payload = ev.model_dump(exclude_none=True)
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is not None and (_loop is None or running is _loop):
        _fanout(payload)
    elif _loop is not None and _loop.is_running():
        _loop.call_soon_threadsafe(_fanout, payload)
    return ev


# --------------------------------------------------------------------------- run gate
# A run checkpoint polls this between two tool calls, so a person can answer before the next action
# (the approval/confirm step). A plain flag rather than an asyncio.Event: the flag is process-wide and
# the tests (and any embedding) run several loops, which an Event binds itself to. In-process only: a
# restart clears a pause, never a run.
_gate = True
_pauses: dict[str, str] = {}


def paused() -> bool:
    return not _gate


def pauses() -> dict[str, str]:
    return dict(_pauses)


def pause(run_id: str | None = None, reason: str = "") -> None:
    """Hold every run at its next checkpoint (one id records where the analyst is)."""
    global _gate
    _gate = False
    if run_id:
        _pauses[run_id] = reason[:200]


def resume() -> None:
    global _gate
    _gate = True
    _pauses.clear()


def set_loop_stub() -> None:
    pass


async def checkpoint(timeout: float = 900.0) -> bool:
    """Hold at a run boundary while paused (polled ~15x/s). True when it held; False when not paused.

    On timeout it releases the pause itself, so a forgotten answer cannot leave a run parked forever."""
    if _gate:
        return False
    deadline = time.monotonic() + timeout
    while not _gate:
        if time.monotonic() > deadline:
            resume()
            return True
        await asyncio.sleep(0.06)
    return True
