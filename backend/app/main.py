"""Tirith backend entrypoint: `uv run uvicorn app.main:app --port 8000`.

Access control: every route except GET /health and GET /api/health (HTTP and WebSocket) requires
`Authorization: Bearer <TIRITH_API_TOKEN>`. Startup fails without a token unless TIRITH_ALLOW_NO_AUTH=1.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from . import config, events
from .remediation import install
from .routes_core import health as api_health
from .routes_analyst import router as analyst_router
from .routes_analystlab import router as analystlab_router
from .routes_core import router as core_router
from .store import get_store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("tirith.auth")

PUBLIC_PATHS = frozenset({"/health", "/api/health"})
WS_SUBPROTOCOL = "tirith.v1"
WS_TOKEN_PREFIX = "bearer."
REPLAY_MAX = 500


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.check_auth_config()
    if config.api_token() is None:
        log.warning("TIRITH_ALLOW_NO_AUTH=1: API authentication is DISABLED (local development only)")
    config.ensure_dirs()
    st = get_store()
    events.bind_loop(asyncio.get_running_loop())
    # Scans interrupted by a restart can't resume; mark them failed.
    for s in st.list_scans():
        if s.status in ("queued", "running"):
            s.status = "failed"
            s.error = "interrupted by backend restart"
            s.tools = {t: ("failed" if v in ("pending", "running") else v) for t, v in s.tools.items()}
            st.save_scan(s)
    yield


def _token_ok(presented: str | None, expected: str) -> bool:
    if not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers") or []:
        if k.lower() == name:
            return v.decode("latin-1")
    return None


def _bearer(scope) -> str | None:
    auth = _header(scope, b"authorization")
    if auth and auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return None


def _ws_subprotocol_token(scope) -> str | None:
    """Browsers can't set headers on a WebSocket: accept `Sec-WebSocket-Protocol: tirith.v1, bearer.<token>`."""
    for p in scope.get("subprotocols") or []:
        if p.startswith(WS_TOKEN_PREFIX):
            return p[len(WS_TOKEN_PREFIX):]
    return None


class BearerAuthMiddleware:
    """Pure ASGI so it covers HTTP routes from every router and both WebSocket paths."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if kind == "http" and path in PUBLIC_PATHS and scope.get("method") in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        expected = config.api_token()
        if expected is None:
            if config.allow_no_auth():
                return await self.app(scope, receive, send)
            return await self._deny(scope, send, 503, "backend auth is not configured")
        presented = _bearer(scope)
        if presented is None and kind == "websocket":
            presented = _ws_subprotocol_token(scope)
        if not _token_ok(presented, expected):
            return await self._deny(scope, send, 401, "missing or invalid bearer token")
        return await self.app(scope, receive, send)

    @staticmethod
    async def _deny(scope, send, status: int, detail: str):
        if scope["type"] == "websocket":
            # Closing before accept makes the server answer the handshake with HTTP 403.
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": detail}).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        if status == 401:
            headers.append((b"www-authenticate", b'Bearer realm="tirith"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


app = FastAPI(title="Tirith backend", version="0.1.0", lifespan=lifespan)
# Order: the last added middleware is outermost. CORS sits outside auth so preflights get answered.
app.add_middleware(BearerAuthMiddleware)
_origins = config.cors_origins()
if _origins:
    app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                       allow_headers=["Authorization", "Content-Type"])
app.include_router(core_router, prefix="/api")
app.include_router(analyst_router, prefix="/api")
app.include_router(analystlab_router, prefix="/api")
install(app)  # remediation router under /api + lab hook for the ZAP runner


@app.get("/health")
def root_health():
    return api_health()


def _replay_count(raw: str | None) -> int:
    try:
        n = int((raw or "0").strip())
    except ValueError:
        return 0
    return max(0, min(n, REPLAY_MAX))


async def _ws_events(ws: WebSocket) -> None:
    offered = ws.scope.get("subprotocols") or []
    await ws.accept(subprotocol=WS_SUBPROTOCOL if WS_SUBPROTOCOL in offered else None)
    q = events.subscribe()
    try:
        # Optional replay: /ws/events?replay=20 (non-numeric -> 0, clamped to 0..500)
        replay = _replay_count(ws.query_params.get("replay"))
        if replay > 0:
            for ev in get_store().recent_events(replay):
                await ws.send_json(ev.model_dump(exclude_none=True))
        while True:
            payload = await q.get()
            await ws.send_json(payload)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        events.unsubscribe(q)


# Contract lists `WS /ws/events`; serve it both at the root and under /api.
app.add_api_websocket_route("/ws/events", _ws_events)
app.add_api_websocket_route("/api/ws/events", _ws_events)
