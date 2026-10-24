"""Structured tool actions for the analyst-lab demo. Fixed code executes; the model only fills
schema-checked arguments.

  - `handle(handle)`                      confirm which known lab handle a call will use
  - `http.get(handle, path, query?, reason?)`   ONE read-only GET through that handle, as demo-low

The model cannot pass a host, URL, port, method, headers or code. There is no identity argument at all:
every model-selected request is sent as the fixed synthetic low-privilege identity (`demo-low`), because a
request made as an admin would look like a success and prove nothing about authorization. The fixed
regression code (`regression.check_access_control`) may use an admin positive control; the model may not.
The model infers from the app's own responses (HTML, error pages, docs routes), never from source.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..audit import audit
from . import http
from .lab import HandleError, LabRef, known_handles, resolve

TOOL_HANDLE = "handle"
TOOL_GET = "http.get"
TOOLS = (TOOL_HANDLE, TOOL_GET)

GET_ARGS = {"handle": "str", "path": "str", "query": "dict[str,str]?", "reason": "str?"}
HANDLE_ARGS = {"handle": "str"}
# The only identity the model's requests ever carry. There is no identity argument and no value
# screening: the demo app names roles in its own pages (`demo-low`, `demo-admin`), so a parameter value
# that looks like a username is a normal *target parameter*, not a way to authenticate. Authorization
# is the app's decision about the caller's identity, which stays fixed at MODEL_IDENTITY.
MODEL_IDENTITY = "demo-low"


class ToolError(RuntimeError):
    """A refusal or bad argument the model sees as an observation."""


@dataclass
class Ctx:
    max_requests: int = 6
    deadline: float = field(default_factory=lambda: time.monotonic() + 120)
    requests: int = 0
    handle: LabRef | None = None
    log: list[dict] = field(default_factory=list)

    def remaining(self) -> int:
        return max(0, self.max_requests - self.requests)

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


def schema() -> str:
    return ("- handle(handle: str) — confirm a lab handle before using it. Known handles: "
            + ", ".join(known_handles()) + " (two variants of the same demo app)\n"
            "- http.get(handle: str, path: str, query: object<string,string>?, reason: str?) "
              "— ONE read-only GET at the lab copy's own loopback port, always sent as the "
              f"low-privilege identity `{MODEL_IDENTITY}`. No host, URL, method, headers or identity can be "
              "chosen. `query` values may only use [A-Za-z0-9._~-]. Redirects are never followed.")


def _check_args(name: str, args: dict[str, Any]) -> dict[str, Any]:
    spec = HANDLE_ARGS if name == TOOL_HANDLE else GET_ARGS
    unknown = set(args) - set(spec)
    if unknown:
        raise ToolError(f"unknown argument(s) {sorted(unknown)} for {name}; allowed: {sorted(spec)}")
    out: dict[str, Any] = {}
    for k, typ in spec.items():
        optional = typ.endswith("?")
        typ = typ.rstrip("?")
        val = args.get(k)
        if val in (None, ""):
            if optional:
                continue
            raise ToolError(f"missing required argument {k!r} for {name}")
        if typ == "dict[str,str]":
            if not isinstance(val, dict) or not all(isinstance(x, str) for x in val.values()):
                raise ToolError(f"{k} must be an object of name -> string")
            out[k] = val
        else:
            if not isinstance(val, str):
                raise ToolError(f"{k} must be a string")
            out[k] = val
    return out


def execute(name: str, args: dict[str, Any], ctx: Ctx) -> tuple[bool, str, list[dict]]:
    """Run one tool action. Model-caused failures come back as observations, never exceptions."""
    try:
        if name not in TOOLS:
            raise ToolError(f"unknown tool {name!r}")
        if ctx.expired():
            raise ToolError("run time budget exhausted")
        clean = _check_args(name, args)
        if name == TOOL_HANDLE:
            return _handle(clean, ctx)
        return _get(clean, ctx)
    except (ToolError, HandleError, http.RequestRefused) as e:
        audit("analystlab.tool", target=name, allowed=False, actor="analyst",
              details={"args": args, "reason": str(e)[:300]})
        return False, f"refused: {e}", []


def _handle(a: dict[str, Any], ctx: Ctx) -> tuple[bool, str, list[dict]]:
    ref = resolve(a["handle"])
    ctx.handle = ref
    audit("analystlab.tool", target=TOOL_HANDLE, actor="analyst", details=ref.to_dict())
    where = (f"container {ref.container} on {ref.network} (internal)" if ref.container
             else "local process (no container runtime)")
    return True, (f"handle {ref.handle} -> variant {ref.variant}, {where}, app {ref.app_url}; "
                  f"checks passed: {', '.join(ref.checks)}"), []


def _get(a: dict[str, Any], ctx: Ctx) -> tuple[bool, str, list[dict]]:
    if ctx.remaining() <= 0:
        raise ToolError(f"request budget exhausted ({ctx.max_requests} per run)")
    if ctx.expired():
        raise ToolError("run time budget exhausted")
    ref = resolve(a["handle"])  # re-verified on every call; a cached destination alone is never trusted
    if a.get("reason"):
        audit("analystlab.reason", target=ref.handle, actor="analyst", details={"reason": a["reason"][:300]})
    ctx.requests += 1
    r = http.get(ref, a["path"], query=a.get("query") or {}, as_user=MODEL_IDENTITY, label=a.get("reason", ""))
    body = (f"[redirect status {r.status} to {r.headers.get('location', '?')}: not followed]"
            if r.redirect else r.body)
    if r.error:
        body = f"[no response: {r.error}]"
    req_line = f"GET {r.path}{_qs(r.query)} HTTP/1.1"
    obs = {"request": {"method": "GET", "handle": ref.handle, "variant": ref.variant, "path": r.path,
                       "query": r.query, "as_user": MODEL_IDENTITY},
           "response": {"status": r.status, "headers": r.headers, "body": body[:1200],
                        "bytes": len(r.body), "elapsed_ms": r.elapsed_ms, "redirect": r.redirect,
                        "error": r.error or None},
           "requests_used": ctx.requests, "requests_left": ctx.remaining()}
    via = f" (via docker exec {ref.container})" if ref.container else " (local client)"
    evidence = [{"kind": "request", "label": f"analyst-lab request ({ref.variant})",
                 "content": f"{req_line}\nHost: {ref.app_url.split('//')[1]}{via}\nX-Demo-User: {MODEL_IDENTITY}"},
                {"kind": "response", "label": f"analyst-lab response ({ref.variant})",
                 "content": f"HTTP {r.status}\n{_heads(r.headers)}\n\n{r.body[:2000]}"}]
    ctx.log.append({"tool": TOOL_GET, "handle": ref.handle, "variant": ref.variant, "path": r.path,
                    "query": r.query, "as_user": MODEL_IDENTITY, "status": r.status})
    audit("analystlab.result", target=f"{ref.handle}{r.path}", actor="analyst",
          details={"status": r.status, "bytes": len(r.body), "redirect": r.redirect})
    return True, json.dumps(obs, ensure_ascii=False), evidence


def _qs(q: dict[str, str]) -> str:
    return ("?" + "&".join(f"{k}={v}" for k, v in q.items())) if q else ""


def _heads(h: dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in sorted(h.items()))


__all__ = ["Ctx", "MODEL_IDENTITY", "TOOLS", "ToolError", "execute", "schema"]
