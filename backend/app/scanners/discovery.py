"""Read-only service discovery on host assets.

A `host` asset is a bare hostname/IP allowed by scope.yaml `host_targets` (exact entries or CIDRs).
Discovery answers one question — *which of the allow-listed ports are open* — and nothing else:

- Only ports in `host_ports` are probed, only against that one host. No port sweep, no CIDR walk
  (a CIDR entry authorises the host you name, not scanning the subnet).
- A connect + optional HTTP HEAD/GET of `/`. No payloads, no version-banner grabbing beyond what a
  plain HTTP response says, no credentials, no POST.
- Every probe is scope-checked and audited; a host outside `host_targets` is refused before any
  socket is opened.

Results feed the analyst's plan (which URLs to hand ZAP, which services exist) and the posture view.
"""

from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass, field

from .. import config
from ..audit import audit
from ..events import emit
from ..models import Asset
from ..scope import check_host, load_scope

CONNECT_TIMEOUT = 2.0
HTTP_TIMEOUT = 5.0
MAX_HEADER_BYTES = 8192
# Ports whose plain-HTTP probe is worth trying (everything else is reported as "open" only).
HTTP_PORTS = {80, 443, 3000, 3001, 5000, 8000, 8001, 8010, 8080, 8081, 8082, 8443, 8787, 8888, 9000, 9090}
TLS_PORTS = {443, 8443}

# Banner -> product guesses, matched only against what the service volunteered.
PRODUCT_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"uvicorn|fastapi", re.I), "python-api"),
    (re.compile(r"Proxmox|pve-", re.I), "proxmox"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "apache"),
    (re.compile(r"grafana", re.I), "grafana"),
    (re.compile(r"postgres|postgresql", re.I), "postgres"),
    (re.compile(r"redis", re.I), "redis"),
    (re.compile(r"docker", re.I), "docker"),
    (re.compile(r"ollama|llama", re.I), "llm-server"),
    (re.compile(r"tirith", re.I), "tirith"),
]


@dataclass
class Service:
    port: int
    state: str = "open"  # open | closed | timeout | error
    scheme: str | None = None  # http | https when an HTTP response came back
    status: int | None = None
    server: str | None = None
    product: str | None = None
    title: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None and k != "error"} | (
            {"error": self.error} if self.error else {}
        )


@dataclass
class Discovery:
    host: str
    services: list[Service] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None

    @property
    def open(self) -> list[Service]:
        return [s for s in self.services if s.state == "open"]

    def to_dict(self) -> dict:
        return {"host": self.host, "started_at": self.started_at, "finished_at": self.finished_at,
                "services": [s.to_dict() for s in self.services],
                "open_ports": [s.port for s in self.open]}


async def _tcp(host: str, port: int) -> str:
    """'open' | 'closed' | 'timeout' | 'error:...' — one connect attempt, closed immediately."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=CONNECT_TIMEOUT)
    except asyncio.TimeoutError:
        return "timeout"
    except (ConnectionRefusedError, OSError) as e:
        return "closed" if isinstance(e, ConnectionRefusedError) else f"error:{type(e).__name__}"
    else:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - closing a probe socket must never fail the probe
            pass
        return "open"


def _http_probe_sync(host: str, port: int, tls: bool) -> Service:
    """One GET / over plain HTTP or TLS, capturing status + a few headers. Never follows redirects."""
    import http.client
    import ssl

    svc = Service(port=port, scheme="https" if tls else "http")
    conn_cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # lab target: a self-signed cert is still a live service
    conn = conn_cls(host, port, timeout=HTTP_TIMEOUT, context=ctx) if tls else conn_cls(host, port, timeout=HTTP_TIMEOUT)
    try:
        conn.request("GET", "/", headers={"User-Agent": "Tirith-Discovery/1", "Accept": "*/*"})
        resp = conn.getresponse()
        svc.status = resp.status
        svc.server = (resp.getheader("Server") or "")[:120] or None
        body = resp.read(MAX_HEADER_BYTES).decode("utf-8", "replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            svc.title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        for pat, name in PRODUCT_HINTS:
            if pat.search(f"{svc.server or ''} {svc.title or ''} {body[:2000]}"):
                svc.product = name
                break
    except Exception as e:  # noqa: BLE001 - any failure just means "no HTTP answer here"
        svc.scheme, svc.status, svc.error = None, None, f"{type(e).__name__}: {str(e)[:120]}"
    finally:
        conn.close()
    return svc


async def _probe(host: str, port: int) -> Service:
    state = await _tcp(host, port)
    svc = Service(port=port, state=state)
    if state != "open":
        return svc
    # Try the schemes this port plausibly speaks; a web service must never be reported as merely
    # "open" just because its port is not in the well-known list.
    schemes = [port in TLS_PORTS]
    if port in HTTP_PORTS or port not in TLS_PORTS:
        schemes.append(False)
    for tls in dict.fromkeys(schemes):
        res = await asyncio.to_thread(_http_probe_sync, host, port, tls)
        if res.status is not None:
            return res
    return svc


def ports_for(host: str) -> list[int]:
    scope = load_scope()
    ports = list(scope.host_ports)
    if not ports:  # conservative default: common service ports only
        ports = sorted({22, 80, 443, 3000, 5432, 6379, 8000, 8080, 8443, 9090})
    return ports[:256]


async def discover(asset: Asset) -> Discovery:
    """Probe one host asset. Refuses (raises PermissionError) when the host is out of scope."""
    if asset.kind != "host":
        raise PermissionError(f"discovery needs a host asset, got {asset.kind}")
    ok, reason = check_host(asset.ref, load_scope())
    audit("discovery.start", target=f"host:{asset.ref}", allowed=ok, actor="scanner", details={"reason": reason})
    if not ok:
        emit("policy.denied", f"Discovery refused on {asset.ref}: {reason}", level="warn",
             data={"action": "discovery", "host": asset.ref, "reason": reason})
        raise PermissionError(reason)

    ports = ports_for(asset.ref)
    emit("discovery.started", f"Probing {asset.ref} on {len(ports)} allow-listed ports", data={"host": asset.ref, "ports": ports})
    d = Discovery(host=asset.ref)
    from ..models import now_iso

    d.started_at = now_iso()
    results = await asyncio.gather(*(_probe(asset.ref, p) for p in ports), return_exceptions=True)
    for r in results:
        if isinstance(r, Service):
            d.services.append(r)
    d.finished_at = now_iso()
    audit("discovery.finished", target=f"host:{asset.ref}",
          details={"open": [s.port for s in d.open], "probed": len(ports)})
    emit("discovery.finished", f"{asset.ref}: {len(d.open)} open port(s) {[s.port for s in d.open]}",
         level="success" if d.open else "info", data=d.to_dict())
    return d


def url_for(host: str, svc: Service) -> str | None:
    """The base URL a discovered web service answers on (for handing to ZAP)."""
    if not svc.scheme or svc.status is None:
        return None
    default = (svc.scheme == "http" and svc.port == 80) or (svc.scheme == "https" and svc.port == 443)
    return f"{svc.scheme}://{host}" + ("" if default else f":{svc.port}")


def hostname_resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


__all__ = ["Discovery", "Service", "discover", "url_for", "ports_for", "hostname_resolves"]