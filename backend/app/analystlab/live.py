"""Reproduce against the service the owner named, at its own address.

The lab copy stays the default for code assets: it is the branch and it is disposable. It is also
expensive. A live service the owner already runs is cheaper and more honest for "does this actually
work here". The cost is that a probe hits real data.

A live handle is a `LabRef` whose `variant` is `live` and whose `(host, port)` is the service's own
address (loopback for a guest-local service), with `container` left blank: the request client runs right
here and the destination is the same string. The whole acceptance test is that the port answers a
connect -- nothing else is contactable through this module, and no owner service is ever narrowed to a
container.

Explicit LAN URLs use their requested address after an allowlist check. Aliases grant permission
only while their canonical entry remains listed; they never rewrite the destination.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

from ..analystlab import http
from ..analystlab import copies
from ..analystlab.lab import LabRef
from ..scope import check_url

# Every loopback spelling collapses to the one connect target.
LOOPBACKS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")
LIVE_PREFIX = "live:"


def is_live(ref: LabRef) -> bool:
    return ref.variant == "live"


PORT_RE = re.compile(r"^(\d{1,5})$")


def _local_address(host: str) -> str:
    if host in LOOPBACKS:
        return "127.0.0.1"
    return host



def _with_scheme(url: str) -> str:
    return url if "://" in url else "http://" + url


def resolve_local(host: str) -> bool:
    """Does `host` address this machine? Raises nothing; fails closed (an unresolvable name is off-box)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback:
            return True
        try:
            with socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((str(ip), 9))  # a UDP connect sends nothing
                return s.getsockname()[0] == str(ip)
        except OSError:
            return False
    try:
        return host in {socket.gethostname(), socket.getfqdn()} or any(
            a[4][0] == host for a in socket.getaddrinfo(host, None))
    except OSError:
        return False


def always_served(url: str) -> bool:
    """True when `url` can only be reached at its own address: guest loopback, or any off-box address.
    A bare unqualified name (`ref`, `lab:5006`) may still be a copy and keeps the copy path."""
    host = url_host_of(url)
    if not host:
        return False
    if "." in host or host == "localhost":
        return host == "127.0.0.1" or not resolve_local(host)
    return False


def url_host_of(url: str) -> str:
    return urlsplit(_with_scheme(url)).hostname or ""


def live_ref(url: str) -> LabRef:
    """Build a live handle for an asset URL. Raises `http.RequestRefused` with a readable why."""
    from ..scope import load_scope

    ok, reason = check_url(url, load_scope())
    if not ok:
        raise http.RequestRefused(reason)
    parts = urlsplit(_with_scheme(url))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not PORT_RE.match(str(port)):
        raise http.RequestRefused(f"{url!r} has no usable port")
    raw_host = parts.hostname or "127.0.0.1"
    host = _local_address(raw_host)
    if not copies.waits(host, port):
        if resolve_local(host):
            raise http.RequestRefused(f"{host}:{port} does not answer a connect; the service must be running "
                                      f"on this guest")
        via = "" if host == url_host_of(url) else f" (from {url_host_of(url)}, the scoped address)"
        raise http.RequestRefused(f"{host}:{port}{via} does not answer a connect; is the service up, and is "
                                  f"whatever publishes it (host port forward, container) running?")
    ref = LabRef(handle=f"{LIVE_PREFIX}{raw_host}:{port}", variant="live", host=host, port=port)
    r = http.request(ref, "GET", "/", label="live reachability")
    for _ in range(3):  # a fresh connect can be refused twice before the listener's backlog settles
        if r.status:
            break
        r = http.request(ref, "GET", "/", label="live reachability (retry)")
    if not 200 <= r.status < 500:
        raise http.RequestRefused(
            f"GET {ref.app_url}/ answered {'no answer' if not r.status else r.status}"
            f"{' (' + r.error[:120] + ')' if r.error else ''}")
    ref.verified_at = "live"
    ref.checks = ["port-answers", "reachability"]
    return ref


def container_of(ref: LabRef) -> str:
    """The container the exec runs in, or "" for a local client (every handle now, since a live handle
    has no container and a copy may be a native process)."""
    return ref.container
