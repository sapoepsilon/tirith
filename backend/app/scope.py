"""Scope checks against backend/scope.yaml. Default-deny.

- github_repos: exact `owner/name` entries (case-insensitive). No globs.
- url_hosts: exact `host:port` pairs. A URL without an explicit port uses its scheme default (80/443).
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from . import config
from .audit import audit
from .events import emit

GITHUB_REF_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


@dataclass
class Scope:
    github_repos: list[str] = field(default_factory=list)
    local_paths: list[Path] = field(default_factory=list)
    url_hosts: list[str] = field(default_factory=list)  # "host:port"
    # Aliases that resolve to the same service: {"scoped host:port": ["host:port", ...]} (guest vs. its
    # published host port). An asset created under an alias would otherwise get every live request refused.
    url_aliases: dict[str, list[str]] = field(default_factory=dict)
    host_targets: list[str] = field(default_factory=list)  # "host" or "CIDR" — discovery + active checks
    host_ports: list[int] = field(default_factory=list)  # ports discovery may probe on host_targets
    lab_network: str = "tirith-lab"
    # Per-asset focus/exclude/sub-app defaults: [{match: [globs on ref or name], focus, exclude, sub_apps}]
    asset_profiles: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "github_repos": self.github_repos,
            "local_paths": [str(p) for p in self.local_paths],
            "url_hosts": self.url_hosts,
            "url_aliases": self.url_aliases,
            "host_targets": self.host_targets,
            "host_ports": self.host_ports,
            "lab_network": self.lab_network,
            "asset_profiles": self.asset_profiles,
        }


def load_scope(path: Path | str | None = None) -> Scope:
    p = Path(path or config.SCOPE_FILE).resolve()
    if not p.exists():
        return Scope()
    raw = yaml.safe_load(p.read_text()) or {}
    base = p.parent
    paths = []
    for lp in raw.get("local_paths") or []:
        q = Path(os.path.expanduser(str(lp)))
        if not q.is_absolute():
            q = base / q
        paths.append(Path(os.path.realpath(q)))
    return Scope(
        github_repos=[str(x).strip() for x in raw.get("github_repos") or []],
        local_paths=paths,
        url_hosts=[str(x).strip().lower() for x in raw.get("url_hosts") or []],
        url_aliases={
            str(k).strip().lower(): [str(v).strip().lower() for v in (vs or [])]
            for k, vs in (raw.get("url_aliases") or {}).items() if isinstance(vs, list)
        },
        host_targets=[str(x).strip().lower() for x in raw.get("host_targets") or []],
        host_ports=sorted({int(x) for x in raw.get("host_ports") or [] if str(x).strip().isdigit()}),
        lab_network=str(raw.get("lab_network") or "tirith-lab"),
        asset_profiles=[_profile_entry(x) for x in raw.get("asset_profiles") or [] if isinstance(x, dict)],
    )


def _strs(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def _profile_entry(raw: dict) -> dict:
    return {k: _strs(raw.get(k)) for k in ("match", "focus", "exclude", "sub_apps")}


def check_github_repo(ref: str, scope: Scope) -> tuple[bool, str]:
    if not GITHUB_REF_RE.match(ref or ""):
        return False, f"invalid github ref {ref!r} (expected owner/name)"
    if ".." in ref:
        return False, "invalid github ref"
    for allowed in scope.github_repos:
        if ref.lower() == allowed.lower():
            return True, f"listed as {allowed}"
    return False, f"repo {ref} not in scope allowlist"


def check_local_path(ref: str, scope: Scope) -> tuple[bool, str]:
    if not ref or not os.path.isabs(ref):
        return False, "local_path ref must be an absolute path"
    real = Path(os.path.realpath(ref))
    for root in scope.local_paths:
        if real == root or real.is_relative_to(root):
            return True, f"under {root}"
    return False, f"path {real} not under an allowed local path"


def url_host(ref: str) -> str | None:
    try:
        u = urlparse(ref)
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    return u.hostname.lower()


def url_host_port(ref: str) -> str | None:
    """`host:port` for an http(s) URL (scheme default port when omitted); None if invalid."""
    try:
        u = urlparse(ref)
        port = u.port
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    if port is None:
        port = 443 if u.scheme == "https" else 80
    host = u.hostname.lower()
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def check_url(ref: str, scope: Scope) -> tuple[bool, str]:
    hp = url_host_port(ref)
    if not hp:
        return False, "url must be http(s)://host[:port][...]"
    if hp in scope.url_hosts:
        return True, f"host:port {hp} is listed"
    for host, aliases in scope.url_aliases.items():
        if hp in aliases and host in scope.url_hosts:
            return True, f"host:port {hp} is an alias of the listed {host}"
    return False, f"host:port {hp} not in scope allowlist"


def host_in_scope(host: str, scope: Scope) -> tuple[bool, str]:
    """A host target is allowed when it is listed verbatim or inside a listed CIDR."""
    h = (host or "").strip().lower()
    if not h:
        return False, "empty host"
    for entry in scope.host_targets:
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                ip = ipaddress.ip_address(h)
            except ValueError:
                continue  # a name can never fall inside a CIDR
            if ip in net:
                return True, f"inside {entry}"
        elif h == entry:
            return True, f"listed as {entry}"
    return False, f"host {h} not in host_targets"


def check_host(ref: str, scope: Scope) -> tuple[bool, str]:
    """`ref` for a host asset is a bare hostname or IP (no scheme, port or path)."""
    if not ref or not re.fullmatch(r"[A-Za-z0-9._:-]{1,253}", ref or ""):
        return False, "host ref must be a bare hostname or IP address"
    return host_in_scope(ref, scope)


def check_asset(kind: str, ref: str, scope: Scope | None = None) -> tuple[bool, str]:
    scope = scope or load_scope()
    if kind == "github_repo":
        return check_github_repo(ref, scope)
    if kind == "local_path":
        return check_local_path(ref, scope)
    if kind == "url":
        return check_url(ref, scope)
    if kind == "host":
        return check_host(ref, scope)
    return False, f"unknown asset kind {kind!r}"


def enforce(
    action: str,
    kind: str,
    ref: str,
    actor: str = "api",
    scan_id: str | None = None,
    scope: Scope | None = None,
) -> tuple[bool, str]:
    """Check scope, write audit entry, emit policy.denied on deny. Returns (allowed, reason)."""
    ok, reason = check_asset(kind, ref, scope)
    audit(action, target=f"{kind}:{ref}", allowed=ok, actor=actor, details={"reason": reason})
    if not ok:
        emit(
            "policy.denied",
            f"Denied {action} on {kind} {ref}: {reason}",
            level="warn",
            scan_id=scan_id,
            data={"action": action, "kind": kind, "ref": ref, "reason": reason},
        )
    return ok, reason
