"""Deterministic access-control check on the demo target, and the demo asset/finding.

Separate from `app.remediation.reproduce` (which replays DAST finding URLs and has no second-identity
concept): here the check is a two-identity comparison over the lab handle, the standard control for
broken access control (CWE-639). Evidence is only ever built from a response this process actually
received; the verdict note names the variant that was tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import os

from .. import config
from ..models import Evidence, Finding, Validation, now_iso
from ..store import get_store
from ..scope import enforce
from . import http
from .lab import LabRef

CHECK = "reproduce-access-control"
LOW_USER = "demo-low"
ADMIN_USER = "demo-admin"
DEMO_TAG = "analystlab-demo"
ASSET_NAME = "analyst-lab (intentionally vulnerable training target)"
FLAG_MARKER = "flag{"
FLAG_CONSTANT = "flag{dummy_ctf_flag_analyst_demo_9f3a}"
DEFAULT_PATH = "/flag?as=demo-admin"
CWE = "CWE-639"


class DemoFindingError(RuntimeError):
    pass


def root_dir() -> Path:
    """Target tree location: TIRITH_ANALYST_LAB_DIR (deployment data), else the checkout default."""
    return Path(os.environ.get("TIRITH_ANALYST_LAB_DIR",
                               str(config.BACKEND_DIR.parent / "targets" / "analyst-lab"))).resolve()


def target_dir() -> Path:
    """The demo target's assets are registered against the vulnerable variant directory."""
    return root_dir() / "vulnerable"


def is_demo_target(path: Path) -> bool:
    """True only for the analyst-lab directory itself or a variant under it."""
    try:
        root = root_dir()
        p = Path(path).resolve()
    except OSError:
        return False
    return p == root or p.is_relative_to(root)


def ensure_demo_asset():
    from ..models import Asset

    st = get_store()
    ref = str(target_dir())
    enforce("analystlab.asset", "local_path", ref)
    a = st.find_asset("local_path", ref)
    if a:
        return a
    return st.save_asset(Asset(kind="local_path", ref=ref, name=ASSET_NAME))


def ensure_demo_finding():
    from ..models import Finding as F

    st = get_store()
    asset = ensure_demo_asset()
    fp = f"analystlab:{CWE}:/flag"
    existing = next((f for f in st.list_findings(asset_id=asset.id) if f.fingerprint == fp), None)
    # Seeded fixture, not a scanner detection: the tool/rule ids and the description say so, and the
    # demo scan id is not a real scan row.
    data = dict(
        scan_id="analystlab-fixture", fingerprint=fp, tool="semgrep", rule_id="analystlab-fixture.access-control",
        tags=[DEMO_TAG, "fixture"],
        title="Broken access control: page identity taken from the request, never compared with the caller",
        severity="high", category="sast", file="app.py", line=68, cwe=CWE,
        snippet='who = (query.get("as") or [self._identity()] or ["apprentice"])[0]\nif USERS.get(who) != "admin":',
        url=DEFAULT_PATH, confidence=0.85,
        description=("[seeded fixture, not a scanner result] GET /flag picks its identity from a query parameter "
                     "and never compares it with the authenticated caller, so the low-privilege identity reads the "
                     "admin-only page."),
    )
    if existing:
        return st.update_finding(existing.id, **data) or existing
    stored, _ = st.upsert_finding(F(asset_id=asset.id, **data))
    return stored


@dataclass
class Exchange:
    identity: str
    request: str
    response: http.Response

    @property
    def flag(self) -> bool:
        return FLAG_CONSTANT in (self.response.body or "")

    @property
    def denied(self) -> bool:
        return self.response.status in (401, 403)

    def evidence(self, label: str) -> list[Evidence]:
        return [
            Evidence(kind="request", label=f"{label} request",
                     content=f"GET {self.request} HTTP/1.1\nX-Demo-User: {self.identity}"),
            Evidence(kind="response", label=f"{label} response",
                     content=f"HTTP {self.response.status}\n" + "\n".join(
                         f"{k}: {v}" for k, v in sorted(self.response.headers.items())) +
                             f"\n\n{self.response.body[:1500]}"),
        ]


def _split(path: str, query: dict[str, str] | None) -> tuple[str, dict[str, str]]:
    """`/flag?as=x` in the finding URL becomes (path, query); an explicit query wins."""
    if "?" in path and not query:
        p, _, qs = path.partition("?")
        q = dict(kv.split("=", 1) for kv in qs.split("&") if "=" in kv)
        return p, q
    return path.split("?", 1)[0], dict(query or {})


def exchange(ref: LabRef, identity: str, path: str, query: dict[str, str] | None = None) -> Exchange:
    p, q = _split(path, query)
    r = http.get(ref, p, query=q, as_user=identity, label="access-control check")
    qs = ("?" + "&".join(f"{k}={v}" for k, v in q.items())) if q else ""
    return Exchange(identity=identity, request=f"{p}{qs}", response=r)


def check_access_control(f: Finding, ref: LabRef, *, path: str | None = None) -> Validation:
    """Baseline (low identity, page as found) + bypass attempt from the finding's URL.

    `path` overrides the finding URL with the path the analyst observed (same requested identity)."""
    started = now_iso()
    target = path or (f.url or DEFAULT_PATH)
    evd: list[Evidence] = []
    low = exchange(ref, LOW_USER, target.split("?")[0] if "?" in target else target)
    evd += low.evidence(f"baseline (demo-low, {low.request})")
    variant = f"{ref.variant} container {ref.container}"
    if low.flag:
        return Validation(finding_id=f.id, check=CHECK, result="unsupported", confidence=0.0, evidence=evd + [
            Evidence(kind="note", label="verdict", content=(
                f"On {variant}: the low-privilege baseline already returns the flag, so no difference would "
                "prove anything. Not in the expected state."))], started_at=started, finished_at=now_iso())
    if not low.denied:
        return Validation(finding_id=f.id, check=CHECK, result="not_reproduced", confidence=0.5, evidence=evd + [
            Evidence(kind="note", label="verdict", content=(
                f"On {variant}: baseline answered HTTP {low.response.status}, not 403; the baseline this check "
                "compares against is absent, so no verdict is claimed."))],
            started_at=started, finished_at=now_iso())
    probe = exchange(ref, LOW_USER, target)
    evd += probe.evidence(f"bypass attempt (demo-low, {probe.request})")
    if probe.flag and probe.response.status == 200:
        return Validation(finding_id=f.id, check=CHECK, result="confirmed", confidence=0.95, evidence=evd + [
            Evidence(kind="note", label="verdict", content=(
                f"On {variant}: demo-low gets HTTP 403 on {low.request} and HTTP 200 with the dummy flag on "
                f"{probe.request}. Application authorization bypass (CWE-639) only; not host or shell compromise."))],
            started_at=started, finished_at=now_iso())
    if probe.denied:
        return Validation(finding_id=f.id, check=CHECK, result="not_reproduced", confidence=0.85, evidence=evd + [
            Evidence(kind="note", label="verdict", content=(
                f"On {variant}: the bypass request answered HTTP {probe.response.status} without the flag; the "
                "identity parameter no longer reaches the admin page on this deployment."))],
            started_at=started, finished_at=now_iso())
    return Validation(finding_id=f.id, check=CHECK, result="unsupported", confidence=0.3, evidence=evd + [
        Evidence(kind="note", label="verdict", content=(
            f"On {variant}: bypass attempt answered HTTP {probe.response.status} without the flag and without a "
            "denial; no check result is claimed from this response."))], started_at=started, finished_at=now_iso())


def validate(finding_id: str, ref: LabRef | None, *, observed_path: str | None = None) -> Validation:
    """Shared helper: finding -> demo asset -> check -> stored Validation."""
    st = get_store()
    f = st.get_finding(finding_id)
    if f is None:
        raise DemoFindingError(f"no finding {finding_id}")
    if f.asset_id != ensure_demo_asset().id:
        raise DemoFindingError("the access-control check applies to the analyst-lab demo asset only")
    if ref is None:
        raise DemoFindingError("no demo lab handle available")
    v = check_access_control(f, ref, path=observed_path)
    st.save_validation(v)
    if v.result == "confirmed" and ref.variant == "vulnerable":
        st.update_finding(f.id, status="validated", confidence=max(f.confidence, v.confidence), validation=v)
    elif v.result == "not_reproduced" and ref.variant == "patched":
        st.update_finding(f.id, status="open", confidence=f.confidence,
                          validation=v.model_copy(update={"evidence": v.evidence + [Evidence(
                              kind="note", label="patched recheck",
                              content="Same request denied on the patched twin; the fix closes the bypass but the "
                                     "finding stays open until the vulnerable deployment is replaced.")]}))
    return v


def is_demo_finding(f: Finding) -> bool:
    a = get_store().get_asset(f.asset_id)
    return bool(a and a.kind == "local_path" and is_demo_target(Path(a.ref)) and (f.cwe or "") == CWE
                and DEMO_TAG in (f.tags or []))


__all__ = ["CHECK", "CWE", "DEMO_TAG", "DEFAULT_PATH", "FLAG_CONSTANT", "DemoFindingError",
           "check_access_control", "ensure_demo_asset", "ensure_demo_finding", "exchange", "is_demo_finding",
           "is_demo_target", "target_dir", "validate"]
