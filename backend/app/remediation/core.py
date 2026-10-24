"""Thin adapter over the backend core (store, events, audit, scope, config).

Everything in `remediation/` talks to the core only through these functions so the
wiring stays in one place. The models are the CONTRACT.md models from `app.models`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from .. import config as _config
from ..audit import audit as _audit
from ..events import emit as _emit
from ..models import (  # noqa: F401  (re-exported for the rest of the package)
    Asset,
    Evidence,
    Finding,
    Fix,
    FixVerification,
    ModeSettings,
    Validation,
    now_iso,
)
from ..scope import check_github_repo, load_scope
from ..store import get_store

log = logging.getLogger("tirith.remediation")

MODE_ORDER = {"observe": 0, "assisted": 1, "autonomous": 2}


# --------------------------------------------------------------------------- paths
def data_dir() -> Path:
    return _config.DATA_DIR


def work_root() -> Path:
    p = _config.DATA_DIR / "remediation"
    p.mkdir(parents=True, exist_ok=True)
    return p


def evidence_dir() -> Path:
    p = _config.EVIDENCE_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def github_token() -> str | None:
    """Never log the return value."""
    return _config.github_token()


# --------------------------------------------------------------------------- events / audit
def emit(type: str, message: str, level: str = "info", **kw: Any) -> None:
    try:
        _emit(type, message, level=level, **kw)
    except Exception:  # events must never break remediation
        log.exception("emit failed")


def audit(action: str, target: str | None = None, allowed: bool = True, details: dict | None = None,
          actor: str = "remediation") -> None:
    try:
        _audit(action, target=target, allowed=allowed, actor=actor, details=details)
    except Exception:
        log.exception("audit failed")


# --------------------------------------------------------------------------- store
def get_finding(finding_id: str) -> Finding | None:
    return get_store().get_finding(finding_id)


def update_finding(finding_id: str, **fields: Any) -> Finding | None:
    return get_store().update_finding(finding_id, **fields)


def list_findings(**kw: Any) -> list[Finding]:
    return get_store().list_findings(**kw)


def get_asset(asset_id: str) -> Asset | None:
    return get_store().get_asset(asset_id)


def save_validation(v: Validation) -> Validation:
    return get_store().save_validation(v)


def save_fix(fx: Fix) -> Fix:
    return get_store().save_fix(fx)


def get_fix(fix_id: str) -> Fix | None:
    return get_store().get_fix(fix_id)


def get_mode() -> ModeSettings:
    return get_store().get_mode()


def fix_meta(fix_id: str) -> dict:
    raw = get_store().get_kv(f"remediation:fix:{fix_id}")
    return json.loads(raw) if raw else {}


def set_fix_meta(fix_id: str, **fields: Any) -> dict:
    meta = {**fix_meta(fix_id), **fields}
    get_store().set_kv(f"remediation:fix:{fix_id}", json.dumps(meta))
    return meta


# --------------------------------------------------------------------------- source trees
def source_dir(asset: Asset) -> Path | None:
    """Host path of the asset's source tree; clones github repos via the core if needed."""
    from ..assets import ensure_clone, workdir_for

    p = workdir_for(asset)
    if asset.kind == "github_repo" and (p is None or not (p / ".git").exists()):
        p = _run_async(ensure_clone(asset))
    return p if p and p.exists() else None


def _run_async(coro):
    """Run a coroutine from sync code (we may be on a worker thread or inside a loop)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: dict[str, Any] = {}

    def runner():
        try:
            box["v"] = asyncio.run(coro)
        except BaseException as e:  # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=runner)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box.get("v")


# --------------------------------------------------------------------------- PR target policy
DEFAULT_PR_REPOS = "sapoepsilon/tirith-demo-target"


def pr_allowed_repos() -> list[str]:
    raw = os.environ.get("TIRITH_PR_REPOS", DEFAULT_PR_REPOS)
    return [r.strip().lower() for r in raw.split(",") if r.strip()]


def check_pr_repo(repo: str) -> tuple[bool, str]:
    """A PR may only be opened on a repo that is BOTH in TIRITH_PR_REPOS and in scope.yaml."""
    if (repo or "").lower() not in pr_allowed_repos():
        return False, f"{repo} is not in TIRITH_PR_REPOS ({', '.join(pr_allowed_repos())})"
    ok, reason = check_github_repo(repo, load_scope())
    return ok, reason


def pr_repo_for(asset: Asset) -> str | None:
    """Which GitHub repo receives fix PRs for this asset.

    github_repo assets use their own ref. local_path assets (e.g. targets/pygoat, whose
    `origin` is the UPSTREAM project) never use their git remote; they use TIRITH_FIX_REPO
    (default: the demo fork).
    """
    if asset.kind == "github_repo":
        return asset.ref
    if asset.kind == "local_path":
        return os.environ.get("TIRITH_FIX_REPO", DEFAULT_PR_REPOS)
    return None


def record_posture(asset_id: str | None) -> None:
    try:
        from .. import posture

        posture.record(asset_id)
    except Exception:
        log.exception("posture update failed")
