"""Asset workdirs: local paths as-is, GitHub repos cloned into TIRITH_DATA_DIR/clones."""

from __future__ import annotations

import asyncio
import base64
import os
import shutil
import threading
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import AsyncIterator, Iterator

from . import config
from .models import Asset

GIT_TIMEOUT = 300  # seconds per git command
CLONE_LOCK_POLL = 0.1  # seconds between non-blocking lock attempts on the event loop


class CloneError(RuntimeError):
    pass


def norm_ref(ref: str) -> str:
    """GitHub owner/name are case-insensitive: one clone (and one lock) per repo."""
    return ref.strip().strip("/").removesuffix(".git").lower()


def clone_dir(ref: str) -> Path:
    owner, name = norm_ref(ref).split("/", 1)
    return config.CLONES_DIR / f"{owner}__{name}"


def workdir_for(asset: Asset) -> Path | None:
    """Host path of the asset's source tree (no network). None for url assets."""
    if asset.kind == "local_path":
        return Path(os.path.realpath(asset.ref))
    if asset.kind == "github_repo":
        return clone_dir(asset.ref)
    return None


# --------------------------------------------------------------------------- per-ref locks
# threading.Lock (not asyncio.Lock): ensure_clone is also driven from worker threads with their
# own event loops (remediation core), so the lock must be shared across threads and loops.
_ref_locks: dict[str, threading.Lock] = {}
_ref_locks_guard = threading.Lock()


def _lock_for(ref: str) -> threading.Lock:
    key = norm_ref(ref)
    with _ref_locks_guard:
        return _ref_locks.setdefault(key, threading.Lock())


@contextmanager
def clone_lock(ref: str) -> Iterator[None]:
    """Blocking (thread) form: hold while reading/modifying the shared clone of `ref`."""
    lk = _lock_for(ref)
    with lk:
        yield


@asynccontextmanager
async def clone_lock_async(ref: str) -> AsyncIterator[None]:
    """Event-loop form of the same lock. Polls non-blocking so cancellation never leaks the lock."""
    lk = _lock_for(ref)
    while not lk.acquire(blocking=False):
        await asyncio.sleep(CLONE_LOCK_POLL)
    try:
        yield
    finally:
        lk.release()


# --------------------------------------------------------------------------- git
def _git_env(token: str | None) -> dict[str, str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if token:
        # Passed via env-config (not argv) so it never shows in `ps` or logs.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        })
    return env


async def _git(args: list[str], token: str | None, cwd: Path | None = None, timeout: int = GIT_TIMEOUT) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", *args, cwd=str(cwd) if cwd else None, env=_git_env(token),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        if isinstance(e, asyncio.CancelledError):
            raise
        return -1, f"git {args[0]} timed out after {timeout}s"
    msg = (err or out).decode(errors="replace").strip()
    if token:
        msg = msg.replace(token, "***")
    return proc.returncode or 0, msg[-400:]


async def _git_net(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Network git command: public first, then token auth if one is available."""
    rc, msg = await _git(args, None, cwd=cwd)
    if rc != 0:
        tok = config.github_token()
        if tok:
            rc, msg = await _git(args, tok, cwd=cwd)
    return rc, msg


async def _sync_existing(dest: Path) -> None:
    """fetch + hard reset to origin's default branch; raises CloneError on any failure."""
    rc, msg = await _git_net(["fetch", "--quiet", "--prune", "origin"], cwd=dest)
    if rc != 0:
        raise CloneError(f"fetch failed: {msg}")
    rc, msg = await _git_net(["remote", "set-head", "origin", "--auto"], cwd=dest)
    if rc != 0:
        raise CloneError(f"could not determine default branch: {msg}")
    rc, head = await _git(["rev-parse", "--abbrev-ref", "origin/HEAD"], None, cwd=dest)
    if rc != 0 or not head.startswith("origin/"):
        raise CloneError(f"could not resolve origin/HEAD: {head}")
    branch = head.removeprefix("origin/").strip()
    for args in (["checkout", "--quiet", "--force", "-B", branch, f"origin/{branch}"],
                 ["reset", "--quiet", "--hard", f"origin/{branch}"],
                 ["clean", "-qffdx"]):
        rc, msg = await _git(args, None, cwd=dest)
        if rc != 0:
            raise CloneError(f"git {args[0]} failed: {msg}")


async def _fresh_clone(url: str, dest: Path) -> None:
    """Clone into a temp dir and rename into place; partial clones are always removed."""
    tmp = dest.with_name(f"{dest.name}.tmp-{uuid.uuid4().hex[:8]}")
    try:
        rc, msg = await _git_net(["clone", "--quiet", url, str(tmp)])
        if rc != 0:
            raise CloneError(f"clone failed: {msg}" + ("" if config.github_token() else " (public, no token available)"))
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        tmp.rename(dest)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


async def ensure_clone(asset: Asset) -> Path:
    """Clone, or fetch + reset to origin's default branch, a github_repo asset.

    Raises CloneError when the tree cannot be brought to the remote state: a scan must never
    silently run on a stale or half-written checkout.
    """
    ref = norm_ref(asset.ref)
    dest = clone_dir(ref)
    url = f"https://github.com/{ref}.git"
    config.CLONES_DIR.mkdir(parents=True, exist_ok=True)
    async with clone_lock_async(ref):
        git_dir = dest / ".git"
        if git_dir.is_dir():
            await _sync_existing(dest)
            return dest
        if dest.exists():  # leftover partial / corrupt checkout
            shutil.rmtree(dest, ignore_errors=True)
        await _fresh_clone(url, dest)
        return dest
