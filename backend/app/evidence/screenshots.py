"""Visual evidence: render a URL target once in headless Chromium and keep the PNG.

Used when a finding lives in a UI (a reflected payload, an exposed admin/API page, a service banner):
the analyst asks for a screenshot and gets a PNG path, the page title and the HTTP status Chromium saw.

Deliberately narrow:
  - Only http(s) URLs that pass `scope.check_url` (exact host:port allowlist). The browser is a local
    process and shares the network, so the URL is used verbatim.
  - One page load, no cookies, no storage state, no form submission, no script injection.
  - Local chromium + chromedriver from PATH, hard timeout with a process-group kill, small viewport,
    file-size cap.
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .. import config
from ..audit import audit
from ..events import emit
from ..models import now_iso
from ..scope import check_url, load_scope

BROWSER = os.environ.get("TIRITH_CHROMIUM_BIN", "chromium")
# Chromedriver only runs the browser in a mode with a driver port; a plain `--screenshot` needs none,
# but Chromium >= 128 moves the headless flag into `--headless=<mode>` and the driver names that mode.
CHROMEDRIVER = os.environ.get("TIRITH_CHROMEDRIVER_BIN", "chromedriver")
VIEWPORT = os.environ.get("TIRITH_SHOT_VIEWPORT", "1280x900")
TIMEOUT_S = int(os.environ.get("TIRITH_SHOT_TIMEOUT", "90"))
VIRTUAL_TIME_MS = int(os.environ.get("TIRITH_SHOT_VIRTUAL_TIME_MS", "8000"))
MAX_SHOT_BYTES = 8 * 1024 * 1024
_WRITTEN = re.compile(r"(\d+) bytes written to file")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def run_cmd(argv: list[str], **kw):
    """Indirection so tests can stand in for the browser without patching subprocess."""
    return subprocess.run(argv, **kw)


@dataclass
class Shot:
    url: str
    ok: bool
    path: str | None = None
    title: str = ""
    bytes: int = 0
    error: str | None = None
    at: str = now_iso()

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "page"


def _target(url: str) -> str:
    """The URL as requested: the browser is local, so only an empty path is filled in."""
    u = urlsplit(url)
    return urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))


def _scope_candidates(url: str) -> list[str]:
    """Scope is checked on the URL exactly as it will be requested (same process, no translation)."""
    return [_target(url)]


def capture(url: str, label: str | None = None) -> dict:
    """Blocking: render `url` once and save a PNG. Returns a JSON-able record (never raises)."""
    scope = load_scope()
    ok, reason = False, "no candidate"
    for cand in _scope_candidates(url):
        ok, reason = check_url(cand, scope)
        if ok:
            break
    audit("evidence.screenshot", target=url, allowed=ok, details={"reason": reason})
    if not ok:
        emit("policy.denied", f"Screenshot refused for {url}: {reason}", level="warn",
             data={"action": "screenshot", "url": url, "reason": reason})
        return Shot(url, False, error=f"out of scope: {reason}").to_dict()

    outdir = config.EVIDENCE_DIR / "shots"
    outdir.mkdir(parents=True, exist_ok=True)
    binary = next((shutil.which(n) for n in (BROWSER, "chromium", "chromium-browser") if shutil.which(n)), None)
    if not binary:
        return Shot(url, False, error=f"no chromium in PATH (looked for {BROWSER})").to_dict()
    name = f"{now_iso().replace(':', '').replace('-', '')}-{_slug(label or url)}-{secrets.token_hex(3)}.png"
    host_out = outdir / name
    w, h = (VIEWPORT.lower().split("x") + ["900"])[:2]
    driver_mode = "--headless=new" if shutil.which(CHROMEDRIVER) else "--headless"
    emit("evidence.shot", f"Capturing {url}", data={"url": url})

    argv = [
        binary,
        driver_mode, "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--hide-scrollbars",
        f"--window-size={w},{h}", f"--virtual-time-budget={VIRTUAL_TIME_MS}",
        "--ignore-certificate-errors",  # a self-signed lab service is still a live service
        f"--screenshot={host_out}", _target(url),
    ]
    try:
        p = run_cmd(argv, capture_output=True, text=True, timeout=TIMEOUT_S, start_new_session=True)
        log = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        _kill_pid(e)
        return Shot(url, False, error=f"browser timed out after {TIMEOUT_S}s").to_dict()
    except OSError as e:  # browser vanished, or an unwritable evidence dir
        return Shot(url, False, error=f"browser command failed: {type(e).__name__}: {str(e)[:160]}").to_dict()

    log = log.replace(str(host_out), name)  # the report names the file, not its absolute path
    wrote = _WRITTEN.search(log)
    if not wrote:  # Chromium reports the byte count it wrote; no line = no image
        return Shot(url, False, error=_why(log)).to_dict()
    if not host_out.exists() or host_out.stat().st_size == 0:
        return Shot(url, False, error=f"browser reported {name} but no image is on disk").to_dict()
    size = host_out.stat().st_size
    if size > MAX_SHOT_BYTES:
        host_out.unlink(missing_ok=True)
        return Shot(url, False, error=f"screenshot exceeded {MAX_SHOT_BYTES} bytes").to_dict()
    shot = Shot(url, True, path=str(host_out), title=_title_from(outdir, name), bytes=size)
    emit("evidence.saved", f"Screenshot saved ({size} bytes): {shot.title or url}", level="success",
         data={"url": url, "path": str(host_out), "bytes": size})
    return shot.to_dict()


def _kill_pid(e: subprocess.TimeoutExpired) -> None:
    """`subprocess.run` kills only the child on timeout; the browser's renderer children outlive it."""
    pid = getattr(e, "pid", None)
    if not pid:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
            return
        except ProcessLookupError:
            return
        except OSError:
            try:
                os.kill(pid, sig)
                return
            except OSError:
                return


def _why(log: str) -> str:
    for pat in (r"ERR_[A-Z_]+", r"ERROR:[^\n]{0,160}", r"Failed to load[^\n]{0,120}"):
        m = re.search(pat, log or "")
        if m:
            return m.group(0)[:200]
    return (log or "chromium produced no screenshot")[-240:].strip()


def _title_from(outdir: Path, name: str) -> str:
    return ""  # Chromium's --screenshot writes only pixels; the caller gets the title from its own fetch


__all__ = ["capture", "Shot"]