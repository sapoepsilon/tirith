"""Per-tool process invocations. Each returns ToolOutput(raw JSON/XML or None, error).

Every tool is a CLI in PATH and runs in its own process group (see .docker.run_process); source
scanners run with cwd = the scanned tree so their reports carry relative paths.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from ..models import Asset
from .docker import run_process
from .normalize import rel_path


@dataclass
class ToolOutput:
    raw: Any = None
    error: str | None = None
    skipped_reason: str | None = None
    partial_files: set[str] = field(default_factory=set)  # repo-relative files not fully analyzed


@dataclass
class LabTarget:
    url: str
    network: str | None = None  # docker network of the lab copy, when it runs as a container


def get_lab_target(asset: Asset) -> LabTarget | str | None:
    """HOOK for the lab module: return the URL (and, for a container lab, its docker network) where
    `asset` is deployed inside the isolated lab, so ZAP baseline can run against it. None until implemented.

    The lab module may monkeypatch/replace this (e.g. `app.scanners.tools.get_lab_target = fn`);
    the scan runner looks it up at call time.
    """
    return None


def get_lab_session(lab: Any) -> dict[str, str]:
    """HOOK for the lab module: logged-in session cookies ({name: value}) for a lab target returned
    by get_lab_target, so ZAP spiders the app as a signed-in test user. {} = unauthenticated."""
    return {}


def get_lab_seeds(lab: Any) -> list[str]:
    """HOOK for the lab module: extra same-origin start paths (e.g. ["/xss", "/sql"]) for ZAP's
    crawl of a lab target. [] = spider from the target URL only."""
    return []


def _tail(s: str, n: int = 600) -> str:
    s = (s or "").strip()
    return s[-n:]


# Tirith-owned scanner configuration (never the scanned repository's).
CONFIG_DIR = Path(__file__).parent / "config"
NO_SEMGREPIGNORE = ".tirith-no-semgrepignore"  # a name no repository ships

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_GITLEAKS_ERR = re.compile(r"^\s*(?:\S+\s+)?(ERR|FTL|ERROR|FATAL)\b", re.M)
_TRIVY_ERR = re.compile(r"^\S+\s+(ERROR|FATAL)\b", re.M)


def _cfg(name: str) -> str:
    return str(CONFIG_DIR / name)


def semgrep_excludes() -> list[str]:
    try:
        lines = (CONFIG_DIR / "semgrep-exclude.txt").read_text().splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def error_lines(stderr: str, pat: re.Pattern) -> list[str]:
    """stderr lines that the tool logged at error/fatal level (ANSI colors stripped)."""
    text = _ANSI.sub("", stderr or "")
    return [ln.strip() for ln in text.splitlines() if pat.search(ln)]


def _run_failure(tool: str, r) -> str | None:
    if r.timed_out or r.truncated:
        return f"{tool}: {r.stderr}"
    return None


def semgrep_args(target: str = ".") -> list[str]:
    args = [config.BIN["semgrep"], "scan"]
    for c in config.SEMGREP_CONFIGS:
        if c.strip():
            args += ["--config", c.strip()]
    for pat in semgrep_excludes():
        args.append(f"--exclude={pat}")
    args += ["--disable-nosem", f"--x-semgrepignore-filename={NO_SEMGREPIGNORE}",
             "--json", "--metrics=off", "--disable-version-check", "--quiet", target]
    return args


def semgrep_problems(data: dict, rc: int) -> tuple[str | None, set[str]]:
    """(fatal error or None, repo-relative files the run could not fully analyze)."""
    partial: set[str] = set()
    fatal: list[str] = []
    for e in data.get("errors") or []:
        if not isinstance(e, dict):
            continue
        path = e.get("path") or next((s.get("file") for s in e.get("spans") or [] if isinstance(s, dict) and s.get("file")), None)
        if path:
            partial.add(rel_path(path))
        elif str(e.get("level", "error")).lower() == "error":
            fatal.append(str(e.get("message") or e.get("type") or "error")[:200])
    if rc not in (0, 1):
        fatal.append(f"exit code {rc}")
    return ("; ".join(fatal) if fatal else None), partial


async def run_semgrep(src: Path, _name: str = "") -> ToolOutput:
    r = await run_process(semgrep_args(), cwd=src, timeout=config.SCAN_TIMEOUT)
    if err := _run_failure("semgrep", r):
        return ToolOutput(error=err)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return ToolOutput(error=f"semgrep rc={r.returncode}: {_tail(r.stderr) or _tail(r.stdout)}")
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return ToolOutput(error=f"semgrep rc={r.returncode}: report has no results list")
    fatal, partial = semgrep_problems(data, r.returncode)
    if fatal:
        return ToolOutput(error=f"semgrep: {fatal}")
    return ToolOutput(raw=data, partial_files=partial)


def gitleaks_mode(src: Path) -> str:
    """git mode only for a real .git directory (not a worktree/submodule file or a symlink)."""
    g = src / ".git"
    return "git" if g.is_dir() and not g.is_symlink() else "dir"


def gitleaks_args(mode: str) -> list[str]:
    # The report goes to stdout (never to disk): it carries raw secret values, which the
    # normalizer only hashes into the fingerprint and masks out of snippets.
    return [config.BIN["gitleaks"], mode, ".", "--config", _cfg("gitleaks.toml"),
            "--gitleaks-ignore-path", str(CONFIG_DIR),
            "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", "-",
            "--no-banner", "--no-color", "--exit-code", "0"]


async def run_gitleaks(src: Path, _outdir: Path | None = None, _name: str = "") -> ToolOutput:
    r = await run_process(gitleaks_args(gitleaks_mode(src)), cwd=src, timeout=config.SCAN_TIMEOUT)
    if err := _run_failure("gitleaks", r):
        return ToolOutput(error=err)
    errs = error_lines(r.stderr, _GITLEAKS_ERR)
    if r.returncode != 0 or errs:
        return ToolOutput(error=f"gitleaks rc={r.returncode}: {_tail(chr(10).join(errs) or r.stderr)}")
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        # never echo stdout: it may contain secrets
        return ToolOutput(error="gitleaks report missing or unreadable")
    if not isinstance(data, list):
        return ToolOutput(error="gitleaks report is not a list")
    return ToolOutput(raw=data)


def trivy_args() -> list[str]:
    return [config.BIN["trivy"], "fs", "--config", _cfg("trivy.yaml"), "--ignorefile", _cfg("trivyignore"),
            "--scanners", "vuln,misconfig", "--format", "json", "--no-progress", "."]


async def run_trivy(src: Path, _name: str = "") -> ToolOutput:
    r = await run_process(trivy_args(), cwd=src, timeout=config.SCAN_TIMEOUT)
    if err := _run_failure("trivy", r):
        return ToolOutput(error=err)
    errs = error_lines(r.stderr, _TRIVY_ERR)
    if r.returncode != 0 or errs:
        return ToolOutput(error=f"trivy rc={r.returncode}: {_tail(chr(10).join(errs) or r.stderr)}")
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return ToolOutput(error=f"trivy rc={r.returncode}: {_tail(r.stderr) or _tail(r.stdout)}")
    if not isinstance(data, dict):
        return ToolOutput(error="trivy report is not an object")
    return ToolOutput(raw=data)


# --------------------------------------------------------------------------- host scanners
def nmap_args(host: str) -> list[str]:
    """Connect scan to stdout as XML; `-Pn` is implicit because a host asset was already probed."""
    return [config.BIN["nmap"], *config.NMAP_ARGS, "-oX", "-", "--", host]


async def run_nmap(host: str, _name: str = "") -> ToolOutput:
    r = await run_process(nmap_args(host), timeout=config.SCAN_TIMEOUT)
    if err := _run_failure("nmap", r):
        return ToolOutput(error=err)
    if r.returncode != 0 or "<nmaprun" not in r.stdout:
        return ToolOutput(error=f"nmap rc={r.returncode}: {_tail(r.stderr) or _tail(r.stdout)}")
    return ToolOutput(raw=r.stdout)


def nikto_url(host: str, port: int, scheme: str) -> str:
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}" + ("" if default else f":{port}")


def nikto_args(url: str) -> list[str]:
    # -Format json writes to stdout; -ask none never stops for update/continue prompts.
    return [config.BIN["nikto"], "-h", url, "-Format", "json", *config.NIKTO_ARGS]


async def run_nikto(url: str, _name: str = "") -> ToolOutput:
    r = await run_process(nikto_args(url), timeout=config.SCAN_TIMEOUT)
    if err := _run_failure("nikto", r):
        return ToolOutput(error=err)
    start = r.stdout.find("{")
    if start == -1:
        return ToolOutput(error=f"nikto rc={r.returncode}: {_tail(r.stderr) or _tail(r.stdout)}")
    try:
        data = json.loads(r.stdout[start:])
    except json.JSONDecodeError:
        return ToolOutput(error=f"nikto rc={r.returncode}: report unreadable")
    if not isinstance(data, dict):
        return ToolOutput(error="nikto report is not an object")
    return ToolOutput(raw=data)


def container_reachable_url(url: str) -> str:
    """Only for a container target: localhost inside a container is the container itself."""
    from urllib.parse import urlparse

    u = urlparse(url)
    if u.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        netloc = "host.docker.internal" + (f":{u.port}" if u.port else "")
        return urlunparse(u._replace(netloc=netloc))
    return url


# Pages the authenticated spider must not touch: they would end (or re-key) the lab test session.
ZAP_AUTH_EXCLUDE = r".*/(logout|log-out|signout|sign-out|password)[^?]*.*"


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def zap_auth_props(cookies: dict[str, str]) -> str:
    """ZAP -configfile properties: a Replacer rule that sets the lab session Cookie header on every
    request (spider + passive scan), plus a global exclude so the spider never logs itself out."""
    props = {
        "replacer.full_list(0).description": "tirith-lab-session",
        "replacer.full_list(0).enabled": "true",
        "replacer.full_list(0).matchtype": "REQ_HEADER",
        "replacer.full_list(0).matchstr": "Cookie",
        "replacer.full_list(0).regex": "false",
        "replacer.full_list(0).replacement": cookie_header(cookies),
        "globalexcludeurl.url_list.url(0).description": "tirith: keep the lab session alive",
        "globalexcludeurl.url_list.url(0).enabled": "true",
        "globalexcludeurl.url_list.url(0).regex": ZAP_AUTH_EXCLUDE,
    }
    # java.util.Properties: escape backslashes (the regex has none today, keep it safe anyway)
    return "".join(f"{k}={v.replace(chr(92), chr(92) * 2)}\n" for k, v in props.items())


# zap-baseline hook (fixed code, written to the auth dir): after ZAP starts, request each seed path once
# through ZAP (same origin as the target only) so the passive rules see pages the spider can't find.
ZAP_SEED_HOOK = """import json
import sys
from urllib.parse import urlparse


def zap_started(zap, target):
    try:
        with open(sys.argv[sys.argv.index("-Dseed") + 1] if "-Dseed" in sys.argv else "seeds.json") as f:
            seeds = json.load(f)
    except Exception:
        return
    base = target.rstrip("/")
    origin = urlparse(base).netloc
    for p in seeds[:300]:
        url = base + "/" + str(p).lstrip("/")
        if urlparse(url).netloc != origin:
            continue
        try:
            zap.core.access_url(url=url, followredirects="false")
        except Exception:
            pass
"""
SEED_PATH = re.compile(r"/[A-Za-z0-9_./-]{0,200}")


def zap_args(url: str, authenticated: bool, seeded: bool = False, authed: Path | None = None) -> list[str]:
    """Baseline = spider + passive rules only. -I: don't fail on warnings. -m: spider minutes.
    `authed` is the dir holding auth.prop/seed_hook.py for a signed-in / seeded lab run."""
    args = [config.BIN["zap"], "-t", url, "-J", "zap.json", "-I", "-m", "2" if authenticated else "1"]
    if authed is not None:
        if authenticated:
            args += ["-z", f"-configfile {authed / 'auth.prop'}"]
        if seeded:
            args += ["-Dseed", str(authed / "seeds.json"), f"--hook={authed / 'seed_hook.py'}"]
    return args


def _scrub(text: str, cookies: dict[str, str]) -> str:
    for v in cookies.values():
        if v:
            text = text.replace(v, "***")
    return text


async def run_zap(target_url: str, outdir: Path, _name: str = "", network: str | None = None,
                  cookies: dict[str, str] | None = None, seeds: list[str] | None = None) -> ToolOutput:
    """ZAP baseline (passive), run from PATH with cwd = outdir (the report lands there). Lab targets
    only (`network` set: the copy is a container, so the URL needs the container-side host):
    - `cookies`: spider + passively scan as the lab's signed-in test user; the values reach ZAP via a
      properties file next to the output, deleted after the run, and are scrubbed from the report.
    - `seeds`: extra same-origin paths ZAP requests once (GET) so passive rules cover JS-linked pages."""
    outdir.mkdir(parents=True, exist_ok=True)
    report = outdir / "zap.json"
    report.unlink(missing_ok=True)
    cookies = dict(cookies or {}) if network else {}  # never send a lab session anywhere but the lab
    seeds = [p for p in (seeds or []) if SEED_PATH.fullmatch(p) and ".." not in p][:300] if network else []
    url = container_reachable_url(target_url) if network else target_url
    authdir = outdir.parent / f"{outdir.name}-auth"
    files: dict[str, str] = {}
    if cookies:
        files["auth.prop"] = zap_auth_props(cookies)
    if seeds:
        files["seeds.json"] = json.dumps(seeds)
        files["seed_hook.py"] = ZAP_SEED_HOOK
    if files:
        authdir.mkdir(parents=True, exist_ok=True)
        for fname, body in files.items():
            (authdir / fname).write_text(body)
    try:
        r = await run_process(
            zap_args(url, bool(cookies), bool(seeds), authed=authdir if files else None),
            cwd=outdir, timeout=config.SCAN_TIMEOUT,
        )
    finally:
        for fname in files:
            (authdir / fname).unlink(missing_ok=True)
        if files:
            try:
                authdir.rmdir()
            except OSError:
                pass
    if err := _run_failure("zap", r):
        return ToolOutput(error=err)
    if r.returncode not in (0, 1, 2) or not report.exists():  # 3 = zap-baseline internal error
        return ToolOutput(error=f"zap rc={r.returncode}: {_scrub(_tail(r.stdout + r.stderr), cookies)}")
    try:
        text = report.read_text()
        if cookies:
            text = _scrub(text, cookies)
            report.write_text(text)
        data = json.loads(text)
    except (OSError, json.JSONDecodeError) as e:
        return ToolOutput(error=f"zap report unreadable: {e}")
    if not isinstance(data, dict):
        return ToolOutput(error="zap report is not an object")
    return ToolOutput(raw=data)
