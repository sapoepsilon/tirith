"""Re-run the finding's own scanner rule on the changed files (before vs after the patch).

Every scanner is a CLI on PATH: it runs on the staged directory directly (no bind mount, no
container). Report paths are the staged files as the tool prints them -- absolute, since the tools
are handed an absolute path -- so matching strips the stage prefix instead of a `/src/` mount point."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import config as _config
from . import core
from .core import Finding
from .sh import run

# Inline suppression markers a patch must never add (they would make the rescan report "gone").
SUPPRESSION_RE = re.compile(
    r"nosemgrep|gitleaks:allow|\bnosec\b|trivy:ignore|NOSONAR|lgtm\s*\[|codeql\[|eslint-disable|"
    r"pragma:\s*allowlist|detect-secrets|noinspection", re.I)


def added_suppressions(diff: str) -> list[str]:
    """Added diff lines that carry a scanner-suppression marker."""
    return [ln[1:].strip()[:120] for ln in diff.splitlines()
            if ln.startswith("+") and not ln.startswith("+++") and SUPPRESSION_RE.search(ln)]


@dataclass
class RescanResult:
    tool: str
    before_present: bool | None
    after_present: bool | None
    detail: str = ""
    remaining: list[str] = field(default_factory=list)  # other findings of the same rule family still present

    @property
    def gone(self) -> bool:
        """Fixed only when the rule fired BEFORE the patch and no longer fires after it.
        An absent/unknown `before` proves nothing (wrong rule, scanner error), so it never passes."""
        return self.before_present is True and self.after_present is False

    def summary(self) -> str:
        b = {True: "present", False: "absent", None: "n/a"}[self.before_present]
        a = {True: "STILL PRESENT", False: "gone", None: "n/a"}[self.after_present]
        return f"{self.tool} rescan of changed files: before={b}, after={a}. {self.detail}".strip()


def _stage(files: dict[str, bytes]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="rescan-", dir=core.work_root()))
    os.chmod(d, 0o755)
    for rel, data in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return d


def _trivy(d: Path) -> dict | None:
    r = run([_config.BIN["trivy"], "fs", "--scanners", "vuln", "--format", "json", "--quiet", str(d)], timeout=600)
    try:
        return json.loads(r.out)
    except json.JSONDecodeError:
        return None


def _rel(path: str) -> str:
    """A report path as the staged tree sees it: absolute (`/tmp/rescan-x/a.py`) or `./`-prefixed
    paths become tree-relative; a legacy `/src/` mount prefix is dropped too."""
    p = path.removeprefix("/src/")
    if p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p.rsplit("/rescan-", 1)[-1].split("/", 1)[-1] if "/rescan-" in p else p.lstrip("/")
    return p


def _target_ids(f: Finding) -> set[str]:
    """Advisory ids the fix must clear. Grouped finding: the advisories its chosen fixed_version
    resolves (all of them when no version was chosen); per-advisory finding: its own id."""
    if not f.advisories:
        return {f.rule_id}
    from .deps import in_affected_range

    ids = {a.id for a in f.advisories
           if f.fixed_version and a.fixed_version and not in_affected_range(f.fixed_version, a.fixed_version)[0]}
    return ids or {a.id for a in f.advisories}


def _trivy_hits(data: dict | None, f: Finding) -> tuple[bool | None, list[str]]:
    if data is None:
        return None, []
    want = _target_ids(f)
    present, same_pkg = False, []
    for res in data.get("Results") or []:
        if f.file and _rel(res.get("Target") or "") not in (f.file, ""):
            continue
        for v in res.get("Vulnerabilities") or []:
            if (v.get("PkgName") or "").lower() != (f.package or "").lower():
                continue
            same_pkg.append(f"{v.get('VulnerabilityID')} ({v.get('Severity')}, fixed {v.get('FixedVersion')})")
            if v.get("VulnerabilityID") in want:
                present = True
    return present, same_pkg


def _semgrep(d: Path, rule_id: str) -> dict | None:
    """Run just the finding's registry rule; fall back to the core's rule packs."""
    for cfgs in ([f"r/{rule_id}"], [c.strip() for c in _config.SEMGREP_CONFIGS if c.strip()]):
        args = [_config.BIN["semgrep"], "scan"]
        for c in cfgs:
            args += ["--config", c]
        # --disable-nosem: a `# nosemgrep` comment added by the patch must not hide the finding.
        args += ["--json", "--metrics=off", "--disable-version-check", "--disable-nosem", "--quiet", str(d)]
        r = run(args, timeout=600)
        try:
            data = json.loads(r.out)
        except json.JSONDecodeError:
            continue
        if r.rc in (0, 1):
            return data
    return None


def _semgrep_hits(data: dict | None, f: Finding) -> bool | None:
    if data is None:
        return None
    for r in data.get("results") or []:
        path = _rel(r.get("path") or "")
        if r.get("check_id") == f.rule_id and (not f.file or path == f.file):
            return True
    return False


def _gitleaks(d: Path) -> list | None:
    out = Path(tempfile.mkdtemp(prefix="gl-", dir=core.work_root()))
    os.chmod(out, 0o777)
    run([_config.BIN["gitleaks"], "dir", ".", "--report-format", "json", "--report-path", str(out / "r.json"),
         "--redact", "--no-banner", "--ignore-gitleaks-allow", "--exit-code", "0"], cwd=d, timeout=300)
    try:
        return json.loads((out / "r.json").read_text() or "[]")
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        shutil.rmtree(out, ignore_errors=True)


def _gitleaks_hits(data: list | None, f: Finding) -> bool | None:
    if data is None:
        return None
    return any(x.get("RuleID") == f.rule_id and _rel(x.get("File") or "") == f.file for x in data)


def _files_at(repo: Path, rev: str | None, paths: list[str]) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in paths:
        if rev is None:
            fp = repo / p
            if fp.is_file():
                out[p] = fp.read_bytes()
        else:
            r = git(["show", f"{rev}:{p}"], cwd=repo)
            if r.ok:
                out[p] = r.out.encode()
    return out


def rescan(f: Finding, repo: Path, base_rev: str, changed: list[str]) -> RescanResult:
    """Run f.tool on the changed files at base_rev (before) and in the working tree (after)."""
    paths = sorted(set(changed + ([f.file] if f.file else [])))
    before_dir = _stage(_files_at(repo, base_rev, paths))
    after_dir = _stage(_files_at(repo, None, paths))
    try:
        if f.tool == "trivy":
            b, _ = _trivy_hits(_trivy(before_dir), f)
            a, remaining = _trivy_hits(_trivy(after_dir), f)
            detail = f"{f.package}: {len(remaining)} advisories remain after the bump" + (f" ({', '.join(remaining[:5])})" if remaining else "")
            return RescanResult("trivy", b, a, detail, remaining)
        if f.tool == "semgrep":
            return RescanResult("semgrep", _semgrep_hits(_semgrep(before_dir, f.rule_id), f), _semgrep_hits(_semgrep(after_dir, f.rule_id), f),
                                f"rule {f.rule_id}")
        if f.tool == "gitleaks":
            return RescanResult("gitleaks", _gitleaks_hits(_gitleaks(before_dir), f), _gitleaks_hits(_gitleaks(after_dir), f),
                                f"rule {f.rule_id}")
        return RescanResult(f.tool, None, None, f"no file-level rescan for {f.tool}")
    finally:
        shutil.rmtree(before_dir, ignore_errors=True)
        shutil.rmtree(after_dir, ignore_errors=True)
