"""Fix pipeline: patch -> `git apply --check` on a fresh branch -> verify -> push -> PR -> (merge) -> rollback.

Modes (CONTRACT): observe = fix refused; assisted = open PR, never merge; autonomous = merge only
categories in autonomous_categories (default ["dependency_bump"]) after verification passes,
everything else is escalated (PR left open for a human). Rollback reverts the merge commit via a
revert PR (merged automatically in autonomous mode), or closes the unmerged PR.

Verification:
  (a) rerun the finding's own scanner rule on the changed files (before vs after),
  (b) rebuild + boot the patched app in the lab (guest loopback only),
  (c) run the project's tests (inside the built image, --network none) if present.

Patch safety (applies to every patch, LLM-written or template):
  - After applying, the REAL change set is read back from git (`git diff --raw -z HEAD`, numstat,
    untracked files). Anything other than an in-place, non-binary, same-mode modification of the
    finding's own file (f.file) is refused: deletes, renames, copies, type/mode changes, binary
    patches, new files, or any other path (e.g. a quoted-path diff aimed at .github/workflows).
  - LLM patches are refused outright for build/manifest/CI files and must not add scanner
    suppression markers (nosemgrep, gitleaks:allow, ...).
  - Secret findings never reach the LLM: a fixed template replaces the literal with an env lookup
    (Python only, else refused); secret values are redacted from the stored/emitted diff.
  - Patched trees containing LLM-written code are built in the lab with `--network none`.

Concurrency: one active fix per finding (per-finding lock); apply/rollback refuse while a pipeline
or another apply/rollback for the same fix is in flight.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
import shutil
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import core, deps, lab, llm
from .context import (REDACTED, SECRET_KEY_RE, STR_LIT_RE, entropy, finding_brief, mask_secrets, read_lines,
                      safe_path, stub_ctx, window)
from .core import Finding, Fix, FixVerification
from .github import GitHub, GitHubError, PolicyError
from .sh import git
from .verify import added_suppressions, rescan

log = logging.getLogger("tirith.fix")

CATEGORY_MAP = {"dependency": "dependency_bump", "secret": "secret_removal", "sast": "code_patch",
                "config": "config_change", "dast": "code_patch"}
FORBIDDEN_PATHS = re.compile(r"(^|/)\.git(/|$)|^\.github/|(^|/)\.git(attributes|modules|ignore)$")
MAX_FILES = 3
# Files an LLM may never patch: build inputs (run with network at build time), dependency manifests,
# CI, and scanner config/ignore files.
BUILD_FILES = re.compile(
    r"(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|\.dockerignore|(docker-)?compose[^/]*\.ya?ml|"
    r"requirements[^/]*\.(txt|in)|constraints[^/]*\.txt|setup\.py|setup\.cfg|pyproject\.toml|Pipfile(\.lock)?|"
    r"poetry\.lock|uv\.lock|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile(\.lock)?|go\.(mod|sum)|"
    r"Makefile|Jenkinsfile|\.gitlab-ci\.ya?ml|\.travis\.ya?ml|azure-pipelines\.ya?ml|\.pre-commit-config\.ya?ml|"
    r"tox\.ini|noxfile\.py|conftest\.py|\.semgrepignore|\.gitleaksignore|\.trivyignore|\.semgrep\.ya?ml|"
    r"\.gitleaks\.toml)$|^\.github/|^\.circleci/|(^|/)\.git(/|$)", re.I)
ACTIVE_STATUSES = ("proposed", "verified", "pr_opened", "escalated", "applied")

# --------------------------------------------------------------------------- concurrency
_state_lock = threading.Lock()
_inflight: set[str] = set()          # fix ids with a running pipeline / apply / rollback
_finding_locks: dict[str, threading.Lock] = {}


def _finding_lock(finding_id: str) -> threading.Lock:
    with _state_lock:
        return _finding_locks.setdefault(finding_id, threading.Lock())


def in_flight(fix_id: str) -> bool:
    with _state_lock:
        return fix_id in _inflight


@contextmanager
def _claim(fix_id: str, what: str):
    with _state_lock:
        if fix_id in _inflight:
            raise FixRefused(409, f"fix {fix_id} is busy (pipeline/apply/rollback in flight); retry when it finishes ({what})")
        _inflight.add(fix_id)
    try:
        yield
    finally:
        with _state_lock:
            _inflight.discard(fix_id)


class FixRefused(Exception):
    def __init__(self, status_code: int, reason: str):
        super().__init__(reason)
        self.status_code = status_code
        self.reason = reason


def remediation_category(f: Finding) -> str:
    return CATEGORY_MAP.get(f.category, "code_patch")


def effective_mode(requested: str | None) -> tuple[str, list[str]]:
    """The request may lower the global mode, never raise it."""
    ms = core.get_mode()
    mode = ms.mode
    if requested and requested in core.MODE_ORDER and core.MODE_ORDER[requested] < core.MODE_ORDER[mode]:
        mode = requested
    return mode, list(ms.autonomous_categories or [])


def _deny(action: str, target: str, reason: str, code: int = 403, **ids) -> FixRefused:
    core.audit(action, target=target, allowed=False, details={"reason": reason})
    core.emit("policy.denied", reason, level="warn", data={"action": action}, **ids)
    return FixRefused(code, reason)


# =========================================================================== entry points
def propose_fix(finding_id: str, mode: str | None = None, wait: bool = False) -> Fix:
    f = core.get_finding(finding_id)
    if not f:
        raise FixRefused(404, "finding not found")
    eff, _ = effective_mode(mode)
    target = f"finding:{f.id}"
    if eff == "observe":
        raise _deny("remediation.fix", target, "observe mode: fixes are disabled (explain/validate only)", finding_id=f.id)
    if not f.file:
        raise _deny("remediation.fix", target, "finding has no source location to patch", 422, finding_id=f.id)
    asset = core.get_asset(f.asset_id)
    repo = core.pr_repo_for(asset) if asset else None
    ok, reason = core.check_pr_repo(repo or "")
    if not ok:
        raise _deny("remediation.fix", target, f"PR target not allowed: {reason}", finding_id=f.id)
    with _finding_lock(f.id):  # double /fix calls: the second one returns the first one's fix
        f = core.get_finding(finding_id) or f
        if f.fix_id:
            prev = core.get_fix(f.fix_id)
            if prev and prev.status in ACTIVE_STATUSES:
                if prev.status in ("proposed", "verified") and not in_flight(prev.id):
                    _fail(prev, f, "stale: the previous pipeline was interrupted (server restart?)")
                else:
                    return prev
        fx = Fix(finding_id=f.id, mode=eff, status="proposed")
        core.save_fix(fx)
        core.set_fix_meta(fx.id, repo=repo, category=remediation_category(f))
        core.update_finding(f.id, fix_id=fx.id, status="fixing")
        with _state_lock:
            _inflight.add(fx.id)  # released by run_pipeline's finally
    core.audit("remediation.fix.start", target=target, details={"fix_id": fx.id, "mode": eff, "repo": repo})
    core.emit("fix.started", f"Fixing {f.title} ({eff} mode)", finding_id=f.id, fix_id=fx.id,
              data={"mode": eff, "category": remediation_category(f), "repo": repo})
    if wait:
        return run_pipeline(fx.id)
    try:
        threading.Thread(target=_safe_pipeline, args=(fx.id,), name=f"fix-{fx.id}", daemon=True).start()
    except Exception as e:  # pragma: no cover - thread start failure
        with _state_lock:
            _inflight.discard(fx.id)
        return _fail(fx, f, f"could not start pipeline: {e}")
    return fx


def _safe_pipeline(fix_id: str) -> None:
    try:
        run_pipeline(fix_id)
    except Exception:  # run_pipeline already converts everything to _fail; this is a last resort
        log.exception("fix pipeline crashed")


# =========================================================================== patch generation
@dataclass
class Patch:
    diff: str
    summary: str
    files: list[str]
    extra: dict                       # persisted (fix meta / audit): never put secret material here
    redact: tuple[str, ...] = field(default=(), repr=False)  # values to mask in stored/emitted diffs
    llm: bool = False                 # contains model-written code


def _unified(rel: str, old: str, new: str) -> str:
    a, b = old.splitlines(keepends=True), new.splitlines(keepends=True)
    out = [f"diff --git a/{rel} b/{rel}\n"]
    for ln in difflib.unified_diff(a, b, f"a/{rel}", f"b/{rel}", n=3):
        if not ln.endswith("\n"):
            ln += "\n\\ No newline at end of file\n"
        out.append(ln)
    return "".join(out) if len(out) > 1 else ""


def dependency_patch(f: Finding, repo: Path) -> Patch:
    manifest = safe_path(repo, f.file)
    if not manifest or not f.package:
        raise FixRefused(422, f"manifest {f.file} not found in the working clone")
    pin = deps.pinned_version(manifest, f.package)
    installed = (pin[1] if pin and pin[1] else f.installed_version) or ""
    target = deps.choose_fixed_version(installed, f.fixed_version)
    if not target:
        raise FixRefused(422, f"no fixed version above {installed} for {f.rule_id}")
    resolves = [f.rule_id]
    if f.advisories:  # grouped finding: one bump covers every advisory the chosen version fixes
        resolves = [a.id for a in f.advisories
                    if a.fixed_version and not deps.in_affected_range(target, a.fixed_version)[0]] or [f.rule_id]
    if os.environ.get("TIRITH_DEP_CONSOLIDATE", "1") == "1":
        # One bump can close sibling advisories on the same release line (no major/minor jump).
        line = deps._release(installed)[:2]
        for s in core.list_findings(asset_id=f.asset_id, tool=f.tool):
            if s.id == f.id or s.file != f.file or deps.norm_pkg(s.package or "") != deps.norm_pkg(f.package):
                continue
            if s.status == "fixed":
                continue
            cand = deps.choose_fixed_version(installed, s.fixed_version)
            if cand and deps._release(cand)[:2] == line:
                resolves.append(s.rule_id)
                if deps.vlt(target, cand):
                    target = cand
    old = manifest.read_text()
    if manifest.name == "package.json":
        new, n = deps.bump_package_json(old, f.package, target)
    else:
        new, n = deps.bump_requirements(old, f.package, target)
    if not n:
        raise FixRefused(422, f"{f.package} is not pinned in {f.file}")
    return Patch(_unified(f.file, old, new), f"Bump {f.package} {installed} -> {target}", [f.file],
                 {"package": f.package, "from": installed, "to": target, "resolves": sorted(set(resolves))})


FIX_SYSTEM = (
    "You are Tirith, a defensive security engineer writing the smallest safe patch for ONE finding. "
    "Change only what is needed to remove the weakness; keep behavior, style and formatting; no refactors, "
    "no new dependencies, never touch CI config. You output text only; nothing you write is executed. "
    "Reply with ONLY JSON: {\"explanation\": str, \"diff\": str (unified diff, paths a/<path> b/<path> relative "
    "to the repo root, or empty), \"edits\": [{\"file\": str, \"find\": str (exact existing text, unique in the "
    "file), \"replace\": str}]}. Prefer `edits`; they are applied literally."
)


def _secret_values(line: str) -> tuple[str, ...]:
    return tuple(m["v"] for m in STR_LIT_RE.finditer(line)
                 if not any(c.isspace() for c in m["v"]) and not SECRET_KEY_RE.fullmatch(m["v"]))


def _known_secret_values(f: Finding, repo: Path) -> tuple[str, ...]:
    """Literal values on lines that a secret finding flagged in the same file."""
    lines = read_lines(repo, f.file) or []
    vals: list[str] = []
    try:
        sibs = [s for s in core.list_findings(asset_id=f.asset_id) if s.category == "secret" and s.file == f.file]
    except Exception:
        sibs = []
    if f.category == "secret":
        sibs.append(f)
    for s in sibs:
        if s.line and 0 < s.line <= len(lines):
            vals += _secret_values(lines[s.line - 1])
    return tuple(sorted(set(vals)))


def _check_llm_target(f: Finding) -> None:
    if BUILD_FILES.search(f.file or "") or FORBIDDEN_PATHS.search(f.file or ""):
        raise FixRefused(422, f"{f.file} is a build/manifest/CI file; Tirith does not let a model patch it "
                              "(fix it by hand or via a dependency bump)")


def llm_patch(f: Finding, repo: Path, fix_id: str) -> Patch:
    _check_llm_target(f)
    lines = read_lines(repo, f.file)
    if lines is None:
        raise FixRefused(422, f"{f.file} not found in the working clone")
    secret_vals = _known_secret_values(f, repo)
    full = "\n".join(lines)
    code = full if len(lines) <= 400 else window(lines, f.line, 120)[0]
    code = mask_secrets(code, secret_vals)          # the model never sees a credential value
    ctx_snip = mask_secrets(window(lines, f.line, 2)[0], secret_vals)
    snippet_plain = "\n".join(lines[max(0, (f.line or 1) - 1): (f.line or 1)]) if f.line else f.snippet
    streamer = llm.ThinkingStreamer(lambda t: core.emit("ai.thinking", t, finding_id=f.id, fix_id=fix_id, data={"phase": "fix"}))
    msgs = [{"role": "system", "content": FIX_SYSTEM},
            {"role": "user", "content": finding_brief(f) + f"\n\nFlagged lines:\n{ctx_snip}\n\nFile {f.file}:\n```\n{code}\n```"
             + f"\n\nOnly {f.file} may be changed. Values shown as {REDACTED} are masked; never write that marker."}]
    data, res = llm.chat_json(msgs, task="fix", on_reasoning=streamer, stub_context=stub_ctx(f, mask_secrets(snippet_plain or "", secret_vals)),
                              deadline=llm.deadline_in())
    streamer.flush()
    if not isinstance(data, dict):
        raise FixRefused(502, "model returned no patch")
    diff, edits = data.get("diff"), data.get("edits")
    if diff is not None and not isinstance(diff, str):
        raise FixRefused(502, "model returned a malformed diff (expected a string)")
    if edits is None:
        edits = []
    if not isinstance(edits, list) or not all(
            isinstance(e, dict) and all(isinstance(e.get(k, ""), str) for k in ("file", "find", "replace")) for e in edits):
        raise FixRefused(502, "model returned malformed edits (expected [{file, find, replace}] with string values)")
    explanation = mask_secrets(str(data.get("explanation") or "LLM patch")[:500], secret_vals)
    extra = {"model": res.model}
    diff = diff or ""
    if diff.strip() and _apply_check(repo, diff):
        # Paths in the diff text are NOT trusted (quoting, renames, /dev/null, binary): the real
        # change set is read back from git after applying, in run_pipeline -> _guard_changes.
        return Patch(diff if diff.endswith("\n") else diff + "\n", explanation, [f.file], {**extra, "source": "diff"},
                     redact=secret_vals, llm=True)
    cur = (repo / f.file).read_text()
    new = cur
    for e in edits[:20]:
        rel = (e.get("file") or f.file).strip().removeprefix("a/").removeprefix("b/").lstrip("/")
        if rel != f.file:
            raise FixRefused(422, f"model tried to edit {rel[:120]}; only {f.file} may change")
        find, rep = e.get("find") or "", e.get("replace") or ""
        if REDACTED in rep:
            raise FixRefused(422, "model wrote the secret-mask marker into the patch")
        if not find or new.count(find) != 1:
            continue
        new = new.replace(find, rep, 1)
    diff = _unified(f.file, cur, new)
    if not diff.strip():
        raise FixRefused(502, "model patch did not apply (no usable diff or edits)")
    return Patch(diff, explanation, [f.file], {**extra, "source": "edits"}, redact=secret_vals, llm=True)


# --------------------------------------------------------------------------- secrets: fixed template, no LLM
def _insert_import_os(lines: list[str]) -> None:
    if any(re.match(r"import os(\s|,|$)|from os import ", ln) for ln in lines):
        return
    for i, ln in enumerate(lines):
        if re.match(r"import |from (?!__future__)", ln):
            lines.insert(i, "import os\n")
            return
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        i += 1
    if i < len(lines) and lines[i].lstrip().startswith(('"""', "'''")):
        q = lines[i].lstrip()[:3]
        if lines[i].count(q) < 2:
            i += 1
            while i < len(lines) and q not in lines[i]:
                i += 1
        i += 1
    while i < len(lines) and lines[i].startswith("from __future__"):
        i += 1
    lines.insert(i, "import os\n")


def secret_patch(f: Finding, repo: Path) -> Patch:
    """Replace the hard-coded literal on the flagged line with os.environ.get("<KEY>", ""). Python only."""
    p = safe_path(repo, f.file)
    if p is None:
        raise FixRefused(422, f"{f.file} not found in the working clone")
    if p.suffix != ".py":
        raise FixRefused(422, f"automatic secret removal only supports Python files; rotate the credential and move "
                              f"it out of {f.file} by hand")
    old = p.read_text()
    lines = old.splitlines(keepends=True)
    if not f.line or not 0 < f.line <= len(lines):
        raise FixRefused(422, "secret finding has no usable line number")
    line = lines[f.line - 1]
    cands = [m for m in STR_LIT_RE.finditer(line)
             if not any(c.isspace() for c in m["v"]) and not SECRET_KEY_RE.fullmatch(m["v"])]
    if not cands:
        raise FixRefused(422, "no string literal on the flagged line; rotate the credential and remove it by hand")
    m = max(cands, key=lambda x: entropy(x["v"]))
    if m.start() > 0 and (line[m.start() - 1].isalnum() or line[m.start() - 1] == "_"):
        raise FixRefused(422, "flagged literal is a prefixed (f/b/r) string; needs a human")
    key = re.search(r"""['"]?([A-Za-z_][\w-]*)['"]?\s*[:=]\s*$""", line[:m.start()])
    env = re.sub(r"[^A-Z0-9]+", "_", (key.group(1) if key else "SECRET").upper()).strip("_") or "SECRET"
    if env[0].isdigit():
        env = "SECRET_" + env
    lines[f.line - 1] = line[:m.start()] + f'os.environ.get("{env}", "")' + line[m.end():]
    _insert_import_os(lines)
    new = "".join(lines)
    return Patch(_unified(f.file, old, new), f"Move hard-coded secret in {f.file} to env var {env}", [f.file],
                 {"env_var": env, "source": "template"}, redact=_secret_values(line))


def _guard_files(files: list[str]) -> None:
    if len(files) > MAX_FILES:
        raise FixRefused(422, f"patch touches {len(files)} files (max {MAX_FILES})")
    for p in files:
        if FORBIDDEN_PATHS.search(p):
            raise FixRefused(422, f"patch may not modify {p}")


_STATUS_NAMES = {"A": "add", "D": "delete", "R": "rename", "C": "copy", "T": "type change", "U": "unmerged", "X": "unknown"}


def real_changes(repo: Path) -> tuple[list[str], list[str]]:
    """(changed paths, problems) for the working tree vs HEAD, read back from git (never from diff text).

    Only in-place, same-mode, non-binary modifications of regular files are acceptable; everything
    else (delete/rename/copy/type or mode change/submodule/binary/new untracked file) is a problem."""
    problems: list[str] = []
    changed: list[str] = []
    raw = git(["diff", "--raw", "-z", "--no-abbrev", "--find-renames", "--find-copies", "--no-ext-diff", "HEAD"], cwd=repo)
    if not raw.ok:
        return [], [f"cannot inspect working tree: {raw.tail(200)}"]
    toks = raw.out.split("\0")
    i = 0
    while i < len(toks):
        t = toks[i]
        if not t:
            i += 1
            continue
        meta = t[1:].split() if t.startswith(":") else []
        if len(meta) < 5:
            problems.append("unparseable git diff entry")
            break
        old_mode, new_mode, status = meta[0], meta[1], meta[4]
        n = 2 if status[:1] in ("R", "C") else 1
        paths = toks[i + 1:i + 1 + n]
        i += 1 + n
        changed += paths
        shown = " -> ".join(paths)
        if status != "M":
            problems.append(f"{_STATUS_NAMES.get(status[:1], status)} of {shown}")
        elif old_mode != new_mode:
            problems.append(f"mode change {old_mode}->{new_mode} on {shown}")
        elif new_mode not in ("100644", "100755"):
            problems.append(f"{shown} is not a regular file (mode {new_mode})")
    num = git(["diff", "--numstat", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", "HEAD"], cwd=repo)
    for ent in num.out.split("\0"):
        parts = ent.split("\t")
        if len(parts) >= 3 and parts[0] == "-" and parts[1] == "-":
            problems.append(f"binary change to {parts[2]}")
    unt = git(["ls-files", "--others", "-z"], cwd=repo)  # incl. ignored files: a fresh clone has none
    for rel in (x for x in unt.out.split("\0") if x):
        changed.append(rel)
        problems.append(f"new file {rel}")
    return sorted(set(changed)), problems


def _guard_changes(repo: Path, allowed: set[str], *, llm_written: bool) -> list[str]:
    """Authoritative post-apply check of what the patch really changed. Raises FixRefused."""
    changed, problems = real_changes(repo)
    for rel in changed:
        if rel not in allowed:
            problems.append(f"{rel} is outside the finding's file ({', '.join(sorted(allowed))})")
        elif FORBIDDEN_PATHS.search(rel) or (llm_written and BUILD_FILES.search(rel)):
            problems.append(f"patch may not modify {rel}")
    if problems:
        raise FixRefused(422, "patch rejected: " + "; ".join(dict.fromkeys(problems))[:600])
    if not changed:
        raise FixRefused(422, "patch produced no change")
    _guard_files(changed)
    return changed


def _apply_check(repo: Path, diff: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False, dir=core.work_root()) as t:
        t.write(diff if diff.endswith("\n") else diff + "\n")
        name = t.name
    try:
        return git(["apply", "--check", "--recount", name], cwd=repo).ok
    finally:
        os.unlink(name)


def apply_diff(repo: Path, diff: str) -> tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False, dir=core.work_root()) as t:
        t.write(diff)
        name = t.name
    try:
        chk = git(["apply", "--check", "--recount", name], cwd=repo)
        if not chk.ok:
            return False, "git apply --check failed: " + chk.tail()
        ap = git(["apply", "--recount", name], cwd=repo)
        return ap.ok, ("git apply --check: ok; applied" if ap.ok else "git apply failed: " + ap.tail())
    finally:
        os.unlink(name)


# =========================================================================== working clone
def _work_clone(fix_id: str, gh: GitHub, base: str) -> Path:
    d = core.work_root() / "clones" / fix_id
    if d.exists():
        shutil.rmtree(d)
    d.parent.mkdir(parents=True, exist_ok=True)
    r = git(["clone", "--quiet", "--depth", "50", "--branch", base, gh.clone_url(), str(d)], token=gh.token, timeout=600)
    if not r.ok:
        raise GitHubError(f"clone of {gh.repo} failed: {r.tail()}")
    return d


def _push(repo_dir: Path, gh: GitHub, branch: str) -> None:
    url = git(["remote", "get-url", "origin"], cwd=repo_dir).out.strip()
    if url.rstrip("/").removesuffix(".git").lower() != gh.clone_url().removesuffix(".git").lower():
        raise PolicyError(f"working clone origin {url} is not {gh.repo}; refusing to push")
    r = git(["push", "--quiet", "origin", f"HEAD:refs/heads/{branch}"], cwd=repo_dir, token=gh.token, timeout=300)
    if not r.ok:
        raise GitHubError(f"push failed: {r.tail()}")


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", s.lower()).strip("-")[:40]


# =========================================================================== pipeline
def _update(fx: Fix, **fields) -> Fix:
    for k, v in fields.items():
        setattr(fx, k, v)
    return core.save_fix(fx)


def _fail(fx: Fix, f: Finding, msg: str) -> Fix:
    fx.verification.details = ((fx.verification.details or "") + f"\nFAILED: {msg}").strip()
    _update(fx, status="failed")
    core.update_finding(f.id, status="validated" if f.validation and f.validation.result == "confirmed" else "open")
    core.emit("fix.verified", f"Fix failed: {msg}"[:400], level="error", finding_id=f.id, fix_id=fx.id)
    core.audit("remediation.fix.failed", target=f"fix:{fx.id}", details={"reason": msg[:400]})
    return fx


def run_pipeline(fix_id: str) -> Fix:
    fx = core.get_fix(fix_id)
    if fx is None:
        with _state_lock:
            _inflight.discard(fix_id)
        raise FixRefused(404, "fix not found")
    f = core.get_finding(fx.finding_id)
    with _state_lock:
        _inflight.add(fix_id)
    try:
        if f is None:
            fx.verification.details = "FAILED: finding disappeared"
            return _update(fx, status="failed")
        return _pipeline(fx, f)
    except FixRefused as e:
        return _fail(fx, f, e.reason)
    except (GitHubError, lab.LabError, llm.LLMError, ValueError) as e:
        return _fail(fx, f, f"{type(e).__name__}: {e}")
    except Exception as e:  # never leave a fix stuck in `proposed` / a finding stuck in `fixing`
        log.exception("fix pipeline crashed")
        return _fail(fx, f, f"internal error: {type(e).__name__}: {str(e)[:300]}")
    finally:
        with _state_lock:
            _inflight.discard(fix_id)


def _pipeline(fx: Fix, f: Finding) -> Fix:
    meta = core.fix_meta(fx.id)
    repo = meta.get("repo")
    ids = {"finding_id": f.id, "fix_id": fx.id}
    gh = GitHub(repo)
    base = os.environ.get("TIRITH_FIX_BASE") or gh.base_branch()
    work = _work_clone(fx.id, gh, base)
    base_rev = git(["rev-parse", "HEAD"], cwd=work).out.strip()
    core.audit("remediation.fix.clone", target=f"github_repo:{repo}", details={"base": base, "rev": base_rev[:12]})

    # ---- patch
    if f.category == "dependency" and f.package:
        patch = dependency_patch(f, work)
    elif f.category == "secret":
        patch = secret_patch(f, work)  # fixed template; the secret never goes to the model
    else:
        patch = llm_patch(f, work, fx.id)
    branch = f"tirith/{_slug(patch.extra.get('package') or f.rule_id.rsplit('.', 1)[-1])}-{fx.id[-6:]}"
    if git(["checkout", "-q", "-b", branch], cwd=work).rc != 0:
        raise GitHubError("could not create branch")
    ok, msg = apply_diff(work, patch.diff)
    if not ok:
        return _fail(fx, f, msg)
    # authoritative: what did the patch really change? (only f.file, in place, text)
    changed = _guard_changes(work, {f.file}, llm_written=patch.llm)
    raw_diff = git(["diff", "--no-ext-diff", "--no-textconv", "HEAD"], cwd=work).out
    marks = added_suppressions(raw_diff)
    if marks:
        raise FixRefused(422, f"patch adds a scanner suppression marker ({marks[0]}); refusing")
    if any(ln.startswith("+") and REDACTED in ln for ln in raw_diff.splitlines()):
        raise FixRefused(422, "patch contains the secret-mask marker; refusing")
    final_diff = mask_secrets(raw_diff, patch.redact)  # stored + emitted: never the secret value
    _update(fx, diff=final_diff, branch=branch)
    core.set_fix_meta(fx.id, base=base, base_rev=base_rev, patch=patch.extra, summary=patch.summary, changed=changed)
    core.audit("remediation.fix.patch", target=f"fix:{fx.id}", details={"branch": branch, "files": changed, **patch.extra})
    core.emit("fix.patch", f"{patch.summary} ({', '.join(changed)})", **ids,
              data={"diff": final_diff[:8000], "branch": branch, "files": changed, "apply_check": msg})
    title = f"[Tirith] {patch.summary}" if f.category == "dependency" else f"[Tirith] Fix {f.title}"[:120]
    if git(["add", "--", *changed], cwd=work).rc != 0:
        return _fail(fx, f, "git add failed")
    c = git(["commit", "-q", "-m", f"{title}\n\nFinding: {f.rule_id} ({f.severity}) in {f.file}\nOpened by Tirith remediation ({fx.mode} mode)."], cwd=work)
    if not c.ok:
        return _fail(fx, f, "commit failed: " + c.tail())
    verified_sha = git(["rev-parse", "HEAD"], cwd=work).out.strip()

    # ---- verify
    v = verify_patch(fx, f, work, base_rev, changed, llm_written=patch.llm or remediation_category(f) != "dependency_bump")
    if not (v["rescan_gone"] and v["lab_ok"]):
        return _fail(fx, f, v["reason"])
    _update(fx, status="verified")
    core.set_fix_meta(fx.id, verified_sha=verified_sha)
    core.emit("fix.verified", f"Verified: {f.rule_id} gone after patch, app boots in lab", level="success", **ids,
              data={"verification": fx.verification.model_dump()})

    # ---- push + PR
    _push(work, gh, branch)
    core.audit("remediation.fix.push", target=f"github_repo:{repo}", details={"branch": branch, "sha": verified_sha})
    body = _pr_body(f, fx, patch, v)
    pr = gh.open_pr(branch, base, title, body)
    _update(fx, status="pr_opened", pr_url=pr["html_url"])
    head_sha = (pr.get("head") or {}).get("sha")
    core.set_fix_meta(fx.id, pr_number=pr["number"], head_sha=head_sha)
    core.audit("remediation.fix.pr_opened", target=f"github_repo:{repo}", details={"pr": pr["html_url"], "base": base})
    core.emit("fix.pr_opened", f"PR opened: {pr['html_url']}", level="success", **ids,
              data={"pr_url": pr["html_url"], "branch": branch, "base": base, "repo": repo})

    # ---- mode policy
    ms = core.get_mode()
    if fx.mode == "autonomous" and ms.mode == "autonomous":
        cat = remediation_category(f)
        if cat in ms.autonomous_categories:
            return merge_fix(fx.id, actor="autonomous")
        _update(fx, status="escalated")
        core.audit("remediation.fix.escalated", target=f"fix:{fx.id}", details={"category": cat, "allowed": ms.autonomous_categories})
        core.emit("fix.pr_opened", f"Escalated to a human: {cat} is not in autonomous_categories", level="warn", **ids,
                  data={"pr_url": fx.pr_url, "escalated": True, "category": cat})
        gh.comment(pr["number"], f"Tirith autonomous mode: `{cat}` is not in autonomous_categories {ms.autonomous_categories}; escalated for human review.")
    return core.get_fix(fx.id)


def _base_tree(work: Path, base_rev: str, fix_id: str) -> Path | None:
    d = core.work_root() / "clones" / f"{fix_id}-base"
    if d.exists():
        git(["worktree", "remove", "--force", str(d)], cwd=work)
        shutil.rmtree(d, ignore_errors=True)
    r = git(["worktree", "add", "--detach", "--quiet", str(d), base_rev], cwd=work)
    return d if r.ok else None


def verify_patch(fx: Fix, f: Finding, work: Path, base_rev: str, changed: list[str], *, llm_written: bool = True) -> dict:
    ids = {"finding_id": f.id, "fix_id": fx.id}
    details: list[str] = []
    out = {"rescan_gone": False, "lab_ok": False, "reason": ""}

    core.emit("validation.step", f"Rescanning changed files with {f.tool}", **ids)
    rs = rescan(f, work, base_rev, changed)
    details.append("(a) " + rs.summary())
    out["rescan_gone"] = rs.gone
    out["rescan"] = rs
    if not rs.gone:
        if rs.after_present:
            result, why = "still_present", ""
        elif rs.before_present is not True:
            result, why = "not_reproduced_before", " The rule did not fire on the unpatched file, so the rescan proves nothing."
        else:
            result, why = "rescan_error", ""
        out["reason"] = rs.summary() + why
        fx.verification = FixVerification(validation_result=result, details="\n".join(details) + why)
        return out

    core.emit("validation.step", "Rebuilding and booting the patched app in the lab", **ids)
    h = None
    base_tree = _base_tree(work, base_rev, fx.id) if llm_written else None
    try:
        if llm_written and base_tree is None:
            raise lab.LabUnavailable("lab boot unavailable: could not check out the base revision for the offline build")
        # Patched code (anything but a template dependency bump) builds with --network none; the base
        # revision is built first, with network, so dependency layers come from the cache.
        h = lab.boot(work, f"fix-{fx.id}", keep=True, network=not llm_written, base_src=base_tree,
                     on_step=lambda m, **kw: core.emit("validation.step", m, **ids))
        out["lab_ok"] = h.ok
        probe = next((e.content for e in h.evidence if e.label == "boot probe"), "")
        egress = next((e.content for e in h.evidence if e.label == "egress check"), "")
        details.append(f"(b) lab: image {h.image}; {probe}; {egress}".strip("; "))
        out["lab"] = h.as_dict()
        out["lab_evidence"] = [e.model_dump() for e in h.evidence]
    except lab.LabError as e:
        details.append(f"(b) lab build/boot failed: {e}")
    finally:
        if h is not None:
            h.stop()
        if base_tree is not None:
            git(["worktree", "remove", "--force", str(base_tree)], cwd=work)
            shutil.rmtree(base_tree, ignore_errors=True)
    if not out["lab_ok"]:
        out["reason"] = "patched app did not boot in the lab" + (
            f" ({details[-1].removeprefix('(b) lab build/boot failed: ')[:300]})" if "failed:" in details[-1] else "")
    fx.verification = FixVerification(
        tests_passed=None,  # Tirith does not run the target project's tests
        validation_result="fixed" if rs.gone else "still_present",
        details="\n".join(details),
    )
    core.save_fix(fx)
    core.audit("remediation.fix.verify", target=f"fix:{fx.id}", details={k: out[k] for k in ("rescan_gone", "lab_ok")})
    return out


def _pr_body(f: Finding, fx: Fix, patch: Patch, v: dict) -> str:
    resolves = patch.extra.get("resolves") or [f.rule_id]
    lines = [
        f"## {patch.summary}", "",
        f"**Finding:** `{f.rule_id}` ({f.severity}) — {f.title}",
        f"**Location:** `{f.file}`" + (f":{f.line}" if f.line else ""),
    ]
    if f.url:
        lines.append(f"**Advisory:** {f.url}")
    if len(resolves) > 1:
        lines.append(f"**Also resolves:** {', '.join(f'`{r}`' for r in resolves if r != f.rule_id)}")
    if patch.extra.get("env_var"):
        lines += ["", f"**Action required:** set `{patch.extra['env_var']}` in the deployment environment and rotate "
                  "the exposed credential at its provider. It is still in git history."]
    lines += ["", "## Verification (done before this PR was opened)", "", "```", fx.verification.details or "", "```", ""]
    lines += [
        "## Safety", "",
        "- The patched app was booted on this host only: loopback address, internal lab network where a "
        "container runtime holds it, and no route off the bridge.",
        "- No credentials were used; no requests were sent to anything outside the lab.",
        f"- Mode: **{fx.mode}**. " + ("Tirith never merges in assisted mode; a human reviews and merges."
                                       if fx.mode != "autonomous" else "Autonomous: merged only if the category is allowlisted."),
        "", f"_Opened by Tirith remediation (fix `{fx.id}`)._",
    ]
    return "\n".join(lines)


# =========================================================================== apply / merge
def apply_fix(fix_id: str) -> Fix:
    if not core.get_fix(fix_id):
        raise FixRefused(404, "fix not found")
    with _claim(fix_id, "apply"):
        fx = core.get_fix(fix_id)
        f = core.get_finding(fx.finding_id)
        ms = core.get_mode()
        mode, allowed = ms.mode, ms.autonomous_categories
        target = f"fix:{fx.id}"
        ids = {"finding_id": fx.finding_id, "fix_id": fx.id}
        if mode == "observe":
            raise _deny("remediation.apply", target, "observe mode: applying fixes is disabled", **ids)
        if mode == "assisted":
            raise _deny("remediation.apply", target, "assisted mode: Tirith never merges; review and merge the PR on GitHub", 409, **ids)
        if fx.status == "applied":
            return fx
        if fx.status not in ("pr_opened", "verified", "escalated") or not fx.pr_url:
            raise FixRefused(409, f"fix is {fx.status}; only a verified fix with an open PR can be applied")
        cat = remediation_category(f) if f else "code_patch"
        if cat not in allowed:
            if fx.status != "escalated":
                _update(fx, status="escalated")
            raise _deny("remediation.apply", target, f"autonomous mode: {cat} not in autonomous_categories {allowed}; escalated", 409, **ids)
        if fx.verification.validation_result != "fixed":
            raise _deny("remediation.apply", target, "verification did not pass; refusing to merge", 409, **ids)
        return merge_fix(fx.id, actor="api")


def merge_fix(fix_id: str, actor: str = "autonomous") -> Fix:
    """Merge the fix PR, pinned to the commit Tirith verified (GitHub refuses if the head moved)."""
    fx = core.get_fix(fix_id)
    meta = core.fix_meta(fix_id)
    ids = {"finding_id": fx.finding_id, "fix_id": fx.id}
    sha_pin = meta.get("verified_sha")
    if not sha_pin:
        raise FixRefused(409, "no verified commit recorded for this fix; refusing to merge")
    if meta.get("head_sha") and meta["head_sha"] != sha_pin:
        raise _deny("remediation.apply", f"fix:{fx.id}", f"PR head {meta['head_sha'][:10]} is not the verified commit "
                    f"{sha_pin[:10]}; refusing to merge", 409, **ids)
    gh = GitHub(meta["repo"])
    res = gh.merge_pr(int(meta["pr_number"]), title=f"Merge Tirith fix {fx.id}", sha=sha_pin)
    sha = res.get("sha")
    core.set_fix_meta(fx.id, merge_sha=sha, merged_by=actor)
    _update(fx, status="applied")
    f = core.update_finding(fx.finding_id, status="fixed")
    core.record_posture(f.asset_id if f else None)
    core.audit("remediation.fix.merge", target=f"github_repo:{meta['repo']}",
               details={"pr": fx.pr_url, "sha": sha, "verified_sha": sha_pin, "actor": actor})
    core.emit("fix.applied", f"Merged {fx.pr_url} ({(sha or '')[:10]})", level="success", **ids, data={"merge_sha": sha})
    if os.environ.get("TIRITH_POSTMERGE_CHECK", "1") == "1":
        ok, why = _postmerge_check(fx, gh, meta)
        if not ok:
            core.emit("fix.verified", f"Post-merge check failed ({why}); rolling back", level="error", **ids)
            return _rollback(fx.id, reason=f"post-merge check failed: {why}")
    return core.get_fix(fx.id)


def _postmerge_check(fx: Fix, gh: GitHub, meta: dict) -> tuple[bool, str]:
    """Boot the merged base branch in the lab; a broken main triggers automatic rollback."""
    d = core.work_root() / "clones" / f"{fx.id}-merged"
    if d.exists():
        shutil.rmtree(d)
    r = git(["clone", "--quiet", "--depth", "5", "--branch", meta["base"], gh.clone_url(), str(d)], token=gh.token, timeout=600)
    if not r.ok:
        return True, "could not clone merged base (skipped)"
    h = None
    offline = (meta.get("category") or "code_patch") != "dependency_bump"
    try:
        # merged code that came from a model builds offline (dependency layers are cached from the fix run)
        h = lab.boot(d, f"merged-{fx.id}", keep=True, network=not offline)
        return h.ok, "merged app boots in lab" if h.ok else "merged app did not boot in lab"
    except lab.LabUnavailable as e:
        return True, f"post-merge lab check skipped: {str(e)[:200]}"
    except lab.LabError as e:
        return False, str(e)[:200]
    finally:
        if h is not None:
            h.stop()
        shutil.rmtree(d, ignore_errors=True)


# =========================================================================== rollback
def rollback_fix(fix_id: str, reason: str = "requested") -> Fix:
    """API entry: refuses while the fix is in flight and enforces the mode (observe never touches GitHub)."""
    fx = core.get_fix(fix_id)
    if not fx:
        raise FixRefused(404, "fix not found")
    with _claim(fix_id, "rollback"):
        fx = core.get_fix(fix_id)
        if fx.status == "rolled_back":
            return fx
        mode = core.get_mode().mode
        if mode == "observe" and fx.pr_url:
            raise _deny("remediation.rollback", f"fix:{fx.id}", "observe mode: rollback would push/close PRs on GitHub; "
                        "switch to assisted/autonomous or close the PR by hand", finding_id=fx.finding_id, fix_id=fx.id)
        return _rollback(fix_id, reason)


def _rollback(fix_id: str, reason: str = "requested") -> Fix:
    fx = core.get_fix(fix_id)
    meta = core.fix_meta(fix_id)
    ids = {"finding_id": fx.finding_id, "fix_id": fx.id}
    if fx.status == "rolled_back":
        return fx
    core.audit("remediation.rollback", target=f"fix:{fx.id}", details={"reason": reason, "status": fx.status})
    if not meta.get("repo") or not fx.pr_url:
        _update(fx, status="rolled_back")
        core.emit("fix.rolled_back", "Rolled back (nothing was pushed)", level="info", **ids)
        return fx
    gh = GitHub(meta["repo"])
    if meta.get("merge_sha"):
        work = core.work_root() / "clones" / f"{fx.id}-revert"
        if work.exists():
            shutil.rmtree(work)
        r = git(["clone", "--quiet", "--depth", "50", "--branch", meta["base"], gh.clone_url(), str(work)], token=gh.token, timeout=600)
        if not r.ok:
            raise GitHubError(f"clone for revert failed: {r.tail()}")
        branch = f"tirith/revert-{fx.id[-6:]}"
        git(["checkout", "-q", "-b", branch], cwd=work)
        rv = git(["revert", "--no-edit", "-m", "1", meta["merge_sha"]], cwd=work)
        if not rv.ok:
            raise GitHubError(f"git revert failed: {rv.tail()}")
        _push(work, gh, branch)
        pr = gh.open_pr(branch, meta["base"], f"[Tirith] Revert fix {fx.id}",
                        f"Reverts merge {meta['merge_sha']} ({fx.pr_url}).\n\nReason: {reason}\n\n_Opened by Tirith rollback._")
        info = {"revert_pr": pr["html_url"], "revert_pr_number": pr["number"]}
        revert_sha = git(["rev-parse", "HEAD"], cwd=work).out.strip()
        if core.get_mode().mode == "autonomous":
            m = gh.merge_pr(pr["number"], title=f"Revert Tirith fix {fx.id}", sha=revert_sha or None)
            info["revert_sha"] = m.get("sha")
        core.set_fix_meta(fx.id, **info)
        shutil.rmtree(work, ignore_errors=True)
        msg = f"Reverted merge {meta['merge_sha'][:10]} via {pr['html_url']}" + (" (merged)" if "revert_sha" in info else " (awaiting review)")
    else:
        gh.close_pr(int(meta["pr_number"]))
        if fx.branch:
            gh.delete_branch(fx.branch)
        msg = f"Closed unmerged PR {fx.pr_url} and deleted {fx.branch}"
        info = {}
    fx.verification.details = ((fx.verification.details or "") + f"\nROLLBACK: {msg} — {reason}").strip()
    _update(fx, status="rolled_back")
    f = core.update_finding(fx.finding_id, status="open")
    core.record_posture(f.asset_id if f else None)
    core.audit("remediation.rollback.done", target=f"fix:{fx.id}", details={"message": msg, **info})
    core.emit("fix.rolled_back", msg, level="warn", **ids, data=info)
    return fx
