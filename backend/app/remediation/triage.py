"""Evidence-based validation (triage). Nothing here attacks anything or uses a credential.

  dependency: installed version inside the advisory's affected range? package actually
              imported / used by the code that owns the manifest?
  secret:     in the current tree vs history only, test/fixture path, entropy, placeholder
              patterns -> likely-real vs likely-test. The value is never printed, sent to the
              LLM, or used anywhere.
  sast:       LLM data-flow review (source -> sink) over the code context + whether the
              enclosing view is reachable from the app's URL routes.
  dast/config: optional lab check -> read-only GET in the isolated lab, evidence = response.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Callable

from . import core, deps, lab, llm
from .context import finding_brief, mask_secrets, read_lines, safe_path, stub_ctx, window
from .core import Evidence, Finding, Validation, now_iso
from .sh import git

Step = Callable[[str], None]


def _ev(kind: str, label: str, content: str) -> Evidence:
    return Evidence(kind=kind, label=label, content=(content or "")[:6000])


# =========================================================================== dependency
def triage_dependency(f: Finding, root: Path | None, step: Step) -> Validation:
    v = Validation(finding_id=f.id, check="dependency-advisory-range", result="error", started_at=now_iso())
    evd: list[Evidence] = []
    inst = f.installed_version or ""
    pinned = None
    manifest = safe_path(root, f.file) if root else None
    if manifest:
        pinned = deps.pinned_version(manifest, f.package or "")
        if pinned:
            evd.append(_ev("note", "manifest pin", f"{f.file}:{pinned[0]} pins {f.package} at {pinned[1] or '(unpinned)'}"))
            if pinned[1] and pinned[1] != inst:
                inst = pinned[1]
                evd.append(_ev("note", "version drift", f"manifest version {pinned[1]} differs from scanner's {f.installed_version}; using manifest"))
    if f.advisories:
        # Grouped finding: affected if the pinned version is inside ANY advisory's range.
        step(f"Checking {f.package} {inst} against {len(f.advisories)} advisories")
        rows, affected = [], False
        for a in f.advisories:
            hit, why = deps.in_affected_range(inst, a.fixed_version)
            affected |= hit
            rows.append(f"{a.id} [{a.severity}]: {why} -> {'AFFECTED' if hit else 'not affected'}")
        evd.append(_ev("note", "affected range", "\n".join(rows)))
    else:
        step(f"Checking {f.package} {inst} against advisory {f.cve or f.rule_id}")
        affected, why = deps.in_affected_range(inst, f.fixed_version)
        evd.append(_ev("note", "affected range", f"{f.cve or f.rule_id}: {why} -> {'AFFECTED' if affected else 'NOT affected'}"))

    imports: list[str] = []
    runtime: list[str] = []
    if root and f.package:
        owner = (manifest.parent if manifest else root)
        step(f"Searching {owner.name or 'repo'} for imports of {f.package}")
        imports = deps.find_imports(owner, f.package, exclude=deps.owned_tree_excludes(owner))
        runtime = deps.find_runtime_refs(owner, f.package)
        evd.append(_ev("note", "imports", "\n".join(imports) if imports else
                       f"no direct `import {'/'.join(deps.import_names(f.package))}` found in code owned by {f.file}"))
        if runtime:
            evd.append(_ev("note", "runtime references", "\n".join(runtime)))

    if not affected:
        v.result, v.confidence = "not_reproduced", 0.9
    else:
        v.result = "confirmed"
        v.confidence = 0.95 if imports else (0.85 if runtime else 0.6)
        reach = "imported by the app" if imports else ("used at runtime" if runtime else "installed but not imported directly (possibly transitive / unused)")
        evd.append(_ev("note", "verdict", f"Vulnerable version is pinned and {reach}. Fix: bump to "
                       f"{deps.choose_fixed_version(inst, f.fixed_version) or f.fixed_version}."))
    v.evidence = evd
    return v


# =========================================================================== secret
TESTY_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|examples?|samples?|testdata|e2e)(/|$)|(_test|test_|\.spec|\.test)\.", re.I)
PLACEHOLDER = re.compile(
    r"(example|sample|dummy|placeholder|changeme|change_me|your[_-]?|xxx+|\*{3,}|<[^>]+>|redacted|todo|fake|"
    r"insert|replace|^test|test$|1234|abcd|password|secret|qwerty|letmein|admin)", re.I)
TEST_KEY_PREFIX = re.compile(r"^(sk|pk|rk)_test_|^AKIA[0-9A-Z]*EXAMPLE|^ghp_0{10}", re.I)
_LITERAL = re.compile(r"""(['"])([^'"\s]{6,})\1""")
_ASSIGN = re.compile(r"""[:=]\s*([^\s'",;#]{8,})""")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _charset(s: str) -> str:
    cls = []
    if re.search(r"[a-z]", s):
        cls.append("a-z")
    if re.search(r"[A-Z]", s):
        cls.append("A-Z")
    if re.search(r"\d", s):
        cls.append("0-9")
    if re.search(r"[^A-Za-z0-9]", s):
        cls.append("symbols")
    return "+".join(cls)


def _candidate(line: str) -> str | None:
    vals = [m.group(2) for m in _LITERAL.finditer(line)] or [m.group(1) for m in _ASSIGN.finditer(line)]
    return max(vals, key=shannon) if vals else None


def assess_secret_value(value: str | None, path: str | None) -> dict:
    """Pure scoring; returns no part of the value."""
    signals: list[str] = []
    score = 0.55
    if path and TESTY_PATH.search(path):
        score -= 0.25
        signals.append("located in a test/fixture/example path")
    if value is None:
        return {"score": score - 0.1, "signals": signals + ["no literal value on the flagged line"], "entropy": None}
    ent = shannon(value)
    if TEST_KEY_PREFIX.search(value):
        score -= 0.35
        signals.append("vendor test-mode / documentation key prefix")
    if PLACEHOLDER.search(value):
        score -= 0.3
        signals.append("matches a placeholder / dictionary-word pattern")
    if re.fullmatch(r"(.)\1{5,}", value) or len(set(value)) <= 3:
        score -= 0.3
        signals.append("low-variety repeated characters")
    if ent >= 4.0:
        score += 0.25
        signals.append(f"high entropy ({ent:.2f} bits/char)")
    elif ent >= 3.3:
        score += 0.05
        signals.append(f"moderate entropy ({ent:.2f} bits/char)")
    else:
        score -= 0.15
        signals.append(f"low entropy ({ent:.2f} bits/char)")
    signals.append(f"charset {_charset(value)}")
    return {"score": max(0.02, min(0.98, score)), "signals": signals, "entropy": round(ent, 2)}


def triage_secret(f: Finding, root: Path | None, step: Step) -> Validation:
    v = Validation(finding_id=f.id, check="secret-exposure-heuristic", result="error", started_at=now_iso())
    evd: list[Evidence] = [_ev("note", "policy", "The credential is never used, tested against any service, or shown. "
                               "Only local, offline signals are evaluated.")]
    step("Locating the secret in the current tree")
    lines = read_lines(root, f.file)
    value = None
    in_tree = False
    if lines and f.line and f.line <= len(lines):
        value = _candidate(lines[f.line - 1])
        in_tree = value is not None
    where = "present in the current tree (HEAD working copy)" if in_tree else "not in the current tree"
    if not in_tree and root and f.file and (root / ".git").exists():
        r = git(["log", "--all", "--format=%h %ad", "--date=short", "-n", "3", "--", f.file], cwd=root, timeout=30)
        where += ("; file appears in git history: " + ", ".join(r.out.split("\n")[:3])) if r.ok and r.out.strip() else "; not found in history either"
    evd.append(_ev("note", "location", f"{f.file}:{f.line} — {where}"))
    step("Scoring entropy, placeholder and test-path signals")
    a = assess_secret_value(value, f.file)
    evd.append(_ev("note", "signals", "\n".join(f"- {s}" for s in a["signals"])))
    likely_real = a["score"] >= 0.5
    v.result = "confirmed" if likely_real else "not_reproduced"
    v.confidence = round(a["score"] if likely_real else 1 - a["score"], 2)
    action = ("Treat as live: rotate it at the provider, move it to a secret store/env var, and purge it from history."
              if likely_real else "Looks like a test/placeholder value; still move it out of source to silence the finding.")
    if in_tree is False and likely_real:
        action = "Only in history: rotate it and rewrite history (git filter-repo) or accept the exposure."
    evd.append(_ev("note", "verdict", f"{'likely-real' if likely_real else 'likely-test'} credential. {action}"))
    v.evidence = evd
    return v


# =========================================================================== sast
SAST_SYSTEM = (
    "You are Tirith, a defensive application-security reviewer. Decide whether a static-analysis finding "
    "is a true positive by tracing data flow from an attacker-controlled SOURCE to the dangerous SINK in the "
    "code shown. Consider sanitizers, type coercion, framework auto-escaping, and whether the code is even "
    "reachable. Do not propose exploits or payloads. Reply with ONLY JSON: "
    '{"verdict": "true_positive"|"false_positive"|"uncertain", "confidence": 0..1, "source": str, '
    '"sink": str, "sanitizers": [str], "reasoning": str (<=120 words)}'
)

_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
_CLASS = re.compile(r"^(\s*)class\s+(\w+)")
_ROUTE_DEC = re.compile(r"^\s*@\s*[\w.]+\.(?:route|get|post|put|delete|patch|api_view)\s*\(\s*(.*)\)", re.I)


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip())


def enclosing_function(lines: list[str], line: int) -> tuple[str | None, int | None, str | None]:
    """(function name, def line, class name) enclosing 1-based `line`."""
    idx = min(max(line, 1), len(lines)) - 1
    cur = _indent(lines[idx]) if lines[idx].strip() else 10**6
    fn = fn_line = None
    fn_ind = 0
    for i in range(idx, -1, -1):
        m = _DEF.match(lines[i])
        if m and (i == idx or _indent(lines[i]) < cur):
            fn, fn_line, fn_ind = m.group(2), i + 1, _indent(lines[i])
            break
    if fn is None:
        return None, None, None
    if fn_ind == 0:
        return fn, fn_line, None
    for i in range(fn_line - 2, -1, -1):
        if not lines[i].strip():
            continue
        c = _CLASS.match(lines[i])
        if c and _indent(lines[i]) < fn_ind:
            return fn, fn_line, c.group(2)
        if _indent(lines[i]) == 0 and not lines[i].lstrip().startswith(("@", "#")):
            break
    return fn, fn_line, None


def route_reachability(root: Path | None, f: Finding, lines: list[str] | None) -> tuple[bool | None, list[str]]:
    if not root or not lines or not f.line:
        return None, ["no source available"]
    fn, fn_line, cls = enclosing_function(lines, f.line)
    if not fn:
        return None, ["flagged line is at module level (runs on import)"]
    notes = [f"enclosing {'method' if cls else 'function'}: {cls + '.' if cls else ''}{fn} (line {fn_line})"]
    # Flask/FastAPI style decorators right above the def
    j = (fn_line or 1) - 2
    while j >= 0 and lines[j].strip().startswith("@"):
        m = _ROUTE_DEC.match(lines[j])
        if m:
            notes.append(f"route decorator: {lines[j].strip()[:160]}")
            return True, notes
        j -= 1
    # Django: referenced from any urls.py
    target = cls or fn
    pat = re.compile(rf"\b{re.escape(target)}\b")
    hits = []
    for up in root.rglob("urls.py"):
        if any(part in deps.SKIP_DIRS for part in up.parts):
            continue
        try:
            for i, ln in enumerate(up.read_text(errors="replace").splitlines(), 1):
                if pat.search(ln) and ("path(" in ln or "url(" in ln or "re_path(" in ln):
                    hits.append(f"{up.relative_to(root)}:{i}: {ln.strip()[:160]}")
        except OSError:
            continue
    if hits:
        return True, notes + ["routed in:"] + hits[:5]
    # called from another function that is routed? one hop
    callers = []
    for py in (root / (f.file or "")).parent.glob("*.py") if f.file else []:
        try:
            for i, ln in enumerate(py.read_text(errors="replace").splitlines(), 1):
                if re.search(rf"\b{re.escape(fn)}\s*\(", ln) and not _DEF.match(ln):
                    callers.append(f"{py.relative_to(root)}:{i}: {ln.strip()[:120]}")
        except OSError:
            continue
    if callers:
        return True, notes + ["not routed directly; called from:"] + callers[:3]
    return False, notes + [f"no URL route or caller references {target}"]


def triage_sast(f: Finding, root: Path | None, step: Step) -> Validation:
    v = Validation(finding_id=f.id, check=f"sast-dataflow-{(f.cwe or 'review').lower()}", result="error", started_at=now_iso())
    lines = read_lines(root, f.file)
    code, _, _ = window(lines, f.line, 40) if lines else (f.snippet or "", 0, 0)
    code = mask_secrets(code)  # never send credential values to the model
    step("Checking whether the flagged code is reachable from a URL route")
    reachable, notes = route_reachability(root, f, lines)
    evd = [_ev("note", "reachability", "\n".join(notes))]
    step("Asking the model to trace source -> sink")
    streamer = llm.ThinkingStreamer(lambda t: core.emit("ai.thinking", t, finding_id=f.id, data={"phase": "triage"}))
    msgs = [{"role": "system", "content": SAST_SYSTEM},
            {"role": "user", "content": finding_brief(f) + "\n\nReachability: " + "; ".join(notes)
             + "\n\nCode (>> marks the flagged line):\n```\n" + code + "\n```"}]
    try:
        data, res = llm.chat_json(msgs, task="triage_sast", on_reasoning=streamer, stub_context=stub_ctx(f, code),
                                  deadline=llm.deadline_in())
    except (llm.LLMError, ValueError) as e:
        streamer.flush()
        evd.append(_ev("note", "llm error", str(e)[:400]))
        v.result, v.confidence, v.evidence = "error", 0.0, evd
        return v
    streamer.flush()
    verdict = str(data.get("verdict", "uncertain")).lower()
    try:
        conf = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    evd.append(_ev("note", "data flow", f"source: {data.get('source')}\nsink: {data.get('sink')}\n"
                   f"sanitizers: {', '.join(data.get('sanitizers') or []) or 'none'}"))
    evd.append(_ev("note", "model reasoning", f"{data.get('reasoning', '')}\n(model: {res.model})"))
    if verdict == "true_positive":
        v.result = "confirmed"
        v.confidence = round(conf * (1.0 if reachable else 0.75 if reachable is None else 0.6), 2)
    elif verdict == "false_positive":
        v.result, v.confidence = "not_reproduced", round(conf, 2)
    else:
        v.result, v.confidence = "unsupported", round(conf * 0.5, 2)
    v.evidence = evd
    return v


# =========================================================================== lab (dast / config)
def triage_lab(f: Finding, asset: core.Asset | None, step: Step) -> Validation:
    v = Validation(finding_id=f.id, check="lab-passive-check", result="error", started_at=now_iso())
    if asset is None:
        v.result, v.evidence = "unsupported", [_ev("note", "lab", "asset unknown")]
        return v
    step("Booting the isolated lab copy (internal network, no egress)")
    h = lab.get_lab_target(asset)
    if h is None:
        v.result, v.evidence = "unsupported", [_ev("note", "lab", "no lab deployment available (no Dockerfile or boot failed)")]
        return v
    evd = list(h.evidence[:8])
    path = "/"
    if f.url:
        m = re.match(r"https?://[^/]+(/[^\s#]*)?", f.url)
        path = (m.group(1) if m and m.group(1) else "/")
    step(f"Read-only GET {path} in the lab")
    req, resp = lab.get_page(h, path)
    evd += [_ev("request", "lab request", req), _ev("response", "lab response", resp)]
    expect = None
    if f.snippet and "evidence:" in f.snippet:
        expect = f.snippet.split("evidence:", 1)[1].strip().splitlines()[0][:200]
    header_alert = re.search(r"header (?:not set|missing)|missing .*header|x-content-type|anti-clickjacking|content security policy", f"{f.title} {f.description}", re.I)
    if expect:
        hit = expect in resp
        v.result, v.confidence = ("confirmed", 0.85) if hit else ("not_reproduced", 0.6)
        evd.append(_ev("note", "verdict", f"scanner evidence {'reproduced' if hit else 'not seen'} in lab response"))
    elif header_alert and resp:
        v.result, v.confidence = "confirmed", 0.6
        evd.append(_ev("note", "verdict", "response headers captured from the lab copy; compare against the alert"))
    else:
        v.result, v.confidence = ("confirmed", 0.5) if resp else ("not_reproduced", 0.4)
    v.evidence = evd
    return v


# =========================================================================== entry point
def validate_finding(f: Finding, root: Path | None = None, asset: core.Asset | None = None, use_lab: bool | None = None) -> Validation:
    core.audit("remediation.validate", target=f"finding:{f.id}", details={"category": f.category, "rule_id": f.rule_id})
    core.emit("validation.started", f"Validating {f.title}", finding_id=f.id, data={"category": f.category})

    def step(msg: str) -> None:
        core.emit("validation.step", msg, finding_id=f.id)

    try:
        if f.category == "dependency":
            v = triage_dependency(f, root, step)
        elif f.category == "secret":
            v = triage_secret(f, root, step)
        elif f.category == "sast":
            v = triage_sast(f, root, step)
        elif f.category == "dast" or use_lab:
            from . import reproduce
            if f.category == "dast" and reproduce.classify(f):
                step(f"Reproducing by controlled request in the lab ({reproduce.classify(f)})")
                v = reproduce.reproduce(f, lab.get_lab_target(asset) if asset else None, asset)
            else:
                v = triage_lab(f, asset, step)
        else:
            v = Validation(finding_id=f.id, check="config-review", result="unsupported", confidence=f.confidence,
                           evidence=[_ev("note", "config", "No fixed validation template for this config finding; "
                                         "run with lab=true to boot the app in the lab and capture evidence.")],
                           started_at=now_iso())
        if use_lab and f.category in ("dependency", "secret", "sast"):
            lv = triage_lab(f, asset, step)
            v.evidence += [e for e in lv.evidence if e.label in ("boot probe", "egress check", "lab network", "lab response")]
    except Exception as e:  # never leave a validation hanging
        v = Validation(finding_id=f.id, check="error", result="error", confidence=0.0,
                       evidence=[_ev("note", "error", f"{type(e).__name__}: {e}"[:500])], started_at=now_iso())
    v.finished_at = now_iso()
    core.save_validation(v)
    status = {"confirmed": "validated", "not_reproduced": "not_reproduced"}.get(v.result)
    fields = {"validation": v, "confidence": v.confidence}
    if status and f.status not in ("fixing", "fixed"):
        fields["status"] = status
    core.update_finding(f.id, **fields)
    core.record_posture(f.asset_id)  # validation re-weights priority/risk (not_reproduced closes it)
    level = {"confirmed": "warn", "not_reproduced": "success", "error": "error"}.get(v.result, "info")
    core.emit("validation.result", f"{f.title}: {v.result} ({v.confidence:.0%})", level=level, finding_id=f.id,
              data={"validation_id": v.id, "result": v.result, "confidence": v.confidence, "check": v.check})
    core.audit("remediation.validate.result", target=f"finding:{f.id}", details={"result": v.result, "confidence": v.confidence})
    return v
