"""Read-only helpers to pull code context for a finding out of the asset's source tree."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from .core import Finding

MAX_FILE_BYTES = 2_000_000

# --------------------------------------------------------------------------- secret masking
# Anything that goes to the LLM (or into a stored/emitted diff) passes through mask_secrets first.
REDACTED = "***REDACTED***"
SECRET_KEY_RE = re.compile(
    r"pass(?:word|wd|phrase)?|secret|token|api[_-]?key|apikey|private[_-]?key|credential|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?key|dsn|conn(?:ection)?[_-]?str", re.I)
STR_LIT_RE = re.compile(r"""(?P<q>['"])(?P<v>(?:\\.|(?!(?P=q)).){6,}?)(?P=q)""")
_BARE_ASSIGN_RE = re.compile(r"""(?P<k>[\w.-]*)(?P<sep>\s*[:=]\s*)(?P<v>[^\s'",;#]{6,})""")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _secretish_literal(v: str, keyed: bool) -> bool:
    if any(ch.isspace() for ch in v) or SECRET_KEY_RE.fullmatch(v):
        return False  # prose / SQL / the key name itself
    if keyed:
        return True
    return len(v) >= 20 and entropy(v) >= 4.0


def mask_secrets(text: str, values: tuple[str, ...] | list[str] = ()) -> str:
    """Replace likely credential values with REDACTED: explicit `values`, string literals on lines that
    name a secret (password=, api_key: ...), long high-entropy literals, and PEM private-key blocks."""
    if not text:
        return text
    for v in sorted({v for v in values if v and len(v) >= 4}, key=len, reverse=True):
        text = text.replace(v, REDACTED)
    out: list[str] = []
    in_pem = False
    for line in text.splitlines(keepends=True):
        if in_pem or _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            out.append(re.sub(r"[A-Za-z0-9+/=]{16,}", REDACTED, line))
            continue
        keyed = bool(SECRET_KEY_RE.search(line))
        new = STR_LIT_RE.sub(lambda m: m["q"] + REDACTED + m["q"] if _secretish_literal(m["v"], keyed) else m[0], line)
        if keyed and new == line and "'" not in line and '"' not in line:
            new = _BARE_ASSIGN_RE.sub(
                lambda m: m["k"] + m["sep"] + REDACTED if SECRET_KEY_RE.search(m["k"]) and _secretish_literal(m["v"], True) else m[0],
                line)
        out.append(new)
    return "".join(out)


def safe_path(root: Path, rel: str | None) -> Path | None:
    if not rel:
        return None
    try:
        r = root.resolve()
        p = (r / rel).resolve()
    except OSError:
        return None
    if not p.is_relative_to(r) or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
        return None
    return p


def read_lines(root: Path | None, rel: str | None) -> list[str] | None:
    if root is None:
        return None
    p = safe_path(root, rel)
    if p is None:
        return None
    try:
        return p.read_text(errors="replace").splitlines()
    except OSError:
        return None


def window(lines: list[str], line: int | None, radius: int = 25) -> tuple[str, int, int]:
    """Numbered code window around `line` (1-based). Returns (text, start, end)."""
    if not lines:
        return "", 0, 0
    ln = max(1, min(line or 1, len(lines)))
    s, e = max(1, ln - radius), min(len(lines), ln + radius)
    out = []
    for i in range(s, e + 1):
        mark = ">>" if i == ln else "  "
        out.append(f"{mark}{i:5d}  {lines[i - 1]}")
    return "\n".join(out), s, e


def code_context(root: Path | None, f: Finding, radius: int = 25) -> str:
    if f.category == "secret":
        return f.snippet or ""  # never send a raw secret to the model; the core already redacted it
    lines = read_lines(root, f.file)
    if not lines:
        return f.snippet or ""
    text, _, _ = window(lines, f.line, radius)
    return mask_secrets(text)


def finding_brief(f: Finding) -> str:
    parts = [
        f"Tool: {f.tool}  Rule: {f.rule_id}",
        f"Title: {f.title}",
        f"Severity: {f.severity}  Category: {f.category}  CWE: {f.cwe or '-'}  CVE: {f.cve or '-'}",
    ]
    if f.file:
        parts.append(f"Location: {f.file}:{f.line or '?'}")
    if f.package:
        parts.append(f"Package: {f.package} installed {f.installed_version} fixed in {f.fixed_version or 'n/a'}")
    if f.url:
        parts.append(f"Reference: {f.url}")
    if f.description:
        parts.append("Scanner description:\n" + f.description[:2500])
    return "\n".join(parts)


def stub_ctx(f: Finding, snippet: str | None = None) -> dict:
    return {
        "title": f.title, "rule_id": f.rule_id, "category": f.category, "cwe": f.cwe, "file": f.file,
        "line": f.line, "snippet": snippet if snippet is not None else f.snippet,
    }
