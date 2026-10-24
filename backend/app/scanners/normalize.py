"""Pure normalizers: raw tool JSON -> list[Finding]. No I/O except optional source reads for snippets."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..models import Advisory, Finding

CONTAINER_SRC = "/src"  # legacy: container-mode reports still carry it
MAX_SNIPPET_LINES = 8


@dataclass
class Ctx:
    scan_id: str
    asset_id: str
    src_root: Path | None = None  # host path of the scanned tree: reports are relative to it, and
    # a legacy absolute `/src/...` or `<src_root>/...` path is cut back to the relative form


def fingerprint(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _strip_prefixes(p: str, root: Path | None) -> str:
    prefixes = [CONTAINER_SRC + "/", CONTAINER_SRC]
    if root is not None:
        r = str(root.resolve()).rstrip("/")
        prefixes = [r + "/", r, *prefixes]
    for prefix in prefixes:
        if p == prefix:
            return ""
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return p


def rel_path(p: str | None, root: Path | None = None) -> str | None:
    """Report path -> path relative to the scanned tree. The tools run with cwd = src and report
    relative paths; an absolute one (legacy /src/... or the host tree) is cut back to relative."""
    if not p:
        return None
    p = _strip_prefixes(p, root)
    return p[2:] if p.startswith("./") else p


def _read_lines(ctx: Ctx, rel: str | None) -> list[str] | None:
    if not ctx.src_root or not rel:
        return None
    try:
        root = ctx.src_root.resolve()
        fp = (root / rel).resolve()
        if not fp.is_relative_to(root) or not fp.is_file() or fp.stat().st_size > 2_000_000:
            return None
        return fp.read_text(errors="replace").splitlines()
    except OSError:
        return None


def read_snippet(ctx: Ctx, rel: str | None, start: int | None, end: int | None = None) -> str | None:
    lines = _read_lines(ctx, rel)
    if lines is None or not start:
        return None
    end = max(start, end or start)
    end = min(end, start + MAX_SNIPPET_LINES - 1)
    chunk = lines[start - 1 : end]
    return "\n".join(chunk) if chunk else None


def redact(text: str, keep: int = 0) -> str:
    """Mask a secret. keep>0 is only for non-secret prefixes; secret characters are never kept."""
    text = text.strip()
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * max(4, min(len(text) - keep, 24))


# --------------------------------------------------------------------------- secret classification
SECRET_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-522"}
SECRET_RULES = {"DS-0031", "DS031", "AVD-DS-0031"}  # trivy: secrets in Dockerfile ENV/ARG
_SECRET_NAME = r"(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?|signing[_-]?key)"
# NAME = "value" / NAME: value / ENV NAME=value / "name": "value"  (value = 4+ non-space chars)
SECRET_ASSIGN = re.compile(
    rf"""(?ix)
    (?P<name>[\w.\-]*{_SECRET_NAME}[\w.\-]*)
    (?P<sep>["']?\s*(?:=|:)\s*)
    (?P<q>["'`]?)
    (?P<val>[^\s"'`,;)]{{4,}})
    """
)
_STRING_LIT = re.compile(r"""(?P<q>["'`])(?P<val>(?:\\.|(?!(?P=q)).){4,}?)(?P=q)""")


def mask_secret_assignments(text: str) -> str:
    """Mask the value of obvious secret assignments (PASSWORD = "x", ENV API_KEY=x, token: x)."""
    def _sub(m: re.Match) -> str:
        val = m.group("val")
        if not m.group("q") and re.search(r"[.(\[]", val):  # unquoted code (request.POST.get(...)), not a literal
            return m.group(0)
        if val.lower() in ("none", "null", "true", "false") or val.startswith(("os.", "env", "getenv", "$", "{", "<")):
            return m.group(0)
        return m.group("name") + m.group("sep") + m.group("q") + redact(val)
    return SECRET_ASSIGN.sub(_sub, text)


def mask_string_literals(text: str) -> str:
    return _STRING_LIT.sub(lambda m: m.group("q") + redact(m.group("val")) + m.group("q"), text)


def has_secret_assignment(text: str | None) -> bool:
    return bool(text) and mask_secret_assignments(text) != text


def is_secret_class(rule: str | None, cwe: str | None, category: str | None = None, code: str | None = None) -> bool:
    if category == "secret" or (cwe and cwe in SECRET_CWES):
        return True
    if rule and rule.upper() in SECRET_RULES:
        return True
    return has_secret_assignment(code)


def mask_secret_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Mask known secret values, string literals and secret assignments in a snippet."""
    for sec in secrets:
        if sec and len(sec) >= 4:
            text = text.replace(sec, redact(sec))
    return mask_string_literals(mask_secret_assignments(text))


def redacted_line(
    ctx: Ctx, rel: str | None, line: int | None, col_start: int | None, col_end: int | None,
    secrets: tuple[str, ...] = (),
) -> str:
    """Return the source line with the secret masked. Never returns the secret itself.

    Columns are treated loosely: gitleaks reports them shifted by one on every line but the
    first, so the masked span is widened by one character on each side; known secret values,
    string literals and secret assignments are masked as well.
    """
    lines = _read_lines(ctx, rel)
    if lines is None or not line or line > len(lines):
        return "[REDACTED]"
    text = lines[line - 1]
    if col_start and col_end and col_end >= col_start:
        s, e = max(0, col_start - 2), min(col_end + 1, len(text))
        text = text[:s] + redact(text[s:e]) + text[e:]
    elif not secrets:
        return redact(text) or "[REDACTED]"
    return mask_secret_text(text, secrets)


def _mask_block(code: str) -> str:
    """Secret-class multi-line match: keep the first line (masked), drop the rest."""
    lines = code.splitlines() or [""]
    head = mask_secret_text(lines[0])
    if head == lines[0]:
        head = redact(head)
    return head + (f"\n[{len(lines) - 1} more line(s) redacted]" if len(lines) > 1 else "")


def _code_key(code: str | None, secret: bool = False) -> str:
    """Normalized matched code for fingerprints: whitespace-collapsed, secrets masked out."""
    c = _collapse(code)
    if secret:
        c = _collapse(mask_string_literals(mask_secret_assignments(c)))
    return c


def secret_digest(*parts: str) -> str:
    """Slow, salted hash of a secret value (fingerprints must not let anyone brute-force it)."""
    salt, value = "|".join(parts[:-1]).encode(), parts[-1].encode()
    return hashlib.pbkdf2_hmac("sha256", value, b"tirith-fp|" + salt, 20_000).hex()[:32]


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def find_manifest_line(ctx: Ctx, rel: str | None, pkg: str) -> int | None:
    """Best-effort: line in a manifest (requirements.txt, package.json, ...) that names `pkg`."""
    lines = _read_lines(ctx, rel)
    if not lines:
        return None
    want = _norm_pkg(pkg)
    pat = re.compile(r'^[\s"\']*([A-Za-z0-9@/_.\-]+)')
    for i, text in enumerate(lines, 1):
        m = pat.match(text)
        if m and _norm_pkg(m.group(1)) == want:
            return i
    return None


_CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def norm_cwe(val: Any) -> str | None:
    if not val:
        return None
    if isinstance(val, (list, tuple)):
        val = val[0] if val else None
        if not val:
            return None
    s = str(val)
    m = _CWE_RE.search(s)
    if m:
        return f"CWE-{m.group(1)}"
    if s.isdigit() and s not in ("0", "-1"):
        return f"CWE-{s}"
    return None


def _strip_html(s: str | None) -> str:
    if not s:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def _collapse(s: str | None) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


# --------------------------------------------------------------------------- semgrep
_SG_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_CONF = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.4}


def normalize_semgrep(data: dict, ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[str, int] = {}
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = r.get("check_id") or "semgrep"
        rel = rel_path(r.get("path"), ctx.src_root)
        start = (r.get("start") or {}).get("line")
        end = (r.get("end") or {}).get("line")
        cwe = norm_cwe(meta.get("cwe"))
        sev = _SG_SEV.get(str(extra.get("severity", "")).upper(), "medium")
        if sev == "medium" and str(meta.get("impact", "")).upper() == "HIGH" and str(meta.get("likelihood", "")).upper() in ("HIGH", "MEDIUM"):
            sev = "high"
        lines = extra.get("lines")
        lines = lines if lines and lines != "requires login" else None
        code = read_snippet(ctx, rel, start, end) or lines
        # Secret-class: semgrep secrets rules and hard-coded credential CWEs (category "secret").
        is_secret = ("secret" in rule.lower() or meta.get("category") == "secrets"
                     or "secrets" in str(meta.get("subcategory", "")).lower() or is_secret_class(rule, cwe))
        masked = False
        if is_secret:
            sc, ec = (r.get("start") or {}).get("col"), (r.get("end") or {}).get("col")
            snippet = redacted_line(ctx, rel, start, sc, ec) if start == end else None
            if not snippet or snippet == "[REDACTED]":
                snippet = _mask_block(code) if code else "[REDACTED]"
            masked = True
        elif has_secret_assignment(code):  # e.g. PASSWORD = "..." inside a SQLi match: mask the value
            snippet, masked = mask_secret_assignments(code), True
        else:
            snippet = code
        sg_fp = extra.get("fingerprint")
        sg_fp = sg_fp if sg_fp and sg_fp != "requires login" else None
        key = _code_key(code, secret=masked) or sg_fp or ""
        base = fingerprint("semgrep", rule, rel, key)
        n = seen.get(base, 0)
        seen[base] = n + 1
        fp = base if n == 0 else fingerprint(base, n)
        vc = meta.get("vulnerability_class")
        title = vc[0] if isinstance(vc, list) and vc and vc[0] != "Other" else None
        short = rule.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ")
        refs = meta.get("references") or []
        out.append(
            Finding(
                scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fp, tool="semgrep", rule_id=rule,
                title=f"{title}: {short}" if title else short.capitalize(),
                description=extra.get("message") or "",
                severity=sev, category="secret" if is_secret else "sast",
                file=rel, line=start, snippet=snippet, cwe=cwe,
                url=meta.get("source") or (refs[0] if refs else None),
                confidence=_CONF.get(str(meta.get("confidence", "")).upper(), 0.6),
            )
        )
    return out


# --------------------------------------------------------------------------- gitleaks
def normalize_gitleaks(data: list | None, ctx: Ctx) -> list[Finding]:
    """Fingerprint = rule + file + salted hash of the secret value (no line, no commit), so the
    same secret keeps its finding across line shifts and history. Raw values never leave here."""
    out: list[Finding] = []
    seen: set[str] = set()
    for r in data or []:
        rule = r.get("RuleID") or "gitleaks"
        rel = rel_path(r.get("File"), ctx.src_root)
        line = r.get("StartLine")
        secret = r.get("Secret") or ""
        match = r.get("Match") or ""
        known = tuple(v for v in (secret, match) if v and v != "REDACTED")
        same_line = r.get("StartLine") == r.get("EndLine")
        snippet = redacted_line(ctx, rel, line, r.get("StartColumn"), r.get("EndColumn") if same_line else None, known)
        if known:
            key = secret_digest("gitleaks", rule, rel or "", known[0])
        else:  # redacted report: masked source line (stable across line shifts, no secret material)
            key = _code_key(snippet, secret=True) if snippet != "[REDACTED]" else ""
        fp = fingerprint("gitleaks", rule, rel, key)
        if fp in seen:  # same secret in several commits / places in the file
            continue
        seen.add(fp)
        commit = r.get("Commit") or None
        desc = r.get("Description") or "Hard-coded secret"
        if commit:
            desc += f" (commit {commit[:12]})"
        out.append(
            Finding(
                scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fp, tool="gitleaks", rule_id=rule,
                title=f"Hard-coded secret: {rule}", description=desc, severity="high", category="secret",
                file=rel, line=line, snippet=snippet, cwe="CWE-798", confidence=0.8,
            )
        )
    return out


# --------------------------------------------------------------------------- trivy
_TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}


def normalize_trivy(data: dict, ctx: Ctx, group: bool = True) -> list[Finding]:
    """group=True (default): one dependency finding per package+manifest (see group_dependencies)."""
    out: list[Finding] = []
    seen: set[str] = set()
    for res in data.get("Results") or []:
        target = rel_path(res.get("Target"), ctx.src_root)
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or "trivy-vuln"
            pkg = v.get("PkgName")
            inst = v.get("InstalledVersion")
            fp = fingerprint("trivy", vid, pkg, inst, target)
            if fp in seen:
                continue
            seen.add(fp)
            line = None
            locs = v.get("PkgLocations") or (v.get("Locations") or [])
            if locs and isinstance(locs[0], dict):
                line = locs[0].get("StartLine")
            if not line and pkg:
                line = find_manifest_line(ctx, target, pkg)
            fixed = v.get("FixedVersion") or None
            title = v.get("Title") or vid
            out.append(
                Finding(
                    scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fp, tool="trivy", rule_id=vid,
                    title=f"{pkg} {inst}: {title}", description=(v.get("Description") or "").strip(),
                    severity=_TRIVY_SEV.get(str(v.get("Severity", "")).upper(), "info"), category="dependency",
                    file=target, line=line, snippet=f"{pkg}=={inst}" if pkg and inst else None,
                    cwe=norm_cwe(v.get("CweIDs")), cve=vid if vid.upper().startswith("CVE-") else None,
                    package=pkg, installed_version=inst, fixed_version=fixed,
                    url=v.get("PrimaryURL"), confidence=0.9 if fixed else 0.8,
                )
            )
        for m in res.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            mid = m.get("ID") or m.get("AVDID") or "trivy-misconfig"
            cause = m.get("CauseMetadata") or {}
            start = cause.get("StartLine")
            code_lines = ((cause.get("Code") or {}).get("Lines")) or []
            snippet = "\n".join(l.get("Content", "") for l in code_lines[:MAX_SNIPPET_LINES]) or read_snippet(ctx, target, start, cause.get("EndLine"))
            mcwe = norm_cwe(m.get("CweIDs"))
            if snippet and (is_secret_class(mid, mcwe, code=snippet) or str(m.get("AVDID", "")).upper() in SECRET_RULES):
                snippet = mask_secret_text(snippet)
            fp = fingerprint("trivy", mid, target, m.get("Message"))
            if fp in seen:
                continue
            seen.add(fp)
            desc = (m.get("Description") or "").strip()
            if m.get("Message"):
                desc = f"{m['Message']}. {desc}".strip()
            if m.get("Resolution"):
                desc += f"\nResolution: {m['Resolution']}"
            out.append(
                Finding(
                    scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fp, tool="trivy", rule_id=mid,
                    title=m.get("Title") or mid, description=desc,
                    severity=_TRIVY_SEV.get(str(m.get("Severity", "")).upper(), "info"), category="config",
                    file=target, line=start, snippet=snippet or None, cwe=mcwe, url=m.get("PrimaryURL"), confidence=0.85,
                )
            )
    return group_dependencies(out) if group else out


# --------------------------------------------------------------------------- dependency grouping
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def best_fixed_version(installed: str, advisories: list[Advisory]) -> tuple[str | None, int]:
    """The single version (from the advisories' fixed lists, above `installed`) that resolves the
    most advisories; ties -> the lowest such version (least disruptive). Returns (version, resolved)."""
    from ..remediation.deps import fixed_candidates, in_affected_range, parse_version, vlt

    cands = {c for a in advisories for c in fixed_candidates(a.fixed_version) if not installed or vlt(installed, c)}
    best, best_n = None, 0
    for c in sorted(cands, key=parse_version):
        n = sum(1 for a in advisories if a.fixed_version and not in_affected_range(c, a.fixed_version)[0])
        if n > best_n:
            best, best_n = c, n
    return best, best_n


def _same_line_best(installed: str, advisories: list[Advisory]) -> tuple[str, int] | None:
    from ..remediation.deps import _release, fixed_candidates

    line = _release(installed)[:2]
    if len(line) < 2:
        return None
    same = [Advisory(id=a.id, severity=a.severity,
                     fixed_version=", ".join(c for c in fixed_candidates(a.fixed_version) if _release(c)[:2] == line) or None)
            for a in advisories]
    v, n = best_fixed_version(installed, same)
    if not v:
        return None
    from ..remediation.deps import in_affected_range

    return v, sum(1 for a in advisories if a.fixed_version and not in_affected_range(v, a.fixed_version)[0])


def group_dependencies(findings: list[Finding]) -> list[Finding]:
    """Collapse per-advisory dependency findings into one per (manifest, package).

    severity = max, fixed_version = best_fixed_version, advisories = every CVE/GHSA (worst first),
    cve = the worst advisory's CVE. Fingerprint is (package, manifest) only, so it survives version
    bumps and turns `fixed` once trivy reports no advisory for the package.
    """
    groups: dict[tuple, list[Finding]] = {}
    order: list[tuple] = []
    out: list[Finding] = []
    for f in findings:
        if f.category != "dependency" or not f.package:
            out.append(f)
            continue
        key = (f.file, _norm_pkg(f.package))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    grouped: list[Finding] = []
    for key in order:
        fs = sorted(groups[key], key=lambda x: (_SEV_RANK.get(x.severity, 5), x.rule_id))
        worst = fs[0]
        advs = [
            Advisory(id=x.rule_id, severity=x.severity, title=x.title.split(": ", 1)[-1], fixed_version=x.fixed_version,
                     url=x.url, cwe=x.cwe)
            for x in fs
        ]
        inst = worst.installed_version or ""
        fixed, resolved = best_fixed_version(inst, advs)
        n = len(advs)
        sev_counts: dict[str, int] = {}
        for a in advs:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        sev_txt = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items(), key=lambda kv: _SEV_RANK.get(kv[0], 5)))
        title = f"{worst.package} {inst}: {n} known vulnerabilit{'y' if n == 1 else 'ies'}"
        if fixed:
            title += f" (upgrade to {fixed})"
        lines = [f"{worst.package} {inst} in {worst.file} has {n} advisor{'y' if n == 1 else 'ies'} ({sev_txt})."]
        if fixed:
            lines.append(f"Upgrading to {fixed} resolves {resolved} of {n}.")
            same_line = _same_line_best(inst, advs)
            if same_line and same_line[0] != fixed:
                lines.append(f"Staying on the {'.'.join(inst.split('.')[:2])}.x line: {same_line[0]} resolves {same_line[1]} of {n}.")
        else:
            lines.append("No single released version resolves these advisories.")
        for a in advs:
            lines.append(f"- {a.id} [{a.severity}] {a.title}" + (f" (fixed in {a.fixed_version})" if a.fixed_version else " (no fix)"))
        cve = next((a.id for a in advs if a.id.upper().startswith("CVE-")), None)
        grouped.append(
            worst.model_copy(update={
                "fingerprint": fingerprint("trivy-pkg", _norm_pkg(worst.package), worst.file),
                "rule_id": f"dependency:{_norm_pkg(worst.package)}",
                "title": title,
                "description": "\n".join(lines),
                "cve": cve,
                "fixed_version": fixed,
                "advisories": advs,
                "confidence": 0.9 if fixed else 0.8,
            })
        )
    return grouped + out


# --------------------------------------------------------------------------- nmap
_XML_ENTITY = re.compile(r"&(#x?[0-9A-Fa-f]+|amp|lt|gt|quot|apos);")
_XML_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}


def _xml_unescape(s: str) -> str:
    """nmap XML is escaped once; unescape it here so nothing is double-escaped down the line."""

    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name.startswith("#"):
            try:
                return chr(int(name[2:], 16) if name[1:2] in ("x", "X") else int(name[1:]))
            except ValueError:
                return m.group(0)
        return _XML_ENTITIES.get(name, m.group(0))

    return _XML_ENTITY.sub(sub, s)


def _xml_attr(tag: str, name: str) -> str | None:
    m = re.search(rf'\b{name}="([^"]*)"', tag)
    return _xml_unescape(m.group(1)) if m else None


_PORT_STATE = re.compile(r'<port protocol="([^"]*)" portid="(\d+)"')
_RISKY_SERVICE = re.compile(r"^(?:ftp|telnet|smtp|http|https|http-alt|ms-wbt-server|rdesktop|rdp|"
                            r"mysql|postgresql|postgres|mssql|redis|mongodb|vnc|"
                            r"elasticsearch|docker|ldap|nfs|rsync|smb|netbios-.*)$", re.I)


def _port_service_finding(scan_id: str, asset_id: str, host: str, proto: str, port: str,
                          extra: str) -> Finding:
    name = _xml_attr(extra, "name") or "unknown"
    product = _xml_attr(extra, "product")
    version = _xml_attr(extra, "version")
    extrainfo = _xml_attr(extra, "extrainfo")
    label = " ".join(x for x in (product, version) if x)
    service = f"{name} {label}".strip() if label else name
    cmd = re.search(r'<service name="[^"]*"[^>]*method="probed"', extra) is not None
    # An exposed service: medium when the port answers a real handshake, low when nmap only saw a socket.
    sev = "medium" if (name != "unknown" or cmd) else "low"
    parts = [f"{proto}/{port}", f"service: {service}"]
    for key in ("ostype",):
        if v := _xml_attr(extra, key):
            parts.append(f"{key}: {v}")
    if extrainfo:
        parts.append(f"info: {extrainfo}")
    for script in re.findall(r'<script id="([^"]*)"', extra):
        parts.append(f"script: {_xml_unescape(script)}")
    title = f"Open port {port}/{proto}" + (f" ({service})" if service != "unknown" else "")
    desc = f"{host} answers on {port}/{proto} with {service}."
    cves = [c for c in re.findall(r'<elem key="([^"]*)"', extra) if c.startswith("CVE-")]
    return Finding(
        scan_id=scan_id, asset_id=asset_id,
        fingerprint=fingerprint("nmap", host, proto, port, name),
        tool="nmap", rule_id=f"nmap-port-{proto}-{port}", title=title, description=desc,
        severity=sev, category="dast", snippet="\n".join(parts), url=f"{proto}://{host}:{port}",
        cve=cves[0] if cves else None, confidence=0.9 if name != "unknown" else 0.6,
        tags=[f"host:{host}"],  # host findings carry no file: scope/profile matching needs this
    )


def normalize_nmap(data: str, ctx: Ctx) -> list[Finding]:
    """`nmap -oX -` XML (one or more hosts): a finding per open port, one info note when a host is down.

    nmap's XML is machine-shaped and stable; a regex walk keeps this normalizer dependency-free and
    tolerates extra output (scripts, tabs) without a strict schema.
    """
    out: list[Finding] = []
    for host_tag in re.findall(r"<host\b[^>]*>.*?</host>", data or "", re.S):
        addr_el = re.search(r"<address addr=\"[^\"]*\"[^>]*>", host_tag)
        addr = (_xml_attr(addr_el.group(0), "addr") if addr_el else None) or _xml_attr(host_tag, "name") or "host"
        st_el = re.search(r"<status [^>]*>", host_tag)
        status = (_xml_attr(st_el.group(0), "state") if st_el else None) or "unknown"
        if status != "up":
            reason = _xml_attr(st_el.group(0), "reason") if st_el else ""
            out.append(Finding(
                scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fingerprint("nmap", addr, "down"),
                tool="nmap", rule_id="nmap-host-down", title=f"Host {addr} did not answer",
                description=f"nmap reports {addr} as {status}" + (f" ({reason})." if reason else "."),
                severity="info", category="dast", snippet=f"host: {addr}\nstate: {status}",
                url=f"//{addr}", confidence=0.8, tags=[f"host:{addr}"],
            ))
            continue
        names = [n for n in (_xml_attr(m.group(0), "name") for m in re.finditer(r"<hostname [^>]*>", host_tag)) if n]
        for m in _PORT_STATE.finditer(host_tag):
            proto, port = m.group(1), m.group(2)
            end = host_tag.find("</port>", m.end())
            block = host_tag[m.end(): end if end != -1 else m.end()]
            st = re.search(r'<state [^>]*state="([^"]*)"', block)
            if st and st.group(1) != "open":
                continue
            f = _port_service_finding(ctx.scan_id, ctx.asset_id, addr, proto, port, block)
            f.tags += [f"hostname:{n}" for n in names]
            if _RISKY_SERVICE.match(_xml_attr(block, "name") or ""):
                f.confidence = min(0.95, f.confidence + 0.05)
            out.append(f)
    return out


# --------------------------------------------------------------------------- zap
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONF = {"4": 0.95, "3": 0.85, "2": 0.6, "1": 0.35, "0": 0.1}


def _zap_path(uri: str) -> str:
    """URL path only (scheme/host/port/query stripped) so fingerprints survive new lab hostnames."""
    from urllib.parse import urlsplit

    try:
        return urlsplit(uri).path or "/"
    except ValueError:
        return uri


def normalize_zap(data: dict, ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for site in data.get("site") or []:
        site_name = site.get("@name") or ""
        for a in site.get("alerts") or []:
            pid = str(a.get("pluginid") or "zap")
            ref = a.get("alertRef") or pid
            first_uri = ((a.get("instances") or [{}])[0] or {}).get("uri") or site_name
            fp = fingerprint("zap", ctx.asset_id, pid, _zap_path(first_uri), (((a.get("instances") or [{}])[0]) or {}).get("param") or "")
            if fp in seen:
                continue
            seen.add(fp)
            inst = a.get("instances") or []
            first = inst[0] if inst else {}
            desc = _strip_html(a.get("desc"))
            sol = _strip_html(a.get("solution"))
            if sol:
                desc += f"\nSolution: {sol}"
            if len(inst) > 1:
                desc += f"\nSeen on {len(inst)} URLs."
            ev_parts = [f"{first.get('method', 'GET')} {first.get('uri', site_name)}"]
            if first.get("param"):
                ev_parts.append(f"param: {first['param']}")
            if first.get("evidence"):
                ev_parts.append(f"evidence: {first['evidence']}")
            out.append(
                Finding(
                    scan_id=ctx.scan_id, asset_id=ctx.asset_id, fingerprint=fp, tool="zap", rule_id=f"zap-{pid}",
                    title=a.get("name") or a.get("alert") or f"ZAP {pid}", description=desc,
                    severity=_ZAP_RISK.get(str(a.get("riskcode")), "info"), category="dast",
                    snippet="\n".join(ev_parts), cwe=norm_cwe(a.get("cweid")),
                    file=_zap_path(first_uri or site_name),  # the URL path: sub-app/profile classification
                    url=first.get("uri") or site_name, confidence=_ZAP_CONF.get(str(a.get("confidence")), 0.5),
                )
            )
    return out


NORMALIZERS: dict[str, Callable[[Any, Ctx], list[Finding]]] = {
    "semgrep": normalize_semgrep,
    "gitleaks": normalize_gitleaks,
    "trivy": normalize_trivy,
    "zap": normalize_zap,
    "nmap": normalize_nmap,
}
