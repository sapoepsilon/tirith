"""Posture scoring (v1.1: priority-weighted).

Each open finding contributes risk = priority / 10, where priority = 100 x severity x confidence
x reachability x validated (see app.focus). So a confirmed critical in the main app ~ 9-10,
an unvalidated high ~ 4, the same high in a lab sub-app ~ 1.3, info ~ 0.

    score = round(100 x (K + credit) / (K + credit + risk_open)),  K = 25
    risk_open = main-app risk + LAB_CAP x (1 - exp(-lab_risk / LAB_CAP)),  LAB_CAP = 10
              (lab sub-apps are intentionally vulnerable training content: they still count,
               but saturate at ~10 risk points so they can't drown out the main app)
    credit = 0.5 x min(risk_fixed, 2K)   (progress credit: closing findings by *fixing* them,
                                           not by dismissing them, earns up to +K/... points)

Open = models.OPEN_STATUSES (every status except `fixed` and `not_reproduced`); `counts` is the
severity tally of store.list_open_findings(asset_id), i.e. GET /findings?asset_id=..&status=open,validated,fixing.
Lab sub-apps are in `counts`; `main_counts` excludes them (it drives the grade cap). Grade: A>=90 B>=80 C>=70 D>=60 else F,
and an open critical in the main app (not a lab sub-app) caps the grade at C. Fixing a
top-priority finding visibly moves the score: it removes its risk and adds progress credit.
"""

from __future__ import annotations

import math

from .events import emit
from .focus import CLOSED, LAB_TAG, priority, risk_weight
from .models import Finding, Posture, SEVERITIES, TopAction, zero_counts
from .remediation import deps
from .store import get_store

K = 25.0
CREDIT_RATE = 0.5
LAB_CAP = 10.0
# Legacy severity weights (counts-only scoring, kept for callers that only have counts).
WEIGHTS = {"critical": 15, "high": 7, "medium": 3, "low": 1, "info": 0}


def score_counts(counts: dict[str, int]) -> int:
    """Counts-only approximation (no confidence/reachability info): legacy curve."""
    raw = sum(WEIGHTS[s] * counts.get(s, 0) for s in SEVERITIES)
    return int(round(100 / (1 + raw / 50)))


def score_risk(risk_open: float, risk_fixed: float = 0.0) -> int:
    credit = CREDIT_RATE * min(risk_fixed, 2 * K)
    return int(round(100 * (K + credit) / (K + credit + risk_open)))


def grade_for(score: int, counts: dict[str, int]) -> str:
    g = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    if counts.get("critical", 0) > 0 and g in ("A", "B"):
        g = "C"
    return g


def _is_lab(f: Finding) -> bool:
    return LAB_TAG in f.tags or f.component.startswith("lab:")


def compute(findings: list[Finding], asset_id: str | None = None, history: list[dict] | None = None) -> Posture:
    counts, main_counts = zero_counts(), zero_counts()
    open_n = fixed_n = lab_open = 0
    risk_main = risk_lab = risk_fixed = 0.0
    for f in findings:
        if f.status == "fixed":
            fixed_n += 1
            # credit uses the risk the finding carried while open (validation kept on the record)
            risk_fixed += risk_weight(f)
        if f.status in CLOSED:
            continue
        open_n += 1
        counts[f.severity] += 1
        if _is_lab(f):
            lab_open += 1
            risk_lab += risk_weight(f)
        else:
            main_counts[f.severity] += 1
            risk_main += risk_weight(f)
    risk_open = risk_main + LAB_CAP * (1 - math.exp(-risk_lab / LAB_CAP))
    score = score_risk(risk_open, risk_fixed)
    return Posture(
        asset_id=asset_id, score=score, grade=grade_for(score, main_counts),
        counts=counts, open=open_n, fixed=fixed_n, history=history or [],
        risk=round(risk_open, 1), risk_fixed=round(risk_fixed, 1), main_counts=main_counts, lab_open=lab_open,
        top_actions=top_actions(findings),
    )


# --------------------------------------------------------------------------- top actions
# Plain-language "Top 3 fixes" for non-experts. Deterministic, no LLM: open findings are grouped by the
# one action that closes them (one package bump, one file's secrets, one scanner rule), groups are ranked
# by their best finding's priority (then total priority, then size, then key), and the top 3 are worded
# from templates. Titles/paths/package names come from scan data, so clients treat them as untrusted.
TOP_N = 3
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # critical=0 .. info=4

# CWE -> (short name, what an attacker could do), worded for someone who is not a security person.
_CWE_PLAIN = {
    "CWE-89": ("SQL injection", "an attacker could read or change data in your database"),
    "CWE-79": ("cross-site scripting (XSS)", "an attacker could run their own script in your users' browsers"),
    "CWE-78": ("command injection", "an attacker could run commands on your server"),
    "CWE-77": ("command injection", "an attacker could run commands on your server"),
    "CWE-94": ("code injection", "an attacker could run their own code inside your app"),
    "CWE-95": ("code injection", "an attacker could run their own code inside your app"),
    "CWE-1336": ("template injection", "an attacker could run their own code inside your app"),
    "CWE-22": ("path traversal", "an attacker could read files on your server they should never see"),
    "CWE-502": ("unsafe deserialization", "an attacker could send crafted data that runs code on your server"),
    "CWE-611": ("XML external entities", "an attacker could make your server read local files or call other systems"),
    "CWE-918": ("server-side request forgery", "an attacker could make your server call internal systems for them"),
    "CWE-352": ("cross-site request forgery", "another website could perform actions as your signed-in users"),
    "CWE-601": ("open redirect", "an attacker could use your site's links to send users to a phishing page"),
    "CWE-327": ("weak cryptography", "data you think is protected could be decrypted or forged"),
    "CWE-328": ("weak hashing", "stored passwords or tokens could be cracked"),
    "CWE-916": ("weak password hashing", "stored passwords could be cracked if the database leaks"),
    "CWE-798": ("hard-coded secret", "anyone who can see the code can use that credential"),
    "CWE-489": ("debug mode left on", "error pages could leak code, settings and secrets to visitors"),
    "CWE-215": ("debug mode left on", "error pages could leak code, settings and secrets to visitors"),
    "CWE-614": ("cookie without Secure flag", "session cookies could be stolen over plain HTTP"),
    "CWE-1004": ("cookie without HttpOnly flag", "a script injected into the page could steal session cookies"),
    "CWE-693": ("missing browser protection", "browsers are not told to block common attacks on your pages"),
    "CWE-1021": ("clickjacking", "another site could trick users into clicking buttons on your pages"),
    "CWE-319": ("unencrypted traffic", "passwords and data could be read by anyone on the network path"),
}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _where(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.line}" if f.line else f.file
    return f.url or "the app"


def _fixable(f: Finding) -> bool:
    """True when POST /findings/{id}/fix would attempt this finding (ignoring mode and PR-target policy)."""
    from .remediation.fix import BUILD_FILES, FORBIDDEN_PATHS, remediation_category

    if not f.file:
        return False
    cat = remediation_category(f)
    if cat == "dependency_bump":
        return bool(f.package and deps.choose_fixed_version(f.installed_version or "", f.fixed_version))
    if cat == "secret_removal":
        return f.file.endswith(".py") and bool(f.line)
    return not (BUILD_FILES.search(f.file) or FORBIDDEN_PATHS.search(f.file))


def _group_key(f: Finding) -> tuple[str, ...]:
    if f.category == "dependency" and f.package:
        return ("dep", deps.norm_pkg(f.package))
    if f.category == "secret":
        return ("secret", f.file or f.url or f.rule_id)
    if f.cwe:  # one weakness class = one fix pattern, whichever scanner/rule spotted it
        return ("cwe", f.cwe)
    return ("rule", f.tool, f.rule_id)


def _word(key: tuple[str, ...], fs: list[Finding]) -> tuple[str, str, str]:
    """(title, why, action) for a group; fs is sorted best-first."""
    lead, n = fs[0], len(fs)
    if key[0] == "dep":
        pkg = lead.package or key[1]
        installed = lead.installed_version or ""
        targets = [t for t in (deps.choose_fixed_version(installed or (g.installed_version or ""), g.fixed_version)
                               or (g.fixed_version or "").split(",")[0].strip() for g in fs) if t]
        target = max(targets, key=deps.parse_version) if targets else None
        holes = sum(max(1, len(g.advisories)) for g in fs)
        ver = f" {installed}" if installed else ""
        return (
            f"Upgrade {pkg}" + (f" to {target}" if target else ""),
            f"{pkg}{ver} has {_plural(holes, 'publicly known security hole')}, and attackers can look these up.",
            (f"Upgrade {pkg} to {target}." if target
             else f"Upgrade {pkg} to a version with no known vulnerabilities (no single fixed release is listed)."),
        )
    if key[0] == "secret":
        where = lead.file or lead.url or "the code"
        return (
            f"Remove the hard-coded secret{'s' if n > 1 else ''} in {where}",
            "A password or API key is written directly in the code, so anyone who can see the code can use it.",
            f"Move the secret{'s' if n > 1 else ''} in {where} into an environment variable, then rotate "
            f"{'them' if n > 1 else 'it'} (issue a new one and revoke the old).",
        )
    name, impact = _CWE_PLAIN.get(lead.cwe or "", (None, None))
    short = name or (lead.title.split(": ", 1)[-1] if lead.title else lead.rule_id)
    short = short[:80]
    n = len(dict.fromkeys(_where(g) for g in fs))  # distinct locations, not scanner hits
    places = "" if n == 1 else f" ({_plural(n, 'place')})"
    why = (f"This is {name}: {impact}." if name
           else f"A scanner flagged \"{short}\" as {lead.severity} risk{places}.")
    if lead.category == "config":
        action = f"Change the setting flagged as \"{short}\" in {_where(lead)}" + (f" and {n - 1} other place{'s' if n > 2 else ''}." if n > 1 else ".")
    elif n == 1:
        action = f"Fix the {short} at {_where(lead)}."
    else:
        action = f"Fix the {short} in {n} places, starting with {_where(lead)}."
    return (f"Change the setting: {short}" if lead.category == "config" else f"Fix {short}{places}"), why, action


def top_actions(findings: list[Finding], n: int = TOP_N) -> list[TopAction]:
    groups: dict[tuple[str, ...], list[tuple[float, Finding]]] = {}
    for f in findings:
        if f.status in CLOSED or f.severity == "info":
            continue
        groups.setdefault(_group_key(f), []).append((priority(f), f))
    ranked = []
    for key, items in groups.items():
        items.sort(key=lambda pf: (-pf[0], _SEV_RANK.get(pf[1].severity, 9), pf[1].id))
        ranked.append((-items[0][0], -sum(p for p, _ in items), -len(items), key, [f for _, f in items]))
    ranked.sort(key=lambda r: r[:4])
    out = []
    for *_, key, fs in ranked[:n]:
        title, why, action = _word(key, fs)
        out.append(TopAction(
            title=title, why=why, action=action, finding_ids=[f.id for f in fs],
            severity=min((f.severity for f in fs), key=lambda s: _SEV_RANK.get(s, 9)),
            fixable=any(_fixable(f) for f in fs),
        ))
    return out


def _findings_for(st, asset_id: str | None) -> list[Finding]:
    """Open findings via the same store query GET /findings uses (status=OPEN_STATUSES), plus fixed
    ones for progress credit. Keeps posture counts == the listing's tally by construction."""
    return st.list_open_findings(asset_id) + st.list_findings(asset_id=asset_id, status="fixed")


def get_posture(asset_id: str | None = None) -> Posture:
    st = get_store()
    p = compute(_findings_for(st, asset_id), asset_id)
    p.history = st.posture_history(asset_id)
    return p


def record(asset_id: str | None, scan_id: str | None = None) -> Posture:
    """Snapshot posture for the asset (and the global aggregate), emit posture.updated.

    Call this after anything that changes finding status (scan finished, fix applied...).
    """
    st = get_store()
    p = compute(_findings_for(st, asset_id), asset_id)
    st.add_posture_point(asset_id, p.score)
    if asset_id is not None:
        g = compute(_findings_for(st, None), None)
        st.add_posture_point(None, g.score)
    p.history = st.posture_history(asset_id)
    emit(
        "posture.updated",
        f"Posture {p.score}/100 (grade {p.grade}), {p.open} open",
        level="info",
        scan_id=scan_id,
        data={"asset_id": asset_id, "score": p.score, "grade": p.grade, "counts": p.counts, "open": p.open,
              "fixed": p.fixed, "risk": p.risk, "main_counts": p.main_counts, "lab_open": p.lab_open},
    )
    return p
