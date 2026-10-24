"""Asset profiles (focus / exclude / lab sub-apps) and finding prioritization.

Profile resolution: non-empty fields on the Asset win; otherwise the first `asset_profiles`
entry in scope.yaml whose `match` glob matches the asset's ref, name, or ref basename.

priority (0..100) = 100 x severity x confidence x reachability x validated
  severity     critical 1.0  high 0.7  medium 0.4  low 0.15  info 0.03
  confidence   validation.confidence when confirmed, else the scanner's confidence
  reachability main app 1.0; periphery (outside focus) 0.6; lab sub-app 0.3; test/fixture path x0.5;
               dependency: confirmed+imported 1.0, used at runtime 0.9, not imported 0.5, unknown 0.8
  validated    confirmed 1.0, not yet validated 0.7, unsupported/error 0.6, not_reproduced 0.05
Closed findings (fixed / not_reproduced) get priority 0 so they sort last.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import PurePosixPath

from .models import CLOSED_STATUSES, Asset, AssetProfile, Finding

SEV_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.15, "info": 0.03}
VALIDATED = {"confirmed": 1.0, "unsupported": 0.6, "error": 0.6, "not_reproduced": 0.05}
UNVALIDATED = 0.7
REACH_PERIPHERY = 0.6
REACH_LAB = 0.3
CLOSED = set(CLOSED_STATUSES)
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|e2e)(/|$)|(^|/)(test_[^/]*|[^/]*_test)\.py$|(^|/)tests\.py$", re.I)

LAB_TAG = "lab-subapp"
PERIPHERY_TAG = "periphery"
TEST_TAG = "test-path"


# --------------------------------------------------------------------------- profiles
def _glob_match(path: str, pat: str) -> bool:
    """fnmatch where `dir/**` also matches `dir` itself and `**/x` matches `x` at the root."""
    pat = pat.strip()
    pat = "*" if pat in (".", "./") else pat.removeprefix("./")
    if fnmatch.fnmatchcase(path, pat):
        return True
    if pat.endswith("/**") and (path == pat[:-3] or fnmatch.fnmatchcase(path, pat[:-3])):
        return True
    if pat.startswith("**/") and _glob_match(path, pat[3:]):
        return True
    return False


def matches_any(path: str | None, pats: list[str]) -> bool:
    return bool(path) and any(_glob_match(path, p) for p in pats)


def resolve_profile(asset: Asset | None) -> AssetProfile:
    if asset is None:
        return AssetProfile()
    prof = AssetProfile(focus=list(asset.focus), exclude=list(asset.exclude), sub_apps=list(asset.sub_apps))
    if prof.focus and prof.exclude and prof.sub_apps:
        return prof
    try:
        from .scope import load_scope

        entries = load_scope().asset_profiles
    except Exception:
        entries = []
    keys = {asset.ref, asset.name, asset.ref.rstrip("/").rsplit("/", 1)[-1]}
    for e in entries:
        if any(fnmatch.fnmatchcase(k, m) for k in keys for m in e.get("match", [])):
            return AssetProfile(
                focus=prof.focus or e.get("focus", []),
                exclude=prof.exclude or e.get("exclude", []),
                sub_apps=prof.sub_apps or e.get("sub_apps", []),
            )
    return prof


def sub_app_for(path: str | None, sub_apps: list[str]) -> str | None:
    """Deepest directory prefix of `path` matching a sub_apps glob (e.g. dockerized_labs/xss_lab)."""
    if not path or not sub_apps:
        return None
    parts = [p for p in PurePosixPath(path).parts if p != "/"]
    is_dir = path.endswith("/") or bool(parts and "." not in parts[-1])  # `/chat/`, `challenge`: not a file
    depth = len(parts) if is_dir else len(parts) - 1  # a file's own name is never a component
    best = None
    for i in range(1, len(parts) + 1):
        d = "/".join(parts[:i])
        if i > depth:  # the file's own name never becomes a component
            continue
        # web-app profiles are written against the URL path (`/drupal/*`), repo profiles against relative
        # paths (`challenge/labs/*`), so a component is tried in both spellings
        if any(fnmatch.fnmatchcase(x, p) for p in sub_apps for t in (d, f"/{d}") for x in (t, f"{t}/_")):
            best = d
    return best


def classify(f: Finding, prof: AssetProfile) -> Finding | None:
    """Apply a profile to a freshly normalized finding: None if excluded, else set component/tags."""
    path = f.file
    if matches_any(path, prof.exclude):
        return None
    tags = [t for t in f.tags if t not in (LAB_TAG, PERIPHERY_TAG, TEST_TAG)]
    sub = sub_app_for(path, prof.sub_apps)
    if sub:
        component = f"lab:{sub}"
        tags.append(LAB_TAG)
    elif path and prof.focus and not matches_any(path, prof.focus):
        component = "periphery"
        tags.append(PERIPHERY_TAG)
    else:
        component = "main"
    if path and TEST_PATH.search(path):
        tags.append(TEST_TAG)
    f.component, f.tags = component, tags
    return f


def apply_profile(findings: list[Finding], prof: AssetProfile) -> tuple[list[Finding], int]:
    out, dropped = [], 0
    for f in findings:
        g = classify(f, prof)
        if g is None:
            dropped += 1
        else:
            out.append(g)
    return out, dropped


# --------------------------------------------------------------------------- priority
def reachability(f: Finding) -> float:
    if LAB_TAG in f.tags or f.component.startswith("lab:"):
        r = REACH_LAB
    elif PERIPHERY_TAG in f.tags or f.component == "periphery":
        r = REACH_PERIPHERY
    else:
        r = 1.0
    if TEST_TAG in f.tags:
        r *= 0.5
    if f.category == "dependency":
        v = f.validation
        if v and v.result == "confirmed":
            dep = 1.0 if v.confidence >= 0.95 else 0.9 if v.confidence >= 0.85 else 0.5
        else:
            dep = 0.8
        r *= dep
    return r


def validated_factor(f: Finding) -> float:
    v = f.validation
    if v is None:
        return UNVALIDATED
    return VALIDATED.get(v.result, UNVALIDATED)


def confidence(f: Finding) -> float:
    v = f.validation
    c = v.confidence if v is not None and v.result == "confirmed" and v.confidence else f.confidence
    return max(0.05, min(1.0, c or 0.5))


def priority(f: Finding) -> float:
    if f.status in CLOSED:
        return 0.0
    p = 100 * SEV_WEIGHT.get(f.severity, 0.03) * confidence(f) * reachability(f) * validated_factor(f)
    return round(p, 1)


def risk_weight(f: Finding) -> float:
    """Posture risk contribution of a finding regardless of status (status handled by caller).
    Info findings carry no risk (they still get a small priority for ordering)."""
    if f.severity == "info":
        return 0.0
    return 100 * SEV_WEIGHT.get(f.severity, 0.03) * confidence(f) * reachability(f) * validated_factor(f) / 10
