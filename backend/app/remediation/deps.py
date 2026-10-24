"""Dependency helpers: version compare, choosing a fixed version, editing manifests, import reachability."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

# ----------------------------------------------------------------------------- versions
_VER_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)(.*)$")


def parse_version(v: str) -> tuple:
    """PEP 440-ish key: numeric release tuple, then pre-release ranks below final."""
    m = _VER_RE.match(v or "")
    if not m:
        return ((0,), 0, v or "")
    nums = tuple(int(x) for x in m.group(1).split("."))
    while len(nums) > 1 and nums[-1] == 0:
        nums = nums[:-1]
    rest = m.group(2).lower().lstrip(".-_")
    if not rest:
        rank = 0
    elif rest.startswith(("a", "b", "rc", "c", "dev", "pre")):
        rank = -1
    elif rest.startswith(("post", "r")):
        rank = 1
    else:
        rank = 0
    return (nums, rank, rest)


def vlt(a: str, b: str) -> bool:
    return parse_version(a) < parse_version(b)


def fixed_candidates(fixed: str | None) -> list[str]:
    return [x.strip() for x in (fixed or "").split(",") if x.strip()]


def _release(v: str) -> tuple[int, ...]:
    m = _VER_RE.match(v or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def choose_fixed_version(installed: str, fixed: str | None) -> str | None:
    """Pick the least disruptive fixed version.

    Trivy lists one fixed version per maintained branch ("3.2.19, 4.1.9, 4.2.1"). Prefer the
    lowest fix on the installed major.minor line, then same major, then the lowest fix > installed.
    """
    cands = [c for c in fixed_candidates(fixed) if vlt(installed, c)]
    if not cands:
        return None
    inst = _release(installed)
    for width in (2, 1):
        same = [c for c in cands if _release(c)[:width] == inst[:width] and len(inst) >= width]
        if same:
            return min(same, key=parse_version)
    return min(cands, key=parse_version)


def in_affected_range(installed: str, fixed: str | None) -> tuple[bool, str]:
    """Trivy reports only an installed + fixed list; affected iff installed is below the fix
    for its release line (and not >= any listed fix on that line)."""
    cands = fixed_candidates(fixed)
    if not cands:
        return True, "advisory lists no fixed version: every version is affected"
    inst = _release(installed)
    line = [c for c in cands if _release(c)[:2] == inst[:2]]
    if line:
        fx = min(line, key=parse_version)
        return vlt(installed, fx), f"installed {installed} vs fix {fx} on the {'.'.join(map(str, inst[:2]))} line"
    higher = [c for c in cands if vlt(installed, c)]
    if higher:
        return True, f"installed {installed} is below the fixed versions {', '.join(sorted(higher, key=parse_version))}"
    return False, f"installed {installed} is at or above every fixed version ({', '.join(cands)})"


# ----------------------------------------------------------------------------- manifests
def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").lower()).strip()


_REQ_LINE = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(\s*)(===|==|>=|~=|<=|!=|>|<)?(\s*)([^\s;#,]*)(.*)$")


def pinned_version(manifest: Path, package: str) -> tuple[int, str] | None:
    """(line_no, version) of `package` in a requirements file, else None."""
    try:
        lines = manifest.read_text(errors="replace").splitlines()
    except OSError:
        return None
    want = norm_pkg(package)
    for i, ln in enumerate(lines, 1):
        m = _REQ_LINE.match(ln)
        if m and norm_pkg(m.group(2)) == want:
            return i, m.group(7) or ""
    return None


def bump_requirements(text: str, package: str, new_version: str) -> tuple[str, int]:
    """Set `package==new_version` in a requirements.txt body. Returns (new_text, lines_changed)."""
    want = norm_pkg(package)
    out, changed = [], 0
    for ln in text.splitlines(keepends=True):
        body = ln.rstrip("\r\n")
        eol = ln[len(body):]
        m = _REQ_LINE.match(body)
        if m and norm_pkg(m.group(2)) == want and not body.lstrip().startswith(("#", "-")):
            lead, name, extras, _, op, _, _, tail = m.groups()
            if op in (None, "==", "===", ">=", "~=", "<=", ">", "<", "!="):
                new = f"{lead}{name}{extras or ''}=={new_version}{tail}"
                if new != body:
                    changed += 1
                out.append(new + eol)
                continue
        out.append(ln)
    return "".join(out), changed


def bump_package_json(text: str, package: str, new_version: str) -> tuple[str, int]:
    pat = re.compile(r'("' + re.escape(package) + r'"\s*:\s*")([~^]?)([^"]+)(")')
    new, n = pat.subn(lambda m: f"{m.group(1)}{m.group(2)}{new_version}{m.group(4)}", text)
    return new, n


def bump_manifest(path: Path, package: str, new_version: str) -> int:
    text = path.read_text()
    if path.name == "package.json":
        new, n = bump_package_json(text, package, new_version)
    elif path.suffix in (".txt", ".in") or "requirements" in path.name:
        new, n = bump_requirements(text, package, new_version)
    else:
        raise ValueError(f"unsupported manifest for automatic bump: {path.name}")
    if n:
        path.write_text(new)
    return n


# ----------------------------------------------------------------------------- reachability
IMPORT_NAMES = {
    "pillow": ["PIL"], "pyjwt": ["jwt"], "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"],
    "python-dotenv": ["dotenv"], "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "django": ["django"], "djangorestframework": ["rest_framework"], "django-allauth": ["allauth"],
    "django-crispy-forms": ["crispy_forms"], "crispy-bootstrap4": ["crispy_bootstrap4"],
    "python3-openid": ["openid"], "dj-database-url": ["dj_database_url"], "pycryptodome": ["Crypto"],
    "protobuf": ["google.protobuf"], "attrs": ["attr", "attrs"], "msgpack-python": ["msgpack"],
    "requests-oauthlib": ["requests_oauthlib"], "argon2-cffi": ["argon2"], "charset-normalizer": ["charset_normalizer"],
}
FRAMEWORK_HINTS = {
    "django": ["INSTALLED_APPS", "django.setup"],
    "gunicorn": ["gunicorn"],  # used from Dockerfile/Procfile CMD, not imports
    "werkzeug": ["flask"],     # transitively used by Flask apps
    "jinja2": ["flask", "render_template"],
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "site-packages", ".tox", "dist", "build"}


def import_names(package: str) -> list[str]:
    n = norm_pkg(package)
    return IMPORT_NAMES.get(n) or [n.replace("-", "_")]


MANIFESTS = ("requirements.txt", "package.json", "pyproject.toml", "Pipfile", "setup.py")


def owned_tree_excludes(root: Path) -> set[Path]:
    """Sub-directories of root that have their own manifest (separate apps, e.g. dockerized labs)."""
    out: set[Path] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        p = Path(dirpath)
        if p != root and any(m in filenames for m in MANIFESTS):
            out.add(p)
            dirnames[:] = []
    return out


def find_imports(root: Path, package: str, limit: int = 8, exclude: set[Path] | None = None) -> list[str]:
    """`file:line: code` for each `import X` / `from X ...` of the package under root."""
    exclude = exclude or set()
    names = import_names(package)
    pats = [re.compile(rf"^\s*(?:from\s+{re.escape(n)}(?:\.|\s)|import\s+(?:[\w.]+\s*,\s*)*{re.escape(n)}(?:\.|\s|,|$))") for n in names]
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and Path(dirpath, d) not in exclude]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = Path(dirpath) / fn
            try:
                if p.stat().st_size > 1_000_000:
                    continue
                for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
                    if any(pt.match(ln) for pt in pats):
                        hits.append(f"{p.relative_to(root)}:{i}: {ln.strip()[:160]}")
                        if len(hits) >= limit:
                            return hits
            except OSError:
                continue
    return hits


def find_runtime_refs(root: Path, package: str, limit: int = 5) -> list[str]:
    """Non-import usage: Dockerfile/Procfile/compose commands (e.g. gunicorn) and framework hints."""
    n = norm_pkg(package)
    words = [n] + FRAMEWORK_HINTS.get(n, [])
    hits: list[str] = []
    for name in ("Dockerfile", "Procfile", "docker-compose.yml", "compose.yml", "setup.py", "pyproject.toml"):
        p = root / name
        if p.is_file():
            for i, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
                low = ln.lower()
                if any(w.lower() in low for w in words) and not low.strip().startswith("#"):
                    hits.append(f"{name}:{i}: {ln.strip()[:160]}")
                    if len(hits) >= limit:
                        return hits
    return hits


def package_json_has(path: Path, package: str) -> bool:
    try:
        d = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return any(package in (d.get(k) or {}) for k in ("dependencies", "devDependencies"))
