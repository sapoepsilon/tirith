"""Runtime configuration (env). Secret values are read lazily and never logged."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
TIRITH_ROOT = BACKEND_DIR.parent

DATA_DIR = Path(os.environ.get("TIRITH_DATA_DIR", str(BACKEND_DIR / ".data"))).resolve()
DB_PATH = DATA_DIR / "tirith.db"
CLONES_DIR = DATA_DIR / "clones"
REPORTS_DIR = DATA_DIR / "reports"
EVIDENCE_DIR = DATA_DIR / "evidence"

SCOPE_FILE = Path(os.environ.get("TIRITH_SCOPE_FILE", str(BACKEND_DIR / "scope.yaml"))).resolve()

# Per-tool process timeout (seconds).
SCAN_TIMEOUT = int(os.environ.get("TIRITH_SCAN_TIMEOUT", "900"))

# Scanner CLIs: plain names resolved from PATH unless the env names another path/binary.
BIN = {
    "semgrep": os.environ.get("TIRITH_SEMGREP_BIN", "semgrep"),
    "gitleaks": os.environ.get("TIRITH_GITLEAKS_BIN", "gitleaks"),
    "trivy": os.environ.get("TIRITH_TRIVY_BIN", "trivy"),
    "zap": os.environ.get("TIRITH_ZAP_SCRIPT", "zap-baseline.py"),
    "nmap": os.environ.get("TIRITH_NMAP_BIN", "nmap"),
    "nikto": os.environ.get("TIRITH_NIKTO_BIN", "nikto"),
}
# nmap arguments in front of the target (connect scan: no raw socket privileges needed).
NMAP_ARGS = os.environ.get("TIRITH_NMAP_ARGS", "-sT -T4 --host-timeout 90s").split()
NIKTO_ARGS = os.environ.get("TIRITH_NIKTO_ARGS", "-ask none").split()

# Container images: only the lab/analyst lane and their pull/build paths still use them.
IMAGES = {
    "semgrep": os.environ.get("TIRITH_SEMGREP_IMAGE", "semgrep/semgrep"),
    "gitleaks": os.environ.get("TIRITH_GITLEAKS_IMAGE", "zricethezav/gitleaks"),
    "trivy": os.environ.get("TIRITH_TRIVY_IMAGE", "aquasec/trivy"),
    "zap": os.environ.get("TIRITH_ZAP_IMAGE", "zaproxy/zap-stable"),
}
SEMGREP_CONFIGS = os.environ.get(
    "TIRITH_SEMGREP_CONFIGS", "p/python,p/javascript,p/secrets"
).split(",")


# -- access control (read at call time so tests can monkeypatch the env) -------
def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def api_token() -> str | None:
    """TIRITH_API_TOKEN (Bearer token for /api/* and the WebSocket). Never log the return value."""
    tok = os.environ.get("TIRITH_API_TOKEN", "").strip()
    return tok or None


def allow_no_auth() -> bool:
    """TIRITH_ALLOW_NO_AUTH=1: local dev only; run without a token."""
    return _flag("TIRITH_ALLOW_NO_AUTH")


def allow_autonomous() -> bool:
    """TIRITH_ALLOW_AUTONOMOUS=1 is required to PUT /mode {mode: autonomous}."""
    return _flag("TIRITH_ALLOW_AUTONOMOUS")


def evidence_enabled() -> bool:
    """TIRITH_ALLOW_SHOTS=1 enables the headless-browser screenshot endpoint (pulls an image)."""
    return _flag("TIRITH_ALLOW_SHOTS")


def analyst_enabled() -> bool:
    """TIRITH_ALLOW_ANALYST=1 enables the autonomous model-planned loop (off by default)."""
    return _flag("TIRITH_ALLOW_ANALYST")


def cors_origins() -> list[str]:
    """TIRITH_CORS_ORIGINS: comma list of exact origins. Default: none (no CORS headers)."""
    return [o.strip().rstrip("/") for o in os.environ.get("TIRITH_CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]


def check_auth_config() -> None:
    """Refuse to start without a token unless TIRITH_ALLOW_NO_AUTH=1."""
    if api_token() is None and not allow_no_auth():
        raise RuntimeError("TIRITH_API_TOKEN is not set; refusing to start "
                           "(set TIRITH_ALLOW_NO_AUTH=1 for local development only)")


def ensure_dirs() -> None:
    for d in (DATA_DIR, CLONES_DIR, REPORTS_DIR, EVIDENCE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def github_token() -> str | None:
    """TIRITH_GITHUB_TOKEN, else `gh auth token`. Never log the return value."""
    tok = os.environ.get("TIRITH_GITHUB_TOKEN")
    if tok:
        return tok.strip()
    if shutil.which("gh"):
        try:
            out = subprocess.run(
                ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
        except Exception:
            return None
    return None
