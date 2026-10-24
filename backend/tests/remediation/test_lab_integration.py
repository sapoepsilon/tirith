"""Opt-in: real docker build + boot of PyGoat on the internal lab network.

    TIRITH_LAB_IT=1 uv run pytest -q tests/remediation/test_lab_integration.py -s
"""

import os
from pathlib import Path

import pytest

from app.remediation import lab

PYGOAT = Path(__file__).resolve().parents[3] / "targets" / "pygoat"

pytestmark = pytest.mark.skipif(os.environ.get("TIRITH_LAB_IT") != "1" or not PYGOAT.is_dir(), reason="set TIRITH_LAB_IT=1")


def test_pygoat_boots_isolated():
    h = lab.boot(PYGOAT, "pygoat-it")
    try:
        ev = {e.label: e.content for e in h.evidence}
        for k, v in ev.items():
            print(f"--- {k}\n{v[:400]}")
        assert h.ok
        assert "internal=true" in ev["lab network"]
        assert "EGRESS-BLOCKED" in ev["egress check"]
        assert ev["published host ports"] == "none"
        assert "HTTP 302" in ev["peer probe over lab network"] or "HTTP 200" in ev["peer probe over lab network"]
        # Host header = the lab container name (what ZAP uses): no 400 DisallowedHost
        assert "HTTP 400" not in ev["peer probe over lab network"]
        cookies = lab.session(h)
        assert any("session" in k.lower() for k in cookies)
        assert len(lab.crawl_seeds(h)) > 5
    finally:
        h.stop()
