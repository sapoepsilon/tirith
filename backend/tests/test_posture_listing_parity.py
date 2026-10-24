"""Posture counts and the findings listing must agree for the same scope.

Reproduces the live mismatch seen in analyst run arn_e4f94d329024: posture for the PyGoat URL asset
said 0 critical, then an unscoped `findings` call (no ref) returned the repo asset's critical Trivy
findings, and the listing also mixed in fixed/not_reproduced rows that posture never counts.
"""

from __future__ import annotations

import asyncio
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from app import config, posture
from app import main as main_mod
from app.analyst.tools import AnalystTools
from app.models import CLOSED_STATUSES, OPEN_STATUSES, SEVERITIES, Asset, Finding

TOKEN = "test-api-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _f(asset_id: str, n: int, sev: str, status: str = "open", lab: bool = False) -> Finding:
    extra = {"component": "lab:dockerized_labs/x", "tags": ["lab-subapp"]} if lab else {}
    return Finding(scan_id="s", asset_id=asset_id, fingerprint=f"{asset_id}-{n:04d}", tool="trivy", rule_id="r",
                   title=f"t{n}", severity=sev, category="dependency", status=status, **extra)


@pytest.fixture()
def seeded(tmp_store):
    repo = tmp_store.save_asset(Asset(kind="github_repo", ref="o/pygoat", name="pygoat"))
    url = tmp_store.save_asset(Asset(kind="url", ref="http://192.0.2.5:8080", name="http://192.0.2.5:8080"))
    rows = [
        _f(repo.id, 1, "critical", "validated"),
        _f(repo.id, 2, "critical", lab=True),            # lab sub-app: still open, still counted
        _f(repo.id, 3, "critical", "fixed"),              # closed: listed by default, never counted
        _f(repo.id, 4, "critical", "not_reproduced"),     # closed
        _f(repo.id, 5, "high", "fixing"),
        _f(url.id, 1, "medium"),
        _f(url.id, 2, "low"),
        _f(url.id, 3, "high", "fixed"),
    ]
    for f in rows:
        tmp_store.upsert_finding(f)
    return tmp_store, repo, url


def _tally(findings) -> dict[str, int]:
    c = Counter(f["severity"] if isinstance(f, dict) else f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


def test_open_and_closed_statuses_partition_the_status_enum():
    from typing import get_args

    from app.models import FindingStatus

    assert set(OPEN_STATUSES) | set(CLOSED_STATUSES) == set(get_args(FindingStatus))
    assert not set(OPEN_STATUSES) & set(CLOSED_STATUSES)


def test_posture_counts_equal_the_open_listing_tally(seeded):
    st, repo, url = seeded
    for asset_id in (repo.id, url.id, None):
        p = posture.get_posture(asset_id)
        listed = st.list_findings(asset_id=asset_id, status=",".join(OPEN_STATUSES))
        assert p.counts == _tally(listed), asset_id
        assert p.open == len(listed)
    rp = posture.get_posture(repo.id)
    assert rp.counts["critical"] == 2 and rp.main_counts["critical"] == 1 and rp.lab_open == 1
    # The unfiltered listing (default) includes closed rows: that is the "listing > posture" gap.
    assert _tally(st.list_findings(asset_id=repo.id))["critical"] == 4


@pytest.fixture()
def client(monkeypatch, tmp_path, seeded):
    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / "data" / sub if sub else tmp_path / "data")
    monkeypatch.setenv("TIRITH_API_TOKEN", TOKEN)
    for v in ("TIRITH_ALLOW_NO_AUTH", "TIRITH_ALLOW_AUTONOMOUS"):
        monkeypatch.delenv(v, raising=False)
    with TestClient(main_mod.app) as c:
        yield c


def test_rest_posture_matches_rest_findings_with_open_statuses(client, seeded):
    _, repo, url = seeded
    status = ",".join(OPEN_STATUSES)
    for asset_id in (repo.id, url.id):
        p = client.get("/api/posture", params={"asset_id": asset_id}, headers=AUTH).json()
        rows = client.get("/api/findings", params={"asset_id": asset_id, "status": status}, headers=AUTH).json()
        assert p["counts"] == _tally(rows), asset_id
        assert p["open"] == len(rows)


def test_analyst_findings_and_posture_agree_and_state_their_scope(seeded):
    """The bug: posture(ref=url) -> 0 critical, then findings() with no ref -> criticals of the repo asset."""
    _, repo, url = seeded
    tools = AnalystTools()
    p = asyncio.run(tools.call("posture", {"ref": url.ref}))
    assert p["counts"]["critical"] == 0 and p["scope"]["asset_id"] == url.id

    unscoped = asyncio.run(tools.call("findings", {"limit": 20}))
    assert unscoped["scope"] == {"asset_id": None, "asset": "ALL assets"}
    assert any(f["severity"] == "critical" and f["asset_id"] == repo.id for f in unscoped["findings"])
    # Defaults to the open set: no fixed / not_reproduced rows, and counts match the all-assets posture.
    assert {f["status"] for f in unscoped["findings"]} <= set(OPEN_STATUSES)
    assert unscoped["counts"] == asyncio.run(tools.call("posture", {}))["counts"]

    for args in ({"ref": url.ref}, {"asset_id": repo.id}, {"name": "pygoat"}):
        fs = asyncio.run(tools.call("findings", args))
        ps = asyncio.run(tools.call("posture", args))
        assert fs["scope"] == ps["scope"], args
        assert fs["counts"] == ps["counts"] and fs["total"] == ps["open"], args

    every = asyncio.run(tools.call("findings", {"asset_id": repo.id, "status": "all"}))
    assert every["total"] == 5 and every["status_filter"] == "all"
