"""Posture.top_actions: up to 3 plain-language fixes, grouped by the one action that closes them."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config, posture
from app import main as main_mod
from app.models import Asset, Finding
from app.scanners.normalize import Ctx, normalize_gitleaks, normalize_semgrep, normalize_trivy, normalize_zap

FX = Path(__file__).parent / "fixtures"
TOKEN = "test-api-token-0123456789"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
_n = [0]


def mk(sev="high", status="open", category="sast", **kw) -> Finding:
    _n[0] += 1
    base = dict(scan_id="s", asset_id="a", fingerprint=f"{_n[0]:032d}", tool="semgrep", rule_id=f"r{_n[0]}",
                title=f"t{_n[0]}", severity=sev, category=category, status=status, file="app.py", line=_n[0])
    base.update(kw)
    return Finding(**base)


def dep(pkg, installed, fixed, manifest="requirements.txt", sev="critical", **kw) -> Finding:
    return mk(sev, category="dependency", tool="trivy", rule_id=f"dependency:{pkg.lower()}", package=pkg,
              installed_version=installed, fixed_version=fixed, file=manifest, line=None,
              title=f"{pkg} {installed}: 3 known vulnerabilities (upgrade to {fixed})", confidence=0.9, **kw)


def test_clean_has_no_actions():
    assert posture.compute([]).top_actions == []


def test_at_most_three_and_ranked_by_priority():
    fs = [mk("low", cwe=f"CWE-{i}") for i in range(10)] + [mk("critical", cwe="CWE-89"), mk("high", cwe="CWE-78")]
    acts = posture.compute(fs).top_actions
    assert len(acts) == 3
    assert [a.severity for a in acts[:2]] == ["critical", "high"]
    assert "SQL injection" in acts[0].title and "database" in acts[0].why


def test_one_package_bump_groups_findings_across_manifests():
    a = dep("Django", "4.2.10", "4.2.30, 5.0.9")
    b = dep("django", "4.2.10", "4.2.25", manifest="web/requirements.txt", sev="high")
    acts = posture.compute([a, b, mk("medium")]).top_actions
    top = acts[0]
    assert top.action == "Upgrade Django to 4.2.30."
    assert top.title == "Upgrade Django to 4.2.30"
    assert set(top.finding_ids) == {a.id, b.id}
    assert top.severity == "critical" and top.fixable is True
    assert len(acts) == 2


def test_same_weakness_class_is_one_action():
    fs = [mk("high", cwe="CWE-89", rule_id="tainted-sql"), mk("high", cwe="CWE-89", rule_id="cursor-execute"),
          mk("high", cwe="CWE-89", file="views.py", line=3)]
    (act,) = posture.compute(fs).top_actions
    assert len(act.finding_ids) == 3
    assert "3 places" in act.title and act.action.startswith("Fix the SQL injection in 3 places")


def test_closed_and_info_findings_are_skipped():
    fs = [mk("critical", "fixed"), mk("critical", "not_reproduced"), mk("info")]
    assert posture.compute(fs).top_actions == []


def test_fixable_follows_the_fix_flow():
    py_secret = mk("high", category="secret", tool="gitleaks", file="settings.py", line=4)
    env_secret = mk("high", category="secret", tool="gitleaks", file=".env", line=2)
    no_fix = dep("leftpad", "1.0.0", None)
    dockerfile = mk("high", category="config", tool="trivy", file="Dockerfile", line=None)
    dast_no_file = mk("high", category="dast", tool="zap", file=None, url="http://x/a")
    by_id = {}
    for f in (py_secret, env_secret, no_fix, dockerfile, dast_no_file):
        (act,) = posture.compute([f]).top_actions
        by_id[f.id] = act.fixable
    assert by_id == {py_secret.id: True, env_secret.id: False, no_fix.id: False, dockerfile.id: False,
                     dast_no_file.id: False}
    (act,) = posture.compute([py_secret]).top_actions
    assert "environment variable" in act.action and "rotate" in act.action


def test_deterministic_regardless_of_input_order():
    fs = [mk(s, cwe=c) for s, c in [("high", "CWE-79"), ("high", "CWE-78"), ("medium", "CWE-22"), ("high", "CWE-89")]]
    fs += [dep("pyyaml", "5.3", "5.4"), dep("PyYAML", "5.3", "5.4.1", manifest="b/requirements.txt", sev="high")]
    want = [a.model_dump() for a in posture.compute(fs).top_actions]
    for seed in range(5):
        shuffled = fs[:]
        random.Random(seed).shuffle(shuffled)
        assert [a.model_dump() for a in posture.compute(shuffled).top_actions] == want


def test_fixture_scan_gives_plain_actions():
    ctx = Ctx(scan_id="scn_t", asset_id="ast_t", src_root=FX / "src")
    load = lambda n: json.loads((FX / n).read_text())  # noqa: E731
    fs = (normalize_semgrep(load("semgrep.json"), ctx) + normalize_gitleaks(load("gitleaks.json"), ctx)
          + normalize_trivy(load("trivy.json"), ctx) + normalize_zap(load("zap.json"), ctx))
    acts = posture.compute(fs, "ast_t").top_actions
    assert len(acts) == 3
    ids = {f.id for f in fs}
    for a in acts:
        assert a.title and a.why.endswith(".") and a.action.endswith(".")
        assert a.finding_ids and set(a.finding_ids) <= ids
    assert acts[0].action == "Upgrade pyyaml to 5.4." and acts[0].fixable


@pytest.fixture()
def client(monkeypatch, tmp_path, tmp_store):
    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, tmp_path / "data" / sub if sub else tmp_path / "data")
    monkeypatch.setenv("TIRITH_API_TOKEN", TOKEN)
    for v in ("TIRITH_ALLOW_NO_AUTH", "TIRITH_ALLOW_AUTONOMOUS"):
        monkeypatch.delenv(v, raising=False)
    with TestClient(main_mod.app) as c:
        yield c


def test_rest_posture_returns_top_actions(client, tmp_store):
    asset = tmp_store.save_asset(Asset(kind="github_repo", ref="o/app", name="app"))
    f = dep("Django", "4.2.10", "4.2.30", asset_id=asset.id)
    tmp_store.upsert_finding(f)
    body = client.get("/api/posture", params={"asset_id": asset.id}, headers=AUTH).json()
    (act,) = body["top_actions"]
    assert set(act) == {"title", "why", "action", "finding_ids", "severity", "fixable"}
    assert act["action"] == "Upgrade Django to 4.2.30." and act["fixable"] is True
    stored = client.get("/api/findings", params={"asset_id": asset.id}, headers=AUTH).json()
    assert act["finding_ids"] == [stored[0]["id"]]
