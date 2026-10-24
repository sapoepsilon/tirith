"""Shared fixtures: temp store + data dir, stub LLM, fixture findings from real scanner output."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from app import config
from app.models import Asset
from app.scanners.normalize import Ctx, normalize_gitleaks, normalize_semgrep, normalize_trivy
from app.store import Store, set_store

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def tmp_env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    for name, sub in (("DATA_DIR", ""), ("CLONES_DIR", "clones"), ("REPORTS_DIR", "reports"), ("EVIDENCE_DIR", "evidence")):
        monkeypatch.setattr(config, name, data / sub if sub else data)
    config.ensure_dirs()
    st = Store(data / "test.db")
    set_store(st)
    monkeypatch.setenv("TIRITH_LLM_PROVIDER", "stub")
    monkeypatch.delenv("TIRITH_LLM_MODEL", raising=False)
    monkeypatch.setenv("TIRITH_GITHUB_TOKEN", "test-token-not-real")
    yield st


@pytest.fixture
def store(tmp_env):
    return tmp_env


def load(name: str):
    return json.loads((FIXTURES / name).read_text())


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def mini_repo(tmp_path) -> Path:
    """A tiny Django-ish project shaped like PyGoat, as a git repo."""
    r = tmp_path / "repo"
    (r / "pygoat").mkdir(parents=True)
    (r / "introduction").mkdir()
    (r / "requirements.txt").write_text("asgiref==3.6.0\nDjango==4.2\nPyJWT==2.4.0\nrequests==2.28.2\n")
    (r / "manage.py").write_text("import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pygoat.settings')\n")
    (r / "pygoat" / "urls.py").write_text(
        "from django.urls import path\nfrom introduction import views\n\nurlpatterns = [\n"
        "    path('sql_lab', views.sql_lab, name='sql_lab'),\n]\n")
    (r / "introduction" / "views.py").write_text(
        "from django.db import connection\nfrom django.shortcuts import render\n\n\n"
        "def sql_lab(request):\n    name = request.POST.get('name')\n    cur = connection.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE name='%s'\" % name)\n    return render(request, 'x.html')\n\n\n"
        "def orphan(request):\n    cur = connection.cursor()\n    cur.execute(\"SELECT 1 WHERE x='%s'\" % request.GET['x'])\n")
    git(r, "init", "-q", "-b", "master")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "init")
    return r


@pytest.fixture
def asset(store, mini_repo) -> Asset:
    return store.save_asset(Asset(kind="local_path", ref=str(mini_repo), name="mini"))


def trivy_findings(asset: Asset, src: Path | None = None, group: bool = False):
    return normalize_trivy(load("trivy.json"), Ctx(scan_id="scn_test", asset_id=asset.id, src_root=src), group=group)


def semgrep_findings(asset: Asset, src: Path | None = None):
    return normalize_semgrep(load("semgrep.json"), Ctx(scan_id="scn_test", asset_id=asset.id, src_root=src))


def gitleaks_findings(asset: Asset, src: Path | None = None):
    data = load("gitleaks.json")
    for x in data:
        x["File"] = x["File"].replace("/repo/", "/src/")
    return normalize_gitleaks(data, Ctx(scan_id="scn_test", asset_id=asset.id, src_root=src))


def django_finding(store, asset, cve="CVE-2023-31047"):
    f = next(x for x in trivy_findings(asset) if x.rule_id == cve and x.file == "requirements.txt")
    stored, _ = store.upsert_finding(f)
    return stored
