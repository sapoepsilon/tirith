"""Scan result reliability: failed/partial runs, exclude globs, stable fingerprints, redaction."""

import asyncio
import json
import secrets
import shutil
import string
from pathlib import Path

import pytest

from app.models import Asset, Finding, Scan, Validation
from app.scanners import docker as docker_mod
from app.scanners import runner
from app.scanners import tools as tools_mod
from app.scanners.normalize import (
    NORMALIZERS,
    Ctx,
    normalize_gitleaks,
    normalize_semgrep,
    normalize_trivy,
    redact,
)
from app.scanners.tools import ToolOutput

FX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FX / name).read_text())


def rand(n, prefix=""):
    return prefix + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def windows(s, n=4):
    return {s[i : i + n] for i in range(len(s) - n + 1)}


# --------------------------------------------------------------------------- runner harness
@pytest.fixture()
def env(tmp_store, tmp_path, monkeypatch):
    src = tmp_path / "src"
    shutil.copytree(FX / "src", src)
    asset = Asset(kind="local_path", ref=str(src), name="reliability-test")
    tmp_store.save_asset(asset)
    monkeypatch.setattr(runner, "enforce", lambda *a, **k: (True, "test"))
    outputs: dict[str, ToolOutput | Exception] = {}

    def fake(tool):
        async def run(*a, **k):
            out = outputs[tool]
            if isinstance(out, Exception):
                raise out
            return out
        return run

    for t in ("semgrep", "gitleaks", "trivy"):
        monkeypatch.setattr(tools_mod, f"run_{t}", fake(t))

    def scan(**outs) -> Scan:
        outputs.clear()
        outputs.update(outs)
        a = tmp_store.get_asset(asset.id)
        s = Scan(asset_id=a.id, tools=runner.plan_tools(a, list(outs)))
        tmp_store.save_scan(s)
        asyncio.run(runner.run_scan(s.id))
        return tmp_store.get_scan(s.id)

    return tmp_store, asset, scan


def by_status(store, asset_id, tool):
    out = {}
    for f in store.list_findings(asset_id=asset_id, tool=tool):
        out.setdefault(f.status, []).append(f)
    return out


# --------------------------------------------------------------------------- 2. failed / partial runs
def test_failed_tool_keeps_previous_findings_open(env):
    store, asset, scan = env
    s1 = scan(semgrep=ToolOutput(raw=load("semgrep.json")))
    assert s1.status == "done" and s1.tools["semgrep"] == "done"
    assert len(by_status(store, asset.id, "semgrep")["open"]) == 7

    s2 = scan(semgrep=ToolOutput(error="semgrep: rule download failed"))
    assert s2.tools["semgrep"] == "failed" and s2.status == "failed"
    st = by_status(store, asset.id, "semgrep")
    assert "fixed" not in st and len(st["open"]) == 7

    s3 = scan(semgrep=RuntimeError("docker exploded"))  # tool raising == failed, nothing resolved
    assert s3.tools["semgrep"] == "failed"
    assert "fixed" not in by_status(store, asset.id, "semgrep")

    # control: a clean, complete, empty run does resolve them
    scan(semgrep=ToolOutput(raw={"results": [], "errors": []}))
    assert len(by_status(store, asset.id, "semgrep")["fixed"]) == 7


def test_partial_run_does_not_resolve_findings_in_unanalyzed_files(env):
    store, asset, scan = env
    scan(semgrep=ToolOutput(raw=load("semgrep.json")))
    s = scan(semgrep=ToolOutput(raw={"results": [], "errors": []}, partial_files={"app.py"}))
    assert s.tools["semgrep"] == "done"
    assert all(f.status == "open" for f in store.list_findings(asset_id=asset.id, tool="semgrep"))


def test_one_tool_crashing_in_normalize_does_not_orphan_others(env, monkeypatch):
    store, asset, scan = env

    def boom(raw, ctx):
        raise ValueError("bad report")

    monkeypatch.setitem(NORMALIZERS, "trivy", boom)
    s = scan(semgrep=ToolOutput(raw=load("semgrep.json")), trivy=ToolOutput(raw={"Results": []}))
    assert s.tools == {**s.tools, "semgrep": "done", "trivy": "failed"}
    assert s.status == "done" and "trivy" in (s.error or "")
    assert len(store.list_findings(asset_id=asset.id, tool="semgrep")) == 7


def test_semgrep_report_errors_classified():
    fatal, partial = tools_mod.semgrep_problems(
        {"errors": [{"level": "warn", "type": "Syntax error", "path": "/src/a.py"}]}, 0)
    fatal, partial2 = tools_mod.semgrep_problems(
        {"errors": [{"level": "warn", "type": "Syntax error", "path": "a.py"}]}, 0)
    assert fatal is None and partial == {"a.py"} and partial2 == {"a.py"}
    fatal, _ = tools_mod.semgrep_problems({"errors": [{"level": "error", "message": "invalid rule"}]}, 0)
    assert "invalid rule" in fatal
    fatal, _ = tools_mod.semgrep_problems({"errors": []}, 2)
    assert "exit code 2" in fatal


def _fake_container(monkeypatch, stdout="", stderr="", rc=0):
    calls = []

    async def fake(args, **kw):
        calls.append((args, kw))
        return docker_mod.RunResult(rc, stdout, stderr)

    monkeypatch.setattr(tools_mod, "run_process", fake)
    return calls


def test_gitleaks_and_trivy_stderr_errors_fail_the_tool(monkeypatch, tmp_path):
    _fake_container(monkeypatch, stdout="[]", stderr="\x1b[90m7:50AM\x1b[0m \x1b[31mERR\x1b[0m failed to scan git history\n")
    assert asyncio.run(tools_mod.run_gitleaks(tmp_path, tmp_path / "o", "n")).error
    _fake_container(monkeypatch, stdout="not json", stderr="")
    assert asyncio.run(tools_mod.run_gitleaks(tmp_path, tmp_path / "o", "n")).error
    _fake_container(monkeypatch, stdout='{"Results": []}', stderr="2026-10-24T07:50:00Z\tFATAL\tDB error\n")
    assert asyncio.run(tools_mod.run_trivy(tmp_path, "n")).error
    _fake_container(monkeypatch, stdout='{"Results": []}', stderr="2026-10-24T07:50:00Z\tWARN\tminor\n")
    out = asyncio.run(tools_mod.run_trivy(tmp_path, "n"))
    assert out.error is None and out.raw == {"Results": []}


def test_gitleaks_mode_and_tirith_owned_config(monkeypatch, tmp_path):
    calls = _fake_container(monkeypatch, stdout="[]")
    (tmp_path / ".git").write_text("gitdir: /elsewhere\n")  # worktree / submodule pointer
    asyncio.run(tools_mod.run_gitleaks(tmp_path, tmp_path / "o", "n"))
    args, kw = calls[-1]
    assert args[0] == "gitleaks" and args[1] == "dir" and args[2] == "."
    assert "--ignore-gitleaks-allow" in args and "--config" in args
    assert args[args.index("--config") + 1] == str(tools_mod.CONFIG_DIR / "gitleaks.toml")
    assert args[args.index("--gitleaks-ignore-path") + 1] == str(tools_mod.CONFIG_DIR)
    assert kw["cwd"] == tmp_path  # relative `.` target: the tool runs inside the scanned tree
    (tmp_path / ".git").unlink()
    (tmp_path / ".git").mkdir()
    asyncio.run(tools_mod.run_gitleaks(tmp_path, tmp_path / "o", "n"))
    assert calls[-1][0][1] == "git"
    sg = tools_mod.semgrep_args()
    assert sg[:2] == ["semgrep", "scan"] and sg[-1] == "." and "--disable-nosem" in sg and any(a.startswith("--x-semgrepignore-filename=") for a in sg)
    tv = tools_mod.trivy_args()
    assert tv[tv.index("--ignorefile") + 1] == str(tools_mod.CONFIG_DIR / "trivyignore")
    assert tv[-1] == "." and not any(a in ("--add-host", "-v") for a in tv)
    for f in ("gitleaks.toml", "trivy.yaml", "trivyignore", "semgrep-exclude.txt"):
        assert (tools_mod.CONFIG_DIR / f).is_file()


# --------------------------------------------------------------------------- 3. exclude globs
def test_excluded_findings_are_not_marked_fixed(env):
    store, asset, scan = env
    scan(semgrep=ToolOutput(raw=load("semgrep.json")))
    store.save_asset(store.get_asset(asset.id).model_copy(update={"exclude": ["app.py"]}))
    s = scan(semgrep=ToolOutput(raw=load("semgrep.json")))  # every result is now filtered out
    assert s.tools["semgrep"] == "done" and sum(s.counts.values()) == 0
    fs = store.list_findings(asset_id=asset.id, tool="semgrep")
    assert fs and all(f.status == "open" for f in fs)  # unchanged: no fake "fixed" progress

    from app import posture

    p = posture.get_posture(asset.id)
    assert p.fixed == 0 and p.risk_fixed == 0


# --------------------------------------------------------------------------- 4. stable fingerprints
def test_semgrep_fingerprint_has_no_line_and_survives_shift_in_store(tmp_store, tmp_path):
    src = tmp_path / "src"
    shutil.copytree(FX / "src", src)
    first = normalize_semgrep(load("semgrep.json"), Ctx("s1", "a", src))
    for f in first:
        tmp_store.upsert_finding(f)
    target = first[0]
    tmp_store.update_finding(
        target.id, status="fixing", fix_id="fix_1", ai_summary="explained",
        validation=Validation(finding_id=target.id, check="cwe-89-sqli", result="confirmed", confidence=0.9),
    )
    (src / "app.py").write_text("# a\n# b\n# c\n" + (src / "app.py").read_text())
    raw = load("semgrep.json")
    for r in raw["results"]:
        r["start"]["line"] += 3
        r["end"]["line"] += 3
    second = normalize_semgrep(raw, Ctx("s2", "a", src))
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    new = [tmp_store.upsert_findings([f])[0][1] for f in second]
    assert not any(new)
    kept = tmp_store.get_finding(target.id)
    assert (kept.status, kept.fix_id, kept.ai_summary, kept.validation.result) == ("fixing", "fix_1", "explained", "confirmed")
    assert kept.line == target.line + 3 and kept.scan_id == "s2"


def test_gitleaks_fingerprint_stable_across_line_shift(tmp_path):
    tok = rand(36, "ghp_")
    src = tmp_path / "src"
    src.mkdir()
    (src / "settings.py").write_text(f'GITHUB_TOKEN = "{tok}"\n')
    raw = [dict(load("gitleaks.json")[0], Secret=tok, Match=f'GITHUB_TOKEN = "{tok}"')]
    a = normalize_gitleaks(raw, Ctx("s", "a", src))
    (src / "settings.py").write_text(f'import os\n\nGITHUB_TOKEN = "{tok}"\n')
    shifted = [dict(raw[0], StartLine=3, EndLine=3, StartColumn=18, EndColumn=57, Commit="",
                    Fingerprint="settings.py:github-pat:3")]
    b = normalize_gitleaks(shifted, Ctx("s", "a", src))
    assert a[0].fingerprint == b[0].fingerprint and b[0].line == 3
    other = normalize_gitleaks([dict(raw[0], Secret=rand(36, "ghp_"))], Ctx("s", "a", src))
    assert other[0].fingerprint != a[0].fingerprint  # a different secret is a different finding
    assert tok not in a[0].model_dump_json() and tok not in b[0].model_dump_json()


def test_legacy_fingerprints_adopted_once(tmp_store):
    old = Finding(scan_id="s0", asset_id="a", fingerprint="legacy-line-based", tool="semgrep", rule_id="r.sqli",
                  title="t", severity="high", category="sast", file="app.py", line=14, status="validated", fix_id="fix_9")
    tmp_store.upsert_finding(old)
    new = old.model_copy(update={"id": "fnd_new", "fingerprint": "v2-code-based", "status": "open", "fix_id": None, "scan_id": "s1"})
    (stored, is_new), = tmp_store.upsert_findings([new], adopt_legacy=True)
    assert not is_new and stored.id == old.id and stored.status == "validated" and stored.fix_id == "fix_9"
    assert stored.fingerprint == "v2-code-based"
    assert len(tmp_store.list_findings(asset_id="a")) == 1


# --------------------------------------------------------------------------- 5. redaction
def test_redact_keeps_no_secret_characters():
    sec = rand(30)
    assert not windows(sec, 1) & set(redact(sec)) - {"*"}
    assert set(redact("abcd")) == {"*"}


def test_gitleaks_dir_mode_column_shift_leaves_no_secret_chars(tmp_path):
    key = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + "234567") for _ in range(16))
    src = tmp_path / "src"
    src.mkdir()
    (src / "settings.py").write_text(f'import os\nx = 1\nAWS = "{key}"\n')
    # real gitleaks 8.30 dir-mode output: columns are shifted by +1 after the first line
    raw = [{"RuleID": "aws-access-token", "StartLine": 3, "EndLine": 3, "StartColumn": 9, "EndColumn": 28,
            "Match": "REDACTED", "Secret": "REDACTED", "File": "/src/settings.py", "Commit": ""}]
    f = normalize_gitleaks(raw, Ctx("s", "a", src))[0]
    assert f.snippet.startswith("AWS = ")
    # Only inspect the value: random secret pairs can legitimately match the variable name AWS.
    assert not any(w in f.snippet[len('AWS = '):] for w in windows(key, 2)), f.snippet


def test_semgrep_hardcoded_credential_cwe_is_secret_class(tmp_path):
    pw = rand(20)
    src = tmp_path / "src"
    src.mkdir()
    (src / "db.py").write_text(f'import psycopg2\nconn = psycopg2.connect(host="db", password="{pw}")\n')
    raw = {"results": [{
        "check_id": "python.lang.security.audit.hardcoded-password-default-argument",
        "path": "/src/db.py", "start": {"line": 2, "col": 8}, "end": {"line": 2, "col": 70},
        "extra": {"message": "hard-coded password", "severity": "WARNING", "lines": "requires login",
                  "metadata": {"cwe": ["CWE-259: Use of Hard-coded Password"], "category": "security"}}}]}
    f = normalize_semgrep(raw, Ctx("s", "a", src))[0]
    assert f.category == "secret" and f.cwe == "CWE-259"
    assert pw not in f.model_dump_json() and not any(w in f.snippet for w in windows(pw))


def test_obvious_secret_assignment_in_sast_snippet_is_masked(tmp_path):
    pw = rand(16)
    src = tmp_path / "src"
    src.mkdir()
    (src / "v.py").write_text(f'def v(request):\n    DB_PASSWORD = "{pw}"\n    cur.execute("SELECT " + request.GET["q"])\n')
    raw = {"results": [{
        "check_id": "python.django.security.injection.sql.raw-query", "path": "/src/v.py",
        "start": {"line": 1, "col": 1}, "end": {"line": 3, "col": 10},
        "extra": {"message": "sqli", "severity": "ERROR", "lines": "requires login",
                  "metadata": {"cwe": ["CWE-89: SQL Injection"]}}}]}
    f = normalize_semgrep(raw, Ctx("s", "a", src))[0]
    assert f.category == "sast" and pw not in f.model_dump_json()
    assert "DB_PASSWORD" in f.snippet and 'request.GET["q"]' in f.snippet


def test_trivy_ds0031_snippet_is_redacted():
    val = rand(24)
    raw = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [{
        "ID": "DS-0031", "AVDID": "AVD-DS-0031", "Title": "Secrets passed via build-args or envs",
        "Message": "Possible exposure of secret env \"SECRET_KEY\" in ENV", "Severity": "CRITICAL", "Status": "FAIL",
        "CauseMetadata": {"StartLine": 2, "EndLine": 2, "Code": {"Lines": [{"Number": 2, "Content": f"ENV SECRET_KEY={val}"}]}},
    }]}]}
    f = normalize_trivy(raw, Ctx("s", "a", None))[0]
    assert f.rule_id == "DS-0031" and "SECRET_KEY" in f.snippet
    assert val not in f.model_dump_json() and not any(w in f.snippet for w in windows(val))
