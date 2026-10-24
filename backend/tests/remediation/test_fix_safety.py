"""Review findings: real change-set guard, suppression markers, secret handling, crash safety, concurrency."""

import json
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest

from app.models import Finding
from app.remediation import context, fix, github, llm, verify
from app.remediation.sh import Result
from app.remediation.verify import RescanResult

from .conftest import django_finding, git
from .test_fix import FORK, FakeGH, fake_verify, remote, remote_file, set_mode  # noqa: F401  (fixtures)

SECRET = "q8Zr2LmX9vT4kP7wN3sB6yH1cJ5d"


def push_files(bare: Path, files: dict[str, str], tmp: Path, msg="add files"):
    w = tmp / f"push-{len(list(tmp.iterdir()))}"
    subprocess.run(["git", "clone", "-q", str(bare), str(w)], check=True)
    for rel, content in files.items():
        (w / rel).parent.mkdir(parents=True, exist_ok=True)
        (w / rel).write_text(content)
    git(w, "add", "-A")
    git(w, "commit", "-q", "-m", msg)
    git(w, "push", "-q", "origin", "HEAD:master")


def sast_finding(store, asset, file="introduction/views.py", line=8, fp="sq"):
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint=fp, tool="semgrep", rule_id="python.sqli", title="SQLi",
                severity="high", category="sast", file=file, line=line, cwe="CWE-89")
    stored, _ = store.upsert_finding(f)
    return stored


def model_returns(monkeypatch, payload, seen=None):
    def fake(msgs, **kw):
        if seen is not None:
            seen.append(msgs)
        return payload, llm.LLMResult(content=json.dumps(payload), model="fake")
    monkeypatch.setattr(fix.llm, "chat_json", fake)


def semgrep_gone(monkeypatch):
    monkeypatch.setattr(fix, "rescan", lambda f, repo, base, changed: RescanResult("semgrep", True, False, "rule gone"))


# =========================================================================== 1. real change set
QUOTED_WORKFLOW_DIFF = (
    'diff --git "a/.github/workflows/ci.yml" "b/.github/workflows/ci.yml"\n'
    '--- "a/.github/workflows/ci.yml"\n'
    '+++ "b/.github/workflows/ci.yml"\n'
    "@@ -1 +1 @@\n"
    "-name: ci\n"
    "+name: pwned\n"
)


def test_quoted_path_workflow_diff_refused(store, asset, remote, fake_verify, monkeypatch, tmp_path):
    push_files(remote, {".github/workflows/ci.yml": "name: ci\n"}, tmp_path)
    set_mode(store, "assisted")
    semgrep_gone(monkeypatch)
    # the old regex `^\+\+\+ b/(\S+)` saw no files in this diff, so _guard_files passed it
    assert fix.re.findall(r"^\+\+\+ b/(\S+)", QUOTED_WORKFLOW_DIFF, fix.re.M) == []
    model_returns(monkeypatch, {"explanation": "x", "diff": QUOTED_WORKFLOW_DIFF, "edits": []})
    f = sast_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "failed"
    assert ".github/workflows/ci.yml" in fx.verification.details and "outside the finding's file" in fx.verification.details
    assert not FakeGH.all_prs() and not fake_verify["boots"]
    assert remote_file(remote, ".github/workflows/ci.yml") == "name: ci\n"
    assert store.get_finding(f.id).status != "fixing"


def test_deletion_diff_refused(store, asset, remote, fake_verify, monkeypatch, mini_repo):
    set_mode(store, "assisted")
    semgrep_gone(monkeypatch)
    body = (mini_repo / "introduction" / "views.py").read_text().splitlines()
    diff = ("diff --git a/introduction/views.py b/introduction/views.py\ndeleted file mode 100644\n"
            "--- a/introduction/views.py\n+++ /dev/null\n" + f"@@ -1,{len(body)} +0,0 @@\n"
            + "".join(f"-{ln}\n" for ln in body))
    model_returns(monkeypatch, {"explanation": "x", "diff": diff, "edits": []})
    f = sast_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "failed" and "delete of introduction/views.py" in fx.verification.details
    assert not FakeGH.all_prs()


def _repo(tmp_path) -> Path:
    r = tmp_path / "g"
    r.mkdir()
    (r / "a.py").write_text("x = 1\n")
    (r / "b.py").write_text("y = 2\n")
    git(r, "init", "-q", "-b", "master")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "init")
    return r


@pytest.mark.parametrize("diff,needle", [
    ("diff --git a/a.py b/a.py\nold mode 100644\nnew mode 100755\n", "mode change"),
    ("diff --git a/a.py b/c.py\nsimilarity index 100%\nrename from a.py\nrename to c.py\n", "a.py"),
    ("diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+print(1)\n", "new file new.py"),
    ("diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-y = 2\n+y = 3\n", "b.py is outside"),
])
def test_guard_changes_rejects(tmp_path, diff, needle):
    r = _repo(tmp_path)
    ok, msg = fix.apply_diff(r, diff)
    assert ok, msg
    with pytest.raises(fix.FixRefused) as ei:
        fix._guard_changes(r, {"a.py"}, llm_written=True)
    assert needle in ei.value.reason


def test_guard_changes_rejects_binary(tmp_path):
    r = _repo(tmp_path)
    (r / "a.py").write_bytes(b"x = 1\x00\x01\n")
    diff = subprocess.run(["git", "diff", "--binary"], cwd=r, capture_output=True, text=True, check=True).stdout
    git(r, "checkout", "--", "a.py")
    assert fix.apply_diff(r, diff)[0]
    with pytest.raises(fix.FixRefused) as ei:
        fix._guard_changes(r, {"a.py"}, llm_written=True)
    assert "binary change to a.py" in ei.value.reason


def test_guard_changes_accepts_in_place_edit(tmp_path):
    r = _repo(tmp_path)
    assert fix.apply_diff(r, "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n")[0]
    assert fix._guard_changes(r, {"a.py"}, llm_written=True) == ["a.py"]


def test_llm_may_not_patch_build_files(store, asset, mini_repo):
    for p in ("Dockerfile", "requirements.txt", "setup.py", ".github/workflows/x.yml", "pyproject.toml"):
        f = Finding(scan_id="s", asset_id=asset.id, fingerprint=p, tool="semgrep", rule_id="r", title="t",
                    severity="low", category="config", file=p, line=1)
        with pytest.raises(fix.FixRefused) as ei:
            fix.llm_patch(f, mini_repo, "fix_x")
        assert ei.value.status_code == 422


def test_llm_edit_of_other_file_refused(store, asset, mini_repo, monkeypatch):
    model_returns(monkeypatch, {"edits": [{"file": "pygoat/urls.py", "find": "path", "replace": "x"}]})
    with pytest.raises(fix.FixRefused) as ei:
        fix.llm_patch(sast_finding(store, asset), mini_repo, "fix_x")
    assert "only introduction/views.py may change" in ei.value.reason


def test_patched_code_builds_offline_with_base_first(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    semgrep_gone(monkeypatch)
    fx = fix.propose_fix(sast_finding(store, asset).id, wait=True)
    assert fx.status == "pr_opened", fx.verification.details
    kw = fake_verify["boot_kw"][0]
    assert kw["network"] is False and kw["base_src"] is not None
    # dependency bumps (fixed template, needs pip) keep network
    fx2 = fix.propose_fix(django_finding(store, asset).id, wait=True)
    assert fx2.status == "pr_opened" and fake_verify["boot_kw"][-1]["network"] is True


# =========================================================================== 4. suppression markers / vacuous rescans
def test_rescan_requires_before_present():
    assert RescanResult("semgrep", True, False).gone is True
    assert RescanResult("semgrep", None, False).gone is False
    assert RescanResult("semgrep", False, False).gone is False


def test_suppression_marker_patch_refused(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    semgrep_gone(monkeypatch)
    line = "    cur.execute(\"SELECT * FROM users WHERE name='%s'\" % name)"
    model_returns(monkeypatch, {"edits": [{"file": "introduction/views.py", "find": line, "replace": line + "  # nosemgrep"}]})
    fx = fix.propose_fix(sast_finding(store, asset).id, wait=True)
    assert fx.status == "failed" and "suppression marker" in fx.verification.details
    assert not FakeGH.all_prs()


def test_added_suppressions_detects_markers():
    d = "+++ b/x.py\n+a = 1  # nosemgrep\n+k = 'x'  # gitleaks:allow\n-old # nosec\n+fine = 2\n"
    assert len(verify.added_suppressions(d)) == 2


def test_vacuous_rescan_fails_fix(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    monkeypatch.setattr(fix, "rescan", lambda f, repo, base, changed: RescanResult("semgrep", None, False, "scanner error"))
    fx = fix.propose_fix(sast_finding(store, asset).id, wait=True)
    assert fx.status == "failed" and fx.verification.validation_result == "not_reproduced_before"


def test_scanners_ignore_inline_suppressions(monkeypatch, tmp_path):
    calls = []

    def fake(args, *, timeout=300, cwd=None, **kw):
        calls.append(args)
        return Result(0, '{"results": []}', "")

    monkeypatch.setattr(verify, "run", fake)
    verify._semgrep(tmp_path, "python.sqli")
    verify._gitleaks(tmp_path)
    assert "--disable-nosem" in calls[0] and "--ignore-gitleaks-allow" in calls[-1]


# =========================================================================== 5. secrets
SECRET_FILE = f'"""Settings."""\nimport json\n\nAPI_TOKEN = "{SECRET}"\nDEBUG = True\n'


def test_secret_fix_uses_template_and_never_leaks(store, asset, remote, fake_verify, monkeypatch, tmp_path):
    push_files(remote, {"app/conf.py": SECRET_FILE}, tmp_path)
    set_mode(store, "assisted")
    monkeypatch.setattr(fix, "rescan", lambda f, repo, base, changed: RescanResult("gitleaks", True, False, "rule gone"))
    called = []
    monkeypatch.setattr(fix.llm, "chat_json", lambda *a, **k: called.append(1) or (_ for _ in ()).throw(AssertionError("LLM called")))
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="sec", tool="gitleaks", rule_id="generic-api-key",
                title="Generic API Key", severity="high", category="secret", file="app/conf.py", line=4, snippet="REDACTED")
    store.upsert_finding(f)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "pr_opened", fx.verification.details
    assert not called
    assert SECRET not in fx.diff and context.REDACTED in fx.diff
    patched = remote_file(remote, "app/conf.py", rev=fx.branch)
    assert 'API_TOKEN = os.environ.get("API_TOKEN", "")' in patched and SECRET not in patched
    assert patched.splitlines()[1] == "import os"
    for e in store.recent_events(500):
        assert SECRET not in json.dumps(e.model_dump())
    assert "API_TOKEN" in FakeGH.instances[-1].prs[0]["body"]


def test_secret_in_non_python_file_refused(store, asset, remote, fake_verify, monkeypatch, tmp_path):
    push_files(remote, {"conf/.env": f"API_TOKEN={SECRET}\n"}, tmp_path)
    set_mode(store, "assisted")
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="sec2", tool="gitleaks", rule_id="generic-api-key",
                title="key", severity="high", category="secret", file="conf/.env", line=1)
    store.upsert_finding(f)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "failed" and "only supports Python" in fx.verification.details


def test_llm_prompt_masks_secrets(store, asset, mini_repo, monkeypatch):
    (mini_repo / "introduction" / "views.py").write_text(
        (mini_repo / "introduction" / "views.py").read_text() + f'\nPASSWORD = "{SECRET}"\nOTHER = "Zx9Kq2Lm8Np4Rt6Vw1Yb3Cd5Fg7Hj"\n')
    seen = []
    model_returns(monkeypatch, {"edits": []}, seen)
    with pytest.raises(fix.FixRefused):
        fix.llm_patch(sast_finding(store, asset), mini_repo, "fix_x")
    sent = json.dumps(seen)
    assert SECRET not in sent and "Zx9Kq2Lm8Np4Rt6Vw1Yb3Cd5Fg7Hj" not in sent and context.REDACTED in sent


def test_explain_context_masks_secrets(store, asset, mini_repo):
    (mini_repo / "introduction" / "views.py").write_text(f'api_key = "{SECRET}"\n' + (mini_repo / "introduction" / "views.py").read_text())
    f = sast_finding(store, asset)
    assert SECRET not in context.code_context(mini_repo, f)


# =========================================================================== 7. crash safety
def test_unexpected_exception_fails_fix_instead_of_sticking(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    monkeypatch.setattr(fix, "dependency_patch", lambda f, repo: (_ for _ in ()).throw(RuntimeError("boom")))
    f = django_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "failed" and "internal error: RuntimeError: boom" in fx.verification.details
    assert store.get_finding(f.id).status != "fixing"
    assert not fix.in_flight(fx.id)


def test_malformed_edits_rejected(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    model_returns(monkeypatch, {"edits": [{"file": "introduction/views.py", "find": 3, "replace": None}]})
    fx = fix.propose_fix(sast_finding(store, asset).id, wait=True)
    assert fx.status == "failed" and "malformed edits" in fx.verification.details
    model_returns(monkeypatch, {"edits": "rewrite everything"})
    fx = fix.propose_fix(sast_finding(store, asset, fp="sq2").id, wait=True)
    assert fx.status == "failed" and "malformed edits" in fx.verification.details


def test_httpx_errors_become_github_errors(monkeypatch):
    def boom(request):
        raise httpx.ConnectError("no route", request=request)

    monkeypatch.setattr(github, "_client", lambda token: httpx.Client(base_url=github.API, transport=httpx.MockTransport(boom)))
    gh = github.GitHub(FORK, token="tok-secret-1")
    with pytest.raises(github.GitHubError) as ei:
        gh.get_pr(1)
    assert "ConnectError" in str(ei.value) and "tok-secret-1" not in str(ei.value)


# =========================================================================== 8/9. concurrency + mode
def _blocking_pipeline(monkeypatch):
    gate, started = threading.Event(), threading.Event()
    real = fix._pipeline

    def slow(fx, f):
        started.set()
        assert gate.wait(10)
        return real(fx, f)

    monkeypatch.setattr(fix, "_pipeline", slow)
    return gate, started


def _wait_idle(fix_id):
    for _ in range(200):
        if not fix.in_flight(fix_id):
            return
        time.sleep(0.05)
    raise AssertionError("pipeline did not finish")


def test_double_fix_calls_share_one_pipeline(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    gate, started = _blocking_pipeline(monkeypatch)
    f = django_finding(store, asset)
    results = []
    ts = [threading.Thread(target=lambda: results.append(fix.propose_fix(f.id))) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len({r.id for r in results}) == 1
    fid = results[0].id
    assert started.wait(5)
    with pytest.raises(fix.FixRefused) as ei:
        fix.rollback_fix(fid)
    assert ei.value.status_code == 409
    with pytest.raises(fix.FixRefused) as ei:
        fix.apply_fix(fid)
    assert ei.value.status_code == 409
    gate.set()
    _wait_idle(fid)
    assert store.get_fix(fid).status == "pr_opened"
    assert len(FakeGH.all_prs()) == 1
    assert fix.propose_fix(f.id).id == fid  # active fix is reused, no second PR


def test_apply_does_not_overwrite_terminal_state(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "assisted")
    semgrep_gone(monkeypatch)
    fx = fix.propose_fix(sast_finding(store, asset).id, wait=True)
    assert fix.rollback_fix(fx.id).status == "rolled_back"
    set_mode(store, "autonomous")
    with pytest.raises(fix.FixRefused) as ei:
        fix.apply_fix(fx.id)
    assert ei.value.status_code == 409
    assert store.get_fix(fx.id).status == "rolled_back"


def test_rollback_refused_in_observe_mode(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    fx = fix.propose_fix(django_finding(store, asset).id, wait=True)
    assert fx.pr_url
    set_mode(store, "observe")
    with pytest.raises(fix.FixRefused) as ei:
        fix.rollback_fix(fx.id)
    assert ei.value.status_code == 403
    assert store.get_fix(fx.id).status == "pr_opened" and not FakeGH.instances[-1].closed


def test_stale_proposed_fix_is_replaced(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    f = django_finding(store, asset)
    stale = fix.Fix(finding_id=f.id, mode="assisted", status="proposed")
    store.save_fix(stale)
    store.update_finding(f.id, fix_id=stale.id, status="fixing")
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.id != stale.id and fx.status == "pr_opened"
    assert store.get_fix(stale.id).status == "failed"


def test_autonomous_merge_is_pinned_to_verified_sha(store, asset, remote, fake_verify):
    set_mode(store, "autonomous")
    fx = fix.propose_fix(django_finding(store, asset).id, wait=True)
    assert fx.status == "applied"
    from app.remediation import core
    assert FakeGH.merge_shas[0] == core.fix_meta(fx.id)["verified_sha"]
