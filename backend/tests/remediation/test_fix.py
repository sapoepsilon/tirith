import subprocess
from pathlib import Path

import pytest

from app.models import Asset, Finding, ModeSettings
from app.remediation import core, fix, lab
from app.remediation.github import GitHub, PolicyError
from app.remediation.verify import RescanResult

from .conftest import django_finding, git, trivy_findings

FORK = "sapoepsilon/tirith-demo-target"


class FakeGH:
    """Stands in for the GitHub REST client; 'remote' is a local bare repo. Keeps the real policy check."""

    instances: list["FakeGH"] = []
    merge_shas: list = []
    bare: Path = None

    def __init__(self, repo, token=None):
        ok, reason = core.check_pr_repo(repo)
        if not ok:
            raise PolicyError(reason)
        self.repo, self.token = repo, "fake"
        self.prs, self.merged, self.closed, self.comments = [], [], [], []
        FakeGH.instances.append(self)

    def base_branch(self):
        return "master"

    def clone_url(self):
        return str(FakeGH.bare)

    def open_pr(self, branch, base, title, body):
        n = len(FakeGH.all_prs()) + 1
        head = subprocess.run(["git", "--git-dir", str(FakeGH.bare), "rev-parse", f"refs/heads/{branch}"],
                              capture_output=True, text=True, check=True).stdout.strip()
        pr = {"number": n, "html_url": f"https://github.com/{self.repo}/pull/{n}", "head": {"sha": head, "ref": branch},
              "base": {"repo": {"full_name": self.repo}, "ref": base}, "title": title, "body": body}
        self.prs.append(pr)
        return pr

    @staticmethod
    def all_prs():
        return [p for i in FakeGH.instances for p in i.prs]

    def merge_pr(self, number, title=None, sha=None):
        pr = next(p for p in FakeGH.all_prs() if p["number"] == number)
        FakeGH.merge_shas.append(sha)
        assert sha == pr["head"]["sha"], "merge must be pinned to the verified head"
        tmp = Path(str(FakeGH.bare) + f"-merge-{number}")
        subprocess.run(["git", "clone", "-q", str(FakeGH.bare), str(tmp)], check=True)
        git(tmp, "fetch", "-q", "origin", pr["head"]["ref"])
        git(tmp, "merge", "-q", "--no-ff", "-m", title or "merge", "FETCH_HEAD")
        git(tmp, "push", "-q", "origin", "HEAD:master")
        sha = git(tmp, "rev-parse", "HEAD").strip()
        self.merged.append(number)
        return {"sha": sha, "merged": True}

    def close_pr(self, number):
        self.closed.append(number)

    def delete_branch(self, branch):
        pass

    def comment(self, number, body):
        self.comments.append((number, body))


@pytest.fixture
def remote(tmp_path, mini_repo, monkeypatch):
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(mini_repo), str(bare)], check=True)
    FakeGH.bare, FakeGH.instances, FakeGH.merge_shas = bare, [], []
    monkeypatch.setattr(fix, "GitHub", FakeGH)
    monkeypatch.setenv("TIRITH_POSTMERGE_CHECK", "0")
    return bare


@pytest.fixture
def fake_verify(monkeypatch):
    state = {"after_present": False, "boot_ok": True, "boots": []}

    def boot(src, label, keep=True, on_step=None, **kw):
        state["boots"].append((Path(src), (Path(src) / "requirements.txt").read_text()))
        state.setdefault("boot_kw", []).append(kw)
        h = lab.LabHandle(url="http://tirith-lab-x:8000/", network="tirith-lab", container="tirith-lab-x", image="tirith-lab/x:1",
                          port=8000, ok=state["boot_ok"])
        h.evidence = [lab.ev("response", "boot probe", "GET / -> HTTP 302"), lab.ev("note", "egress check", "EGRESS-BLOCKED")]
        return h

    monkeypatch.setattr(lab, "boot", boot)
    monkeypatch.setattr(lab.LabHandle, "stop", lambda self: None)
    monkeypatch.setattr(fix, "rescan", lambda f, repo, base, changed: RescanResult("trivy", True, state["after_present"], "Django: 0 advisories remain"))
    return state


def remote_file(bare: Path, path="requirements.txt", rev="master") -> str:
    return subprocess.run(["git", "--git-dir", str(bare), "show", f"{rev}:{path}"], capture_output=True, text=True, check=True).stdout


def set_mode(store, mode, cats=("dependency_bump",)):
    store.set_mode(ModeSettings(mode=mode, autonomous_categories=list(cats)))


def test_observe_refuses(store, asset):
    f = django_finding(store, asset)
    with pytest.raises(fix.FixRefused) as ei:
        fix.propose_fix(f.id, wait=True)
    assert ei.value.status_code == 403
    assert store.recent_events(5)[-1].type == "policy.denied"
    assert store.list_audit(1)[0].allowed is False


def test_request_cannot_raise_mode(store, asset):
    set_mode(store, "observe")
    f = django_finding(store, asset)
    with pytest.raises(fix.FixRefused):
        fix.propose_fix(f.id, mode="autonomous", wait=True)


def test_upstream_parent_is_never_a_pr_target(store):
    assert core.check_pr_repo(FORK)[0] is True
    assert core.check_pr_repo("adeyosemanputra/pygoat")[0] is False
    with pytest.raises(PolicyError):
        GitHub("adeyosemanputra/pygoat")
    up = store.save_asset(Asset(kind="github_repo", ref="adeyosemanputra/pygoat", name="up"))
    f = Finding(scan_id="s", asset_id=up.id, fingerprint="u", tool="trivy", rule_id="CVE-1", title="t", severity="high",
                category="dependency", file="requirements.txt", package="Django", installed_version="4.2", fixed_version="4.2.1")
    store.upsert_finding(f)
    set_mode(store, "assisted")
    with pytest.raises(fix.FixRefused) as ei:
        fix.propose_fix(f.id, wait=True)
    assert ei.value.status_code == 403 and "not allowed" in ei.value.reason


def test_local_path_asset_uses_fork_not_origin(store, asset):
    assert core.pr_repo_for(asset) == FORK


def test_assisted_dependency_bump_opens_pr_never_merges(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    for f in trivy_findings(asset):
        store.upsert_finding(f)
    f = next(x for x in store.list_findings(asset_id=asset.id) if x.rule_id == "CVE-2023-31047")
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "pr_opened", fx.verification.details
    assert "-Django==4.2\n" in fx.diff and "+Django==4.2.30\n" in fx.diff  # consolidated on the 4.2 line
    assert fx.branch.startswith("tirith/django-")
    assert fx.verification.tests_passed is None and fx.verification.validation_result == "fixed"
    assert "(c)" not in (fx.verification.details or "") and not hasattr(lab, "run_tests")
    gh = FakeGH.instances[-1]
    assert gh.repo == FORK and gh.prs and not gh.merged
    assert "Verification" in gh.prs[0]["body"] and "CVE-2023-31047" in gh.prs[0]["body"]
    # branch pushed to the remote, master untouched
    assert remote_file(remote, rev=fx.branch).splitlines()[1] == "Django==4.2.30"
    assert remote_file(remote).splitlines()[1] == "Django==4.2"
    # patched tree was the one booted in the lab
    assert "Django==4.2.30" in fake_verify["boots"][0][1]
    types = [e.type for e in store.recent_events(200)]
    for t in ("fix.started", "fix.patch", "fix.verified", "fix.pr_opened"):
        assert t in types
    assert "fix.applied" not in types
    with pytest.raises(fix.FixRefused) as ei:
        fix.apply_fix(fx.id)
    assert ei.value.status_code == 409
    actions = [a.action for a in store.list_audit(100)]
    for a in ("remediation.fix.start", "remediation.fix.patch", "remediation.fix.verify", "remediation.fix.push", "remediation.fix.pr_opened"):
        assert a in actions


def test_single_cve_without_consolidation(store, asset, remote, fake_verify, monkeypatch):
    monkeypatch.setenv("TIRITH_DEP_CONSOLIDATE", "0")
    set_mode(store, "assisted")
    f = django_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert "+Django==4.2.1\n" in fx.diff


def test_verification_failure_does_not_push(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    fake_verify["after_present"] = True
    f = django_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "failed" and "STILL PRESENT" in fx.verification.details
    assert not FakeGH.all_prs()
    assert store.get_finding(f.id).status in ("open", "validated")


def test_lab_boot_failure_fails_fix(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    fake_verify["boot_ok"] = False
    f = django_finding(store, asset)
    assert fix.propose_fix(f.id, wait=True).status == "failed"


def test_autonomous_merges_dependency_bump_then_rollback(store, asset, remote, fake_verify):
    set_mode(store, "autonomous")
    f = django_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "applied", fx.verification.details
    assert remote_file(remote).splitlines()[1] == "Django==4.2.1"
    assert store.get_finding(f.id).status == "fixed"
    meta = core.fix_meta(fx.id)
    assert meta["merge_sha"]
    rb = fix.rollback_fix(fx.id)
    assert rb.status == "rolled_back"
    assert remote_file(remote).splitlines()[1] == "Django==4.2"  # merge reverted on master
    assert core.fix_meta(fx.id)["revert_pr"].endswith("/pull/2")
    assert store.get_finding(f.id).status == "open"
    types = [e.type for e in store.recent_events(200)]
    assert "fix.applied" in types and "fix.rolled_back" in types


def test_autonomous_escalates_non_allowlisted_category(store, asset, remote, fake_verify, monkeypatch):
    set_mode(store, "autonomous")
    monkeypatch.setattr(fix, "rescan", lambda f, repo, base, changed: RescanResult("semgrep", True, False, "rule gone"))
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="sq", tool="semgrep", rule_id="python.sqli", title="SQLi",
                severity="high", category="sast", file="introduction/views.py", line=8, cwe="CWE-89")
    store.upsert_finding(f)
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "escalated", fx.verification.details
    assert "# tirith: reviewed" in fx.diff  # stub LLM edit applied via git apply --check
    gh = FakeGH.instances[-1]
    assert not gh.merged and gh.comments
    with pytest.raises(fix.FixRefused):
        fix.apply_fix(fx.id)


def test_rollback_unmerged_pr_closes_it(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    f = django_finding(store, asset)
    fx = fix.propose_fix(f.id, wait=True)
    rb = fix.rollback_fix(fx.id)
    assert rb.status == "rolled_back" and FakeGH.instances[-1].closed == [1]


def test_apply_diff_rejects_bad_patch(mini_repo):
    ok, msg = fix.apply_diff(mini_repo, "diff --git a/nope.txt b/nope.txt\n--- a/nope.txt\n+++ b/nope.txt\n@@ -1 +1 @@\n-a\n+b\n")
    assert not ok and "git apply --check failed" in msg


def test_guard_blocks_ci_files():
    with pytest.raises(fix.FixRefused):
        fix._guard_files([".github/workflows/tests.yml"])


def test_grouped_dependency_bump_resolves_all_listed_advisories(store, asset, remote, fake_verify):
    set_mode(store, "assisted")
    for f in trivy_findings(asset, group=True):
        store.upsert_finding(f)
    f = next(x for x in store.list_findings(asset_id=asset.id) if x.package == "Django")
    assert f.rule_id == "dependency:django" and len(f.advisories) > 10 and f.severity == "critical"
    assert "Staying on the 4.2.x line: 4.2.30" in f.description
    fx = fix.propose_fix(f.id, wait=True)
    assert fx.status == "pr_opened", fx.verification.details
    assert "-Django==4.2\n" in fx.diff and f"+Django=={f.fixed_version}\n" in fx.diff
    body = FakeGH.instances[-1].prs[0]["body"]
    assert sum(a.id in body for a in f.advisories) >= 10  # the PR lists every advisory it closes
