"""Normalization of real (captured) scanner output into the contract Finding model."""

import json
import secrets
import shutil
import string
from pathlib import Path

from app.models import Finding
from app.scanners.normalize import (
    Ctx,
    norm_cwe,
    normalize_gitleaks,
    normalize_semgrep,
    normalize_trivy,
    normalize_zap,
)

FX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FX / name).read_text())


def ctx(src=FX / "src"):
    return Ctx(scan_id="scn_t", asset_id="ast_t", src_root=src)


def assert_contract(fs: list[Finding]):
    assert fs
    for f in fs:
        d = f.model_dump()
        assert d["severity"] in ("critical", "high", "medium", "low", "info")
        assert d["category"] in ("sast", "secret", "dependency", "dast", "config")
        assert d["status"] == "open" and 0 <= d["confidence"] <= 1
        assert len(d["fingerprint"]) == 32
        assert d["scan_id"] == "scn_t" and d["asset_id"] == "ast_t"
    assert len({f.fingerprint for f in fs}) == len(fs), "fingerprints must be unique within a run"


def test_semgrep():
    fs = normalize_semgrep(load("semgrep.json"), ctx())
    assert_contract(fs)
    assert len(fs) == 7
    sqli = next(f for f in fs if "tainted-sql-string" in f.rule_id)
    assert sqli.category == "sast" and sqli.severity == "high"
    assert next(f for f in fs if "db-cursor-execute" in f.rule_id).cwe == "CWE-89"
    assert sqli.file == "app.py" and sqli.line == 14
    assert "cur.execute" in sqli.snippet  # snippet read from source, not "requires login"
    assert all(not f.file.startswith("/src") for f in fs)


def test_semgrep_fingerprint_stable_across_line_shift(tmp_path):
    src = tmp_path / "src"
    shutil.copytree(FX / "src", src)
    a = {f.rule_id: f.fingerprint for f in normalize_semgrep(load("semgrep.json"), ctx(src))}
    # Insert two lines at the top and shift the raw results accordingly.
    (src / "app.py").write_text("# header\n# header\n" + (src / "app.py").read_text())
    raw = load("semgrep.json")
    for r in raw["results"]:
        r["start"]["line"] += 2
        r["end"]["line"] += 2
    b = {f.rule_id: f.fingerprint for f in normalize_semgrep(raw, ctx(src))}
    assert a == b


def test_gitleaks_redacts_secret(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    tok = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (src / "settings.py").write_text(f'GITHUB_TOKEN = "{tok}"\n')
    fs = normalize_gitleaks(load("gitleaks.json"), ctx(src))
    assert_contract(fs)
    f = fs[0]
    assert f.category == "secret" and f.cwe == "CWE-798" and f.file == "settings.py" and f.line == 1
    assert tok not in f.model_dump_json()
    assert tok[4:12] not in (f.snippet or "")
    assert f.snippet.startswith("GITHUB_TOKEN = ") and "ghp_" not in f.snippet  # no secret character survives


def test_gitleaks_dedupes_same_secret_in_many_commits():
    raw = load("gitleaks.json")
    dup = dict(raw[0], Commit="0" * 40)
    fs = normalize_gitleaks(raw + [dup], ctx())
    assert len(fs) == 1


def test_trivy_vuln_and_misconfig():
    fs = normalize_trivy(load("trivy.json"), ctx(), group=False)
    assert_contract(fs)
    deps = [f for f in fs if f.category == "dependency"]
    cfg = [f for f in fs if f.category == "config"]
    assert len(deps) == 17 and len(cfg) == 2
    flask = next(f for f in deps if f.cve == "CVE-2018-1000656")
    assert (flask.package, flask.installed_version, flask.fixed_version) == ("flask", "0.12.2", "0.12.3")
    assert flask.file == "requirements.txt" and flask.line == 1  # line found in manifest
    assert flask.severity == "high" and flask.cwe == "CWE-20"
    assert any(f.severity == "critical" and f.package == "pyyaml" for f in deps)
    root = next(f for f in cfg if f.rule_id == "DS-0002")
    assert root.file == "Dockerfile" and "USER" in root.description


# --------------------------------------------------------------------------- dependency grouping
def test_trivy_groups_dependencies_per_package_and_manifest():
    fs = normalize_trivy(load("trivy.json"), ctx())  # group=True is the default
    assert_contract(fs)
    deps = {f.package: f for f in fs if f.category == "dependency"}
    assert set(deps) == {"flask", "jinja2", "pyyaml", "requests"}  # 17 advisories -> 4 findings
    assert len([f for f in fs if f.category == "config"]) == 2  # misconfigs untouched

    flask = deps["flask"]
    assert [a.id for a in flask.advisories][:3] == ["CVE-2018-1000656", "CVE-2019-1010083", "CVE-2023-30861"]
    assert len(flask.advisories) == 4 and flask.advisories[-1].severity == "low"  # worst first
    assert flask.severity == "high"  # max over advisories
    assert flask.fixed_version == "3.1.3"  # the only single version that clears all 4
    assert flask.cve == "CVE-2018-1000656" and flask.rule_id == "dependency:flask"
    assert flask.installed_version == "0.12.2" and flask.file == "requirements.txt" and flask.line == 1
    assert "4 known vulnerabilities" in flask.title and "3.1.3" in flask.title
    assert all(a.id in flask.description for a in flask.advisories)
    assert "resolves 4 of 4" in flask.description

    assert deps["pyyaml"].severity == "critical" and deps["pyyaml"].fixed_version == "5.4"
    assert deps["jinja2"].fixed_version == "3.1.6" and len(deps["jinja2"].advisories) == 6
    assert deps["requests"].fixed_version == "2.33.0"


def test_group_fingerprint_stable_across_version_bump():
    data = load("trivy.json")
    before = {f.package: f.fingerprint for f in normalize_trivy(data, ctx()) if f.package}
    bumped = json.loads(json.dumps(data))
    vulns = bumped["Results"][0]["Vulnerabilities"]
    bumped["Results"][0]["Vulnerabilities"] = [dict(v, InstalledVersion="2.2.5") if v["PkgName"] == "flask" else v
                                               for v in vulns if not (v["PkgName"] == "flask" and v["VulnerabilityID"] != "CVE-2026-27205")]
    after = {f.package: f for f in normalize_trivy(bumped, ctx()) if f.package}
    assert after["flask"].fingerprint == before["flask"]  # same finding, now with 1 advisory left
    assert len(after["flask"].advisories) == 1 and after["flask"].severity == "low"


def test_group_separates_manifests():
    data = load("trivy.json")
    lab = json.loads(json.dumps(data["Results"][0]))
    lab["Target"] = "dockerized_labs/xss_lab/requirements.txt"
    data = {**data, "Results": data["Results"] + [lab]}
    fs = [f for f in normalize_trivy(data, ctx()) if f.package == "flask"]
    assert sorted(f.file for f in fs) == ["dockerized_labs/xss_lab/requirements.txt", "requirements.txt"]
    assert len({f.fingerprint for f in fs}) == 2


def test_best_fixed_version_prefers_most_resolved_then_lowest():
    from app.models import Advisory
    from app.scanners.normalize import best_fixed_version

    advs = [Advisory(id="A", severity="high", fixed_version="4.2.16, 5.0.9"),
            Advisory(id="B", severity="medium", fixed_version="4.2.20"),
            Advisory(id="C", severity="low", fixed_version=None)]  # unfixable advisory never counts
    assert best_fixed_version("4.2", advs) == ("4.2.20", 2)
    assert best_fixed_version("4.2", advs[:1]) == ("4.2.16", 1)
    assert best_fixed_version("9.0", advs) == (None, 0)


# --------------------------------------------------------------------------- focus / exclude / sub-apps
def test_web_url_paths_tag_subapps():
    """A DAST finding carries a URL path: its first segment is the sub-app, a bare file at the root is not."""
    from app import focus
    from app.models import AssetProfile

    prof = AssetProfile(sub_apps=["/drupal/*", "/chat/*"])
    for path, want in (("/drupal/misc/jquery.js", "lab:drupal/misc"), ("/chat/", "lab:chat"),
                       ("/chat/index.php", "lab:chat"), ("/drupal/", "lab:drupal"), ("/", None),
                       ("/payroll_app.php", None)):
        f = Finding(scan_id="s", asset_id="a", fingerprint=path, tool="zap", rule_id="r", title="t",
                    severity="high", category="dast", file=path)
        got = focus.apply_profile([f], prof)[0][0]
        assert got.component == (want or "main"), path
        assert ("lab-subapp" in got.tags) == bool(want), path


def test_profile_tags_lab_subapps_excludes_and_periphery():
    from app import focus
    from app.models import AssetProfile

    prof = AssetProfile(focus=["pygoat/**", "introduction/**", "requirements.txt"], exclude=["docs/**"],
                        sub_apps=["dockerized_labs/*", "challenge/labs/*", "challenge"])

    def mk(path):
        return Finding(scan_id="s", asset_id="a", fingerprint=path or "none", tool="semgrep", rule_id="r", title="t",
                       severity="high", category="sast", file=path)

    got = {f.file: f for f in focus.apply_profile(
        [mk(p) for p in ("pygoat/settings.py", "requirements.txt", "dockerized_labs/xss_lab/app.py",
                         "challenge/labs/bopla_lab/app.py", "challenge/views.py", "docs/x.py", "chatbot/bot.py",
                         "introduction/tests.py", None)], prof)[0]}
    assert "docs/x.py" not in got  # excluded
    assert got["pygoat/settings.py"].component == "main" and not got["pygoat/settings.py"].tags
    assert got[None].component == "main"  # DAST / pathless findings belong to the app
    assert got["dockerized_labs/xss_lab/app.py"].component == "lab:dockerized_labs/xss_lab"
    assert "lab-subapp" in got["dockerized_labs/xss_lab/app.py"].tags
    assert got["challenge/labs/bopla_lab/app.py"].component == "lab:challenge/labs/bopla_lab"
    assert got["challenge/views.py"].component == "lab:challenge"
    assert got["chatbot/bot.py"].component == "periphery"
    assert "test-path" in got["introduction/tests.py"].tags
    pr = {k: focus.priority(v) for k, v in got.items()}
    assert pr["pygoat/settings.py"] > pr["chatbot/bot.py"] > pr["dockerized_labs/xss_lab/app.py"]
    assert pr["introduction/tests.py"] < pr["pygoat/settings.py"]


def test_profile_from_scope_yaml_for_pygoat():
    from app import focus
    from app.models import Asset

    a = Asset(kind="local_path", ref="/x/targets/pygoat", name="pygoat")
    prof = focus.resolve_profile(a)
    assert "dockerized_labs/*" in prof.sub_apps and "introduction/**" in prof.focus
    own = focus.resolve_profile(a.model_copy(update={"focus": ["src/**"]}))
    assert own.focus == ["src/**"] and own.sub_apps == prof.sub_apps  # asset fields win per field
    assert focus.resolve_profile(Asset(kind="url", ref="http://localhost:1", name="other")).focus == []


def test_zap():
    fs = normalize_zap(load("zap.json"), ctx(None))
    assert_contract(fs)
    assert {f.category for f in fs} == {"dast"}
    csp = next(f for f in fs if f.rule_id == "zap-10038")
    assert csp.severity == "medium" and csp.cwe == "CWE-693" and csp.url.startswith("http")
    assert "<p>" not in csp.description


def test_zap_fingerprint_stable_across_lab_hosts():
    def rehost(host: str) -> dict:
        raw = json.dumps(load("zap.json")).replace("host.docker.internal:8765", host)
        return json.loads(raw)

    a = normalize_zap(rehost("lab-aaa111:8080"), ctx(None))
    b = normalize_zap(rehost("lab-bbb222:9090"), ctx(None))
    assert a and sorted(f.fingerprint for f in a) == sorted(f.fingerprint for f in b)
    assert all("lab-aaa111" in (f.url or "") for f in a)  # displayed URL untouched


def test_norm_cwe():
    assert norm_cwe(["CWE-89: Improper Neutralization"]) == "CWE-89"
    assert norm_cwe("693") == "CWE-693"
    assert norm_cwe("-1") is None and norm_cwe(None) is None and norm_cwe([]) is None


def test_upsert_dedupes_and_preserves_state(tmp_store):
    fs = normalize_trivy(load("trivy.json"), ctx())
    for f in fs:
        tmp_store.upsert_finding(f)
    first = tmp_store.list_findings(asset_id="ast_t")
    tmp_store.update_finding(first[0].id, status="fixing", fix_id="fix_1")
    again = normalize_trivy(load("trivy.json"), Ctx(scan_id="scn_2", asset_id="ast_t", src_root=FX / "src"))
    new = [tmp_store.upsert_finding(f)[1] for f in again]
    assert not any(new)
    after = tmp_store.list_findings(asset_id="ast_t")
    assert len(after) == len(first)
    kept = tmp_store.get_finding(first[0].id)
    assert kept.status == "fixing" and kept.fix_id == "fix_1" and kept.scan_id == "scn_2"
