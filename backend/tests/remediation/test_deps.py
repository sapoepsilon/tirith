from app.remediation import deps


def test_version_ordering():
    assert deps.vlt("4.2", "4.2.1")
    assert not deps.vlt("4.2.0", "4.2")
    assert deps.vlt("4.2rc1", "4.2")
    assert deps.vlt("2.9.9", "2.10.0")


def test_choose_fixed_version_prefers_same_line():
    assert deps.choose_fixed_version("4.2", "3.2.19, 4.1.9, 4.2.1") == "4.2.1"
    assert deps.choose_fixed_version("2.4.0", "2.14.0") == "2.14.0"
    assert deps.choose_fixed_version("3.2.18", "5.2.17, 6.0.8") == "5.2.17"
    assert deps.choose_fixed_version("4.2.30", "4.2.1") is None


def test_affected_range():
    assert deps.in_affected_range("4.2", "3.2.19, 4.1.9, 4.2.1")[0] is True
    assert deps.in_affected_range("4.2.5", "3.2.19, 4.1.9, 4.2.1")[0] is False
    assert deps.in_affected_range("1.0", None)[0] is True


def test_bump_requirements_keeps_everything_else():
    txt = "asgiref==3.6.0\nDjango==4.2  # web\ndjango-allauth==0.52.0\n"
    new, n = deps.bump_requirements(txt, "django", "4.2.30")
    assert n == 1
    assert new == "asgiref==3.6.0\nDjango==4.2.30  # web\ndjango-allauth==0.52.0\n"


def test_bump_package_json():
    new, n = deps.bump_package_json('{"dependencies": {"lodash": "^4.17.15"}}', "lodash", "4.17.21")
    assert n == 1 and '"^4.17.21"' in new


def test_find_imports_excludes_sub_apps(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text("import jwt\nfrom django.db import models\n")
    lab = tmp_path / "labs" / "x"
    lab.mkdir(parents=True)
    (lab / "requirements.txt").write_text("PyYAML==5.1\n")
    (lab / "b.py").write_text("import yaml\n")
    ex = deps.owned_tree_excludes(tmp_path)
    assert deps.find_imports(tmp_path, "PyJWT", exclude=ex) == ["app/a.py:1: import jwt"]
    assert deps.find_imports(tmp_path, "Django", exclude=ex)
    assert deps.find_imports(tmp_path, "PyYAML", exclude=ex) == []
    assert deps.find_imports(lab, "PyYAML") == ["b.py:1: import yaml"]


def test_rescan_hits_for_grouped_finding_track_resolvable_advisories():
    from app.models import Advisory, Finding
    from app.remediation.verify import _trivy_hits

    f = Finding(scan_id="s", asset_id="a", fingerprint="x", tool="trivy", rule_id="dependency:flask", title="t",
                severity="high", category="dependency", file="requirements.txt", package="flask",
                installed_version="0.12.2", fixed_version="1.0",
                advisories=[Advisory(id="CVE-A", severity="high", fixed_version="0.12.3"),
                            Advisory(id="CVE-B", severity="high", fixed_version="2.2.5")])
    def report(*ids):
        return {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
            {"VulnerabilityID": i, "PkgName": "flask", "Severity": "HIGH", "FixedVersion": "x"} for i in ids]}]}
    assert _trivy_hits(report("CVE-A", "CVE-B"), f)[0] is True
    # 1.0 only claims CVE-A; CVE-B remaining doesn't make the bump "still present"
    present, remaining = _trivy_hits(report("CVE-B"), f)
    assert present is False and len(remaining) == 1
