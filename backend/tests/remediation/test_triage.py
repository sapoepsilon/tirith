from app.models import Finding
from app.remediation import triage

from .conftest import django_finding, gitleaks_findings, semgrep_findings, trivy_findings


def _steps():
    out = []
    return out, out.append


def test_dependency_confirmed_and_reachable(store, asset, mini_repo):
    (mini_repo / "pygoat" / "settings.py").write_text("import django\nINSTALLED_APPS = []\n")
    f = django_finding(store, asset)
    v = triage.validate_finding(f, mini_repo, asset)
    assert v.result == "confirmed" and v.confidence >= 0.9
    text = "\n".join(e.content for e in v.evidence)
    assert "AFFECTED" in text and "import django" in text and "requirements.txt:2 pins Django at 4.2" in text
    stored = store.get_finding(f.id)
    assert stored.status == "validated" and stored.validation.id == v.id
    types = [e.type for e in store.recent_events(50)]
    assert types[0] == "validation.started" and "validation.step" in types and types[-1] == "validation.result"


def test_dependency_not_affected_when_manifest_already_fixed(store, asset, mini_repo):
    (mini_repo / "requirements.txt").write_text("Django==4.2.30\n")
    f = django_finding(store, asset)
    v = triage.validate_finding(f, mini_repo, asset)
    assert v.result == "not_reproduced"
    assert store.get_finding(f.id).status == "not_reproduced"


def test_dependency_installed_but_not_imported(store, asset, mini_repo):
    f = next(x for x in trivy_findings(asset) if x.package == "requests" and x.file == "requirements.txt")
    store.upsert_finding(f)
    v = triage.validate_finding(f, mini_repo, asset)
    assert v.result == "confirmed" and v.confidence <= 0.6


def test_secret_heuristics_never_leak_value(store, asset, mini_repo):
    real = "Zq8r" + "T2vLp9XwK4mN7bQ1sY6dH3jF0aC5eG"  # synthetic, high entropy
    (mini_repo / "pygoat" / "conf.py").write_text(f'STRIPE_KEY = "{real}"\n')
    (mini_repo / "tests").mkdir()
    (mini_repo / "tests" / "fixture_keys.py").write_text('API_KEY = "sk_test_' + "example0000000000" + '"\n')
    f_real = Finding(scan_id="s", asset_id=asset.id, fingerprint="a", tool="gitleaks", rule_id="generic-api-key",
                     title="secret", severity="high", category="secret", file="pygoat/conf.py", line=1, snippet="[REDACTED]")
    f_test = f_real.model_copy(update={"fingerprint": "b", "file": "tests/fixture_keys.py", "id": "fnd_test2"})
    for f in (f_real, f_test):
        store.upsert_finding(f)
    v1 = triage.validate_finding(f_real, mini_repo, asset)
    v2 = triage.validate_finding(f_test, mini_repo, asset)
    assert v1.result == "confirmed" and "likely-real" in v1.evidence[-1].content
    assert v2.result == "not_reproduced" and "likely-test" in v2.evidence[-1].content
    blob = " ".join(e.content for e in v1.evidence + v2.evidence) + " ".join(e.model_dump_json() for e in store.recent_events(100))
    assert real not in blob and real[:8] not in blob and "example0000000000" not in blob


def test_secret_not_in_tree(store, asset, mini_repo):
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="c", tool="gitleaks", rule_id="generic-api-key",
                title="secret", severity="high", category="secret", file="gone.py", line=3)
    store.upsert_finding(f)
    v = triage.validate_finding(f, mini_repo, asset)
    assert "not in the current tree" in v.evidence[1].content


def test_gitleaks_fixture_paths_normalize(store, asset):
    fs = gitleaks_findings(asset)
    assert fs and all(f.category == "secret" and f.file.startswith("dockerized_labs/") for f in fs)


def test_sast_reachable_django_view(store, asset, mini_repo):
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="d", tool="semgrep",
                rule_id="python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute",
                title="SQLi", severity="high", category="sast", file="introduction/views.py", line=8, cwe="CWE-89")
    store.upsert_finding(f)
    v = triage.validate_finding(f, mini_repo, asset)
    assert v.result == "confirmed" and v.confidence == 0.8
    reach = v.evidence[0].content
    assert "sql_lab" in reach and "pygoat/urls.py:5" in reach
    assert any(e.type == "ai.thinking" for e in store.recent_events(50))


def test_sast_unrouted_function_lowers_confidence(store, asset, mini_repo):
    f = Finding(scan_id="s", asset_id=asset.id, fingerprint="e", tool="semgrep", rule_id="x.sqli", title="SQLi",
                severity="high", category="sast", file="introduction/views.py", line=15, cwe="CWE-89")
    store.upsert_finding(f)
    v = triage.validate_finding(f, mini_repo, asset)
    assert "no URL route or caller references orphan" in v.evidence[0].content
    assert v.confidence < 0.8


def test_flask_route_decorator(tmp_path):
    lines = ["from flask import Flask", "app = Flask(__name__)", "", "@app.route('/run', methods=['POST'])",
             "def run():", "    cmd = request.form['c']", "    os.system(cmd)"]
    (tmp_path / "app.py").write_text("\n".join(lines))
    f = Finding(scan_id="s", asset_id="a", fingerprint="f", tool="semgrep", rule_id="r", title="t", severity="high",
                category="sast", file="app.py", line=7)
    ok, notes = triage.route_reachability(tmp_path, f, lines)
    assert ok is True and any("@app.route('/run'" in n for n in notes)


def test_semgrep_fixture_findings_have_locations(store, asset):
    fs = semgrep_findings(asset)
    assert len(fs) > 50 and all(f.file for f in fs)


# --------------------------------------------------------------------------- grouped dependency findings
def test_grouped_dependency_confirmed_lists_every_advisory(store, asset, mini_repo):
    from app.remediation import triage

    f = next(x for x in trivy_findings(asset, group=True) if x.package == "requests")
    assert len(f.advisories) >= 2 and f.fixed_version
    f = f.model_copy(update={"file": "requirements.txt"})
    store.upsert_finding(f)
    v = triage.validate_finding(f, mini_repo, asset)
    assert v.result == "confirmed"
    rng = next(e for e in v.evidence if e.label == "affected range").content
    assert all(a.id in rng for a in f.advisories)
    assert f.fixed_version in next(e for e in v.evidence if e.label == "verdict").content
    stored = store.get_finding(f.id)
    assert stored.status == "validated" and stored.priority > 0
