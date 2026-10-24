"""The HTML report must never claim a fix that did not happen, and must never vanish when data is thin."""

from __future__ import annotations

import json

from app.analyst import html_report
from app.models import Finding


def _run(issues):
    return {"id": "arn_test", "goal": "assess", "status": "done", "error": None,
            "started_at": "2026-01-01T00:00:00Z", "steps": [],
            "report": {"summary": "s", "issues": issues}}


def _finding(status="open", **kw):
    base = dict(scan_id="scn_1", asset_id="ast_1", fingerprint="fp", tool="zap", rule_id="r",
                title="t", severity="high", category="dast", status=status, confidence=0.9)
    base.update(kw)
    return Finding(**base)


def _issue(**kw):
    base = {"title": "Unauthenticated endpoint", "severity": "high", "where": "h:1",
            "evidence": "200 without auth", "reproduce": ["curl it"], "impact": "anyone can reach it",
            "fix": "require a token"}
    base.update(kw)
    return base


def test_claiming_applied_does_not_beat_a_live_open_finding():
    f = _finding(status="open")
    doc = html_report.render(_run([_issue(finding_id=f.id, fix_status="applied")]), [f], "as-fixed")
    assert "Proposed, not applied" in doc
    assert "class=\"issue sev-high proposed\"" in doc


def test_a_fixed_finding_makes_the_fix_count_as_applied():
    f = _finding(status="fixed")
    doc = html_report.render(_run([_issue(finding_id=f.id)]), [f], "as-fixed")
    assert ">Fixed<" in doc
    assert "1 fixed, 0 still open." in doc


def test_as_found_never_shows_fix_state():
    doc = html_report.render(_run([_issue(fix_status="applied")]), [], "as-found")
    assert ">Fixed<" not in doc
    assert ">Open<" in doc


def test_thin_run_still_renders_a_whole_document():
    doc = html_report.render({"id": "arn_x", "status": "budget", "error": "step budget", "steps": []}, [], "as-found")
    assert doc.startswith("<!doctype html>")
    assert "No reproduced issues" in doc
    assert "stopped early" in doc


def test_renderer_strips_the_usual_ai_tells():
    out = html_report._plain("We actually delve into a robust, comprehensive landscape — it showcases value.")
    for bad in ("actually", "delve", "robust", "comprehensive", "landscape", "showcases", "—"):
        assert bad not in out.lower()
    assert "curly" not in out


def test_render_run_writes_both_files(tmp_path, monkeypatch):
    ev = tmp_path / "evidence"
    (ev / "analyst").mkdir(parents=True)
    (ev / "shots").mkdir()
    monkeypatch.setattr(html_report.config, "EVIDENCE_DIR", ev)
    (ev / "analyst" / "arn_abc123.json").write_text(json.dumps(_run([_issue()])))

    for v in ("as-found", "as-fixed"):
        p = html_report.render_run("arn_abc123", v)
        assert p.is_file() and p.name == f"{v}.html"
        assert "Unauthenticated endpoint" in p.read_text()

def test_gallery_only_shows_this_runs_screenshots(tmp_path, monkeypatch):
    ev = tmp_path / "evidence"
    (ev / "shots").mkdir(parents=True)
    for n in ("mine-a.png", "other-run.png"):
        (ev / "shots" / n).write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 20)
    monkeypatch.setattr(html_report.config, "EVIDENCE_DIR", ev)
    run = {"id": "arn_x", "status": "done", "steps": [
        {"n": 1, "tool": "evidence", "ok": True, "observation": '{"path": "/ev/mine-a.png", "bytes": 31}'}]}
    doc = html_report.render(run, [], "as-found")
    assert "mine-a.png" in doc
    assert "other-run.png" not in doc


def test_gallery_does_not_defer_images(tmp_path, monkeypatch):
    ev = tmp_path / "evidence"
    (ev / "shots").mkdir(parents=True)
    (ev / "shots" / "s1.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 20)
    monkeypatch.setattr(html_report.config, "EVIDENCE_DIR", ev)
    run = {"id": "arn_x", "status": "done", "steps": [
        {"n": 1, "tool": "evidence", "ok": True, "observation": "saved /ev/s1.png"}]}
    doc = html_report.render(run, [], "as-found")
    assert 'src="shots/s1.png"' in doc
    assert "loading=\"lazy\"" not in doc
