from app import focus, posture
from app.models import Finding, Validation


def mk(sev, status="open", i=[0]):
    i[0] += 1
    return Finding(scan_id="s", asset_id="a", fingerprint=f"{i[0]:032d}", tool="semgrep", rule_id="r",
                   title="t", severity=sev, category="sast", status=status)


def test_clean_is_100_A():
    p = posture.compute([], "a")
    assert (p.score, p.grade, p.open, p.fixed) == (100, "A", 0, 0)


def test_info_does_not_hurt():
    assert posture.compute([mk("info")] * 5).score == 100


def test_monotonic_and_bounded():
    prev = 101
    fs = []
    for sev in ["low", "medium", "high", "critical"] * 10:
        fs.append(mk(sev))
        s = posture.compute(fs).score
        assert 0 <= s <= prev  # integer rounding may plateau, never increases
        prev = s
    assert prev < 30


def test_severity_weighting():
    assert posture.compute([mk("critical")]).score < posture.compute([mk("high")]).score < posture.compute([mk("medium")]).score < posture.compute([mk("low")]).score


def test_fixed_and_not_reproduced_are_closed():
    fs = [mk("critical", "fixed"), mk("high", "not_reproduced"), mk("low")]
    p = posture.compute(fs)
    assert p.open == 1 and p.fixed == 1 and p.counts["critical"] == 0
    assert p.score == posture.compute([mk("low")]).score


def test_fixing_improves_score():
    fs = [mk("high") for _ in range(5)]
    before = posture.compute(fs).score
    fs[0] = fs[0].model_copy(update={"status": "fixed"})
    assert posture.compute(fs).score > before


def test_critical_caps_grade():
    p = posture.compute([mk("critical")])
    assert p.score >= 80 and p.grade == "C"


def test_lab_critical_does_not_cap_grade_and_weighs_less():
    lab = mk("critical").model_copy(update={"component": "lab:dockerized_labs/x", "tags": ["lab-subapp"]})
    p = posture.compute([lab])
    assert p.grade in ("A", "B") and p.lab_open == 1 and p.main_counts["critical"] == 0
    assert p.score > posture.compute([mk("critical")]).score


def test_fix_earns_progress_credit():
    """Fixing beats dismissing: same open set, but fixed findings add credit."""
    open_ = [mk("high") for _ in range(6)]
    fixed = [mk("high", "fixed") for _ in range(4)]
    dismissed = [mk("high", "not_reproduced") for _ in range(4)]
    with_fixes = posture.compute(open_ + fixed)
    assert with_fixes.score > posture.compute(open_ + dismissed).score
    assert with_fixes.risk_fixed > 0


def test_each_top_fix_moves_score_visibly():
    fs = [mk("critical") for _ in range(3)] + [mk("high") for _ in range(10)] + [mk("medium") for _ in range(20)]
    s0 = posture.compute(fs).score
    fs[0] = fs[0].model_copy(update={"status": "fixed"})
    s1 = posture.compute(fs).score
    assert s1 - s0 >= 2


def test_grade_bands():
    assert posture.grade_for(95, {}) == "A"
    assert posture.grade_for(85, {}) == "B"
    assert posture.grade_for(72, {}) == "C"
    assert posture.grade_for(61, {}) == "D"
    assert posture.grade_for(10, {}) == "F"


def test_record_history_and_event(tmp_store):
    for f in [mk("high"), mk("low")]:
        tmp_store.upsert_finding(f)
    p = posture.record("a", scan_id="s")
    assert p.history and p.history[-1]["score"] == p.score
    assert tmp_store.recent_events(1)[-1].type == "posture.updated"
    assert posture.get_posture(None).history  # global aggregate recorded too


def test_priority_orders_by_severity_confidence_reachability_validation():
    base = dict(scan_id="s", asset_id="a", tool="semgrep", rule_id="r", title="t", category="sast", confidence=0.7)
    crit_main = Finding(fingerprint="1", severity="critical", **base)
    crit_lab = Finding(fingerprint="2", severity="critical", component="lab:dockerized_labs/x", tags=["lab-subapp"], **base)
    high_main = Finding(fingerprint="3", severity="high", **base)
    high_confirmed = high_main.model_copy(update={"validation": Validation(finding_id="x", check="c", result="confirmed", confidence=0.95)})
    high_dismissed = high_main.model_copy(update={"validation": Validation(finding_id="x", check="c", result="not_reproduced", confidence=0.9)})
    p = focus.priority
    assert p(crit_main) > p(high_main) > p(crit_lab)
    assert p(high_confirmed) > p(crit_main)  # confirmed evidence outranks an unvalidated guess
    assert p(high_dismissed) < p(crit_lab)
    assert p(high_main.model_copy(update={"status": "fixed"})) == 0
    assert 0 < p(crit_main) <= 100


def test_store_sorts_findings_by_priority(tmp_store):
    lab = mk("critical").model_copy(update={"component": "lab:dockerized_labs/x", "tags": ["lab-subapp"]})
    main_high, main_low, done = mk("high"), mk("low"), mk("critical", "fixed")
    for f in (main_low, lab, done, main_high):
        tmp_store.upsert_finding(f)
    got = [f.fingerprint for f in tmp_store.list_findings(asset_id="a")]
    assert got == [main_high.fingerprint, lab.fingerprint, main_low.fingerprint, done.fingerprint]
    sev = [f.severity for f in tmp_store.list_findings(asset_id="a", sort="severity")]
    assert sev[:2] == ["critical", "critical"]
    assert [f.fingerprint for f in tmp_store.list_findings(asset_id="a", component="lab")] == [lab.fingerprint]
