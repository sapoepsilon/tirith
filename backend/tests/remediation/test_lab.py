from pathlib import Path

from app.remediation import lab
from app.remediation.sh import Result


def res(out: str = "", err: str = "", rc: int = 0) -> Result:
    return Result(rc=rc, out=out, err=err)



def test_image_tag_hashes_content_not_just_names(mini_repo: Path):
    clean = lab.image_tag(mini_repo, "t")
    p = mini_repo / "introduction" / "views.py"
    p.write_text(p.read_text() + "# one\n")
    t1 = lab.image_tag(mini_repo, "t")
    p.write_text(p.read_text() + "# two\n")
    t2 = lab.image_tag(mini_repo, "t")
    (mini_repo / "new.py").write_text("a = 1\n")
    t3 = lab.image_tag(mini_repo, "t")
    (mini_repo / "new.py").write_text("a = 2\n")
    t4 = lab.image_tag(mini_repo, "t")
    assert len({clean, t1, t2, t3, t4}) == 5


def test_egress_check_reports_reachable_gateway(monkeypatch):
    def network(*_a, **_kw):
        return res(out="172.30.0.1\n")

    def exec_(*_a, **_kw):
        return res(out="internet 1.1.1.1:443 OSError\n"
                       "gateway 172.30.0.1:22 refused\ngateway 172.30.0.1:8000 open\n")

    monkeypatch.setattr(lab, "docker", network)
    monkeypatch.setattr(lab, "run", exec_)
    h = lab.LabHandle(url="http://c:8000/", network="tirith-lab", container="c", image="i", port=8000)
    e = lab.egress_check(h)
    assert "EGRESS-BLOCKED" in e.content and "GATEWAY-REACHABLE" in e.content
    assert "iptables -I INPUT -i tirith-lab0 -j DROP" in e.content
    assert "iptables -I DOCKER-USER -i tirith-lab0 ! -o tirith-lab0 -j DROP" in e.content


def test_egress_check_blocked_gateway(monkeypatch):
    monkeypatch.setattr(lab, "docker", lambda *a, **k: res(out="172.30.0.1"))
    monkeypatch.setattr(lab, "run", lambda *a, **k: res(out="internet 1.1.1.1:443 timeout\ngateway 172.30.0.1:22 timeout\n"))
    e = lab.egress_check(lab.LabHandle(url="u", network="n", container="c", image="i", port=1))
    assert "GATEWAY-BLOCKED" in e.content and "iptables" not in e.content


def test_peer_probe_uses_fixed_curl_image(monkeypatch):
    calls = []
    monkeypatch.setattr(lab, "docker", lambda args, **kw: calls.append(args) or res(out="200"))
    lab.peer_probe(lab.LabHandle(url="http://127.0.0.1:18000/", network="tirith-lab", container="c",
                                 image="tirith-lab/target:x", port=18000))
    a = calls[0]
    assert lab.CURL_IMAGE in a and "tirith-lab/target:x" not in a
    assert a[a.index("--network") + 1] == "host"  # the copy binds the guest loopback now
    assert a[a.index("--cap-drop") + 1] == "ALL" and "--memory" in a and "--pids-limit" in a


def test_offline_build_failure_is_lab_unavailable(monkeypatch, tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    calls = []

    def fake(args, *, timeout=300, cwd=None, **kw):
        calls.append(args)
        return res(err="network unreachable", rc=1) if args[0] in ("build", "image") else res()

    monkeypatch.setattr(lab, "docker", fake)
    import pytest
    with pytest.raises(lab.LabUnavailable, match="lab boot unavailable"):
        lab.build(tmp_path, "x", network=False)
    b = next(c for c in calls if c[0] == "build")
    assert b[b.index("--network") + 1] == "none"
