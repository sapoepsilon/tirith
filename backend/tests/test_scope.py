from pathlib import Path

from app.config import BACKEND_DIR, TIRITH_ROOT
from app.scope import Scope, check_asset, enforce, load_scope


def make_scope(tmp_path: Path) -> Scope:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "sub").mkdir()
    return Scope(
        github_repos=["sapoepsilon/tirith-demo-target", "sapoepsilon/x"],
        local_paths=[allowed.resolve()],
        url_hosts=["localhost:5000", "127.0.0.1:8000", "demo.lab.internal:80", "secure.lab.internal:443"],
    )


def test_default_scope_file():
    s = load_scope(BACKEND_DIR / "scope.yaml")
    assert s.github_repos == ["sapoepsilon/tirith-demo-target"]
    assert s.local_paths == [TIRITH_ROOT.resolve()]
    assert all(":" in h for h in s.url_hosts)
    assert check_asset("github_repo", "sapoepsilon/tirith-demo-target", s)[0]
    assert not check_asset("github_repo", "sapoepsilon/other-repo", s)[0]  # no owner-wide glob
    assert not check_asset("github_repo", "someone/else", s)[0]
    assert check_asset("local_path", str(TIRITH_ROOT / "demo-shop"), s)[0]
    assert not check_asset("local_path", "/etc", s)[0]


def test_github(tmp_path):
    s = make_scope(tmp_path)
    assert check_asset("github_repo", "sapoepsilon/tirith-demo-target", s)[0]
    assert check_asset("github_repo", "SapoEpsilon/X", s)[0]  # GitHub names are case-insensitive
    for bad in ("torvalds/linux", "sapoepsilon", "sapoepsilon/../x", "x/sapoepsilon/y", "",
                "sapoepsilon/tirith-demo-shop", "sapoepsilon/*", "sapoepsilon/x?"):
        assert not check_asset("github_repo", bad, s)[0], bad


def test_local_paths(tmp_path):
    s = make_scope(tmp_path)
    allowed = tmp_path / "allowed"
    assert check_asset("local_path", str(allowed), s)[0]
    assert check_asset("local_path", str(allowed / "sub"), s)[0]
    assert not check_asset("local_path", str(allowed / ".." ), s)[0]  # traversal
    assert not check_asset("local_path", str(tmp_path / "allowed-evil"), s)[0]  # prefix trick
    assert not check_asset("local_path", "relative/path", s)[0]
    link = allowed / "escape"
    link.symlink_to(tmp_path)
    assert not check_asset("local_path", str(link), s)[0]  # symlink escape


def test_urls(tmp_path):
    s = make_scope(tmp_path)
    assert check_asset("url", "http://localhost:5000", s)[0]
    assert check_asset("url", "http://LOCALHOST:5000/path?q=1", s)[0]
    assert check_asset("url", "http://demo.lab.internal/x", s)[0]  # default port 80
    assert check_asset("url", "https://secure.lab.internal/", s)[0]  # default port 443
    assert check_asset("url", "http://127.0.0.1:8000", s)[0]
    for bad in ("https://example.com", "http://localhost.evil.com", "ftp://localhost", "file:///etc/passwd",
                "http://evil.com@example.org", "javascript:alert(1)",
                "http://localhost", "http://localhost:5001", "http://127.0.0.1:2375", "https://demo.lab.internal/",
                "http://x.demo.lab.internal/", "http://localhost:99999", "http://localhost:abc"):
        assert not check_asset("url", bad, s)[0], bad
    assert not check_asset("bogus", "x", s)[0]


def test_url_alias(tmp_path):
    """A guest address published under a scoped host port passes, but only while the scoped entry exists."""
    s = make_scope(tmp_path)
    s.url_hosts.append("10.0.0.5:9000")
    s.url_aliases = {"10.0.0.5:9000": ["10.0.0.9:9000"]}
    assert check_asset("url", "http://10.0.0.9:9000/drupal/", s)[0]
    assert check_asset("url", "http://10.0.0.5:9000/", s)[0]
    assert not check_asset("url", "http://10.0.0.9:9001/", s)[0]  # port is not part of the alias
    assert not check_asset("url", "http://10.0.0.8:9000/", s)[0]
    s.url_hosts.remove("10.0.0.5:9000")  # dropping the entry retires its aliases too
    assert not check_asset("url", "http://10.0.0.9:9000/", s)[0]


def test_enforce_audits_and_emits(tmp_store, tmp_path):
    s = make_scope(tmp_path)
    ok, _ = enforce("asset.create", "github_repo", "torvalds/linux", scope=s)
    assert not ok
    a = tmp_store.list_audit(5)[0]
    assert a.action == "asset.create" and a.allowed is False and a.target == "github_repo:torvalds/linux"
    ev = tmp_store.recent_events(5)[-1]
    assert ev.type == "policy.denied" and ev.level == "warn"
    ok, _ = enforce("asset.create", "github_repo", "sapoepsilon/x", scope=s)
    assert ok and tmp_store.list_audit(1)[0].allowed is True
