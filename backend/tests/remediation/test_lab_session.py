"""lab.session(): throwaway lab test user + signed-in cookies, docker fully mocked."""

import json

import pytest

from app.remediation import lab
from app.remediation.sh import Result

MARK = lab._SESSION_MARK


@pytest.fixture(autouse=True)
def clean_cache():
    lab._sessions.clear()
    lab._creds.clear()
    yield
    lab._sessions.clear()
    lab._creds.clear()


def handle(django="pygoat.settings"):
    return lab.LabHandle(url="http://c:8000/", network="tirith-lab", container="c", image="i", port=8000,
                         django_settings=django)


class FakeExec:
    """Stands in for sh.run(["docker", "exec", "-i", ...], input=script)."""

    def __init__(self, form_cookies=None, direct_cookies=None, user_ok=True):
        self.calls: list[tuple[list[str], str]] = []
        self.form_cookies = form_cookies
        self.direct_cookies = direct_cookies
        self.user_ok = user_ok

    def __call__(self, argv, *, input=None, timeout=300, secrets=(), **kw):
        self.calls.append((argv, input or ""))
        if "TIRITH_LAB_USER_OK" in (input or ""):
            return Result(0, "TIRITH_LAB_USER_OK\n" if self.user_ok else "", "" if self.user_ok else "boom")
        if "csrfmiddlewaretoken" in (input or ""):
            if self.form_cookies:
                return Result(0, MARK + json.dumps({"via": "/login/", "cookies": self.form_cookies}) + "\n", "")
            return Result(0, "", "")
        if "SessionStore" in (input or ""):
            if self.direct_cookies:
                return Result(0, MARK + json.dumps({"via": "session-store", "cookies": self.direct_cookies}) + "\n", "")
            return Result(1, "", "err")
        return Result(1, "", "unexpected")

    def password(self) -> str:
        # PW = '<value>' is the prelude line of every script
        line = next(ln for ln in self.calls[0][1].splitlines() if ln.startswith("PW = "))
        return eval(line.split(" = ", 1)[1])  # noqa: S307 - repr() of a str we generated


def test_session_creates_user_logs_in_via_form_and_caches(monkeypatch):
    fx = FakeExec(form_cookies={"sessionid": "s3ss", "csrftoken": "csrf"})
    monkeypatch.setattr(lab, "run", fx)
    monkeypatch.setattr(lab, "docker", lambda *a, **k: pytest.fail("no docker() call expected for a Django handle"))
    h = handle()
    assert lab.session(h) == {"sessionid": "s3ss", "csrftoken": "csrf"}
    assert len(fx.calls) == 2  # create user, form login
    pw = fx.password()
    assert len(pw) >= 24
    for argv, script in fx.calls:
        assert argv[:4] == ["docker", "exec", "-i", "c"]
        assert pw not in " ".join(argv)  # credentials travel on stdin only
        assert pw in script
    # cached per handle: no further docker exec
    assert lab.session(h) == {"sessionid": "s3ss", "csrftoken": "csrf"}
    assert len(fx.calls) == 2
    # evidence names the cookies, never the password or cookie values
    note = h.evidence[-1].content
    assert "sessionid" in note and "s3ss" not in note and pw not in note
    assert pw not in repr(lab._creds["c"])


def test_refresh_logs_in_again_with_same_credentials(monkeypatch):
    fx = FakeExec(form_cookies={"sessionid": "a"})
    monkeypatch.setattr(lab, "run", fx)
    h = handle()
    lab.session(h)
    pw = fx.password()
    lab.session(h, refresh=True)
    assert len(fx.calls) == 4
    assert all(pw in script for _, script in fx.calls)


def test_falls_back_to_session_store_when_form_login_fails(monkeypatch):
    fx = FakeExec(form_cookies=None, direct_cookies={"sessionid": "direct"})
    monkeypatch.setattr(lab, "run", fx)
    assert lab.session(handle()) == {"sessionid": "direct"}
    assert len(fx.calls) == 3


def test_user_creation_failure_returns_empty_and_does_not_cache(monkeypatch):
    fx = FakeExec(user_ok=False)
    monkeypatch.setattr(lab, "run", fx)
    h = handle()
    assert lab.session(h) == {}
    assert "c" not in lab._sessions


def test_non_django_app_gets_no_session(monkeypatch):
    monkeypatch.setattr(lab, "run", lambda *a, **k: pytest.fail("no exec for a non-Django app"))
    monkeypatch.setattr(lab, "docker", lambda args, timeout=300, cwd=None: Result(1, "", ""))  # no manage.py
    assert lab.session(handle(django=None)) == {}


def test_non_handle_returns_empty():
    assert lab.session("http://x/") == {}


def test_stop_drops_cached_session_and_credentials(monkeypatch):
    monkeypatch.setattr(lab, "run", FakeExec(form_cookies={"sessionid": "a"}))
    monkeypatch.setattr(lab, "docker", lambda *a, **k: Result(0, "", ""))
    h = handle()
    lab.session(h)
    assert "c" in lab._sessions and "c" in lab._creds
    h.stop()
    assert "c" not in lab._sessions and "c" not in lab._creds


def test_parse_session_rejects_header_injection():
    bad = MARK + json.dumps({"via": "x", "cookies": {"sessionid": "a;b", "x y": "1", "ok": "v\r\nX: y"}})
    assert lab._parse_session(bad) is None
    good = MARK + json.dumps({"via": "x", "cookies": {"sessionid": "abc", "evil": "a;b"}})
    assert lab._parse_session("noise\n" + good) == ("x", {"sessionid": "abc"})


def test_install_wires_session_hook():
    from fastapi import FastAPI

    from app.remediation import install
    from app.scanners import tools

    install(FastAPI())
    assert tools.get_lab_session is lab.session


def test_seed_commands_replays_only_shipped_seed_commands(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        'command: sh -c "python manage.py migrate --noinput && python manage.py seed_scoring && '
        'python manage.py populate_labs && python manage.py startuplabs && python manage.py populate_missing '
        '&& python manage.py populate_labs; rm -rf /"\n')
    for app, cmd in (("scoring", "seed_scoring"), ("challenge", "populate_labs"), ("challenge", "startuplabs")):
        d = tmp_path / app / "management" / "commands"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{cmd}.py").write_text("")
    assert lab.seed_commands(tmp_path) == ["seed_scoring", "populate_labs"]


def test_boot_script_runs_migrate_then_seeds_then_app():
    prof = lab.Profile(argv=["gunicorn"], django_settings="pygoat.settings", seed_commands=["seed_scoring", "bad;rm"])
    s = lab._boot_script(prof)
    assert s.index("migrate") < s.index("manage.py seed_scoring") < s.index('exec "$@"')
    assert "bad;rm" not in s
    assert lab._boot_script(lab.Profile(argv=["node"])) == 'exec "$@"'


def test_crawl_seeds_lists_safe_parameter_free_routes(monkeypatch):
    routes = ["", "xss", "sql", "^admin/", "^admin/login/$", "logout/", "accounts/password/change/",
              "challenge/start-lab/<str:name>/", "challenge/custom-labs/delete/<int:id>/", "scoring/dashboard/",
              "static/x", "^api/v1/items\\Z", "a(b)"]
    calls = []

    def fake_run(argv, *, input=None, timeout=300, **kw):
        calls.append(argv)
        return Result(0, "warn\n" + MARK + json.dumps(routes) + "\n", "")
    monkeypatch.setattr(lab, "run", fake_run)
    seeds = lab.crawl_seeds(handle())
    assert seeds == ["/", "/xss", "/sql", "/scoring/dashboard/", "/api/v1/items"]
    assert calls[0][:4] == ["docker", "exec", "-i", "c"]


def test_crawl_seeds_non_django_or_garbage(monkeypatch):
    monkeypatch.setattr(lab, "docker", lambda *a, **k: Result(1, "", ""))
    assert lab.crawl_seeds(handle(django=None)) == []
    monkeypatch.setattr(lab, "run", lambda *a, **k: Result(1, "Traceback", ""))
    assert lab.crawl_seeds(handle()) == []
    assert lab.crawl_seeds("not a handle") == []


def test_install_wires_seed_hook():
    from fastapi import FastAPI

    from app.remediation import install
    from app.scanners import tools

    install(FastAPI())
    assert tools.get_lab_seeds is lab.crawl_seeds
