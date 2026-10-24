"""Django lab boot (host mode): the container name and 127.0.0.1 must pass ALLOWED_HOSTS.

The container name is what a ZAP peer still sends as Host (the app stays reachable by name on the
lab bridge), and 127.0.0.1 is what the in-guest client sends, so both must be allowed."""

import json
import sys
from pathlib import Path

from app.remediation import lab
from app.remediation.sh import Result

PYGOAT_SETTINGS = (
    "import os\n"
    'ALLOWED_HOSTS = ["pygoat.herokuapp.com", "0.0.0.0", "127.0.0.1", "localhost", "lvh.me", ".lvh.me", "web"]\n'
    'CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8000", "http://lvh.me"]\n'
    'LAB_DOMAIN = os.environ.get("LAB_DOMAIN", "localhost")\n'
)


def _django_src(tmp_path: Path, settings: str = PYGOAT_SETTINGS) -> Path:
    src = tmp_path / "src"
    (src / "pygoat").mkdir(parents=True)
    (src / "pygoat" / "__init__.py").write_text("")
    (src / "pygoat" / "settings.py").write_text(settings)
    (src / "manage.py").write_text("import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pygoat.settings')\n")
    return src


def _fake_docker(calls: list, overlays: dict, image_env: list[str] | None = None):
    cfg = {"ExposedPorts": {"8000/tcp": {}}, "Cmd": ["gunicorn", "--bind", "0.0.0.0:8000", "pygoat.wsgi"],
           "Env": image_env or ["PATH=/usr/local/bin:/usr/bin"]}

    def fake(args, *, timeout=300, cwd=None, **kw):
        calls.append(list(args))
        if args[:2] == ["image", "inspect"]:
            return Result(rc=0, out=json.dumps(cfg), err="")
        if args[0] == "cp":  # read the overlay while the temp dir still exists
            overlays[args[2]] = (Path(args[1]) / "tirith_lab_settings.py").read_text()
        return Result(rc=0, out="", err="")

    return fake


def _envs(create: list[str]) -> dict[str, str]:
    return dict(create[i + 1].split("=", 1) for i, a in enumerate(create) if a == "-e")


def _load_overlay(tmp_path: Path, src: Path, overlay: str, monkeypatch) -> dict:
    """Execute the generated overlay against the target's real settings module (no Django needed)."""
    monkeypatch.syspath_prepend(str(src))
    for m in [m for m in sys.modules if m == "pygoat" or m.startswith("pygoat.")]:
        monkeypatch.delitem(sys.modules, m)
    ns: dict = {}
    exec(compile(overlay, "tirith_lab_settings.py", "exec"), ns)
    return ns


def test_start_django_overlay_accepts_lab_host_and_loopback(tmp_path, monkeypatch):
    src = _django_src(tmp_path)
    calls, overlays = [], {}
    monkeypatch.setattr(lab, "docker", _fake_docker(calls, overlays, ["PYTHONPATH=/app/lib"]))
    monkeypatch.setattr(lab, "host_mode", lambda: True)
    h, prof = lab.start("tirith-lab/pygoat:abc", src, "asset:a1", "tirith-lab")

    create = next(c for c in calls if c[0] == "create")
    name = h.container
    assert create[create.index("--hostname") + 1] == name  # container's own hostname == the name ZAP uses
    env = _envs(create)
    assert env["DJANGO_SETTINGS_MODULE"] == "tirith_lab_settings"
    assert env["PYTHONPATH"] == "/tirith_lab:/app/lib"  # image's PYTHONPATH kept
    assert h.url.startswith("http://127.0.0.1:") and h.django_settings == "pygoat.settings"
    assert create[create.index("--network") + 1] == "host"
    assert not (src / "tirith_lab_settings.py").exists()  # checkout untouched
    assert (src / "pygoat" / "settings.py").read_text() == PYGOAT_SETTINGS

    ns = _load_overlay(tmp_path, src, overlays[f"{name}:/tirith_lab"], monkeypatch)
    hosts = ns["ALLOWED_HOSTS"]
    assert name in hosts and "127.0.0.1" in hosts and "localhost" in hosts
    assert "pygoat.herokuapp.com" in hosts and ".lvh.me" in hosts  # original entries kept
    assert "*" not in hosts
    origin = f"http://{name}:{h.port}"
    assert origin in ns["CSRF_TRUSTED_ORIGINS"] and "http://lvh.me" in ns["CSRF_TRUSTED_ORIGINS"]
    assert ns["LAB_DOMAIN"] == "localhost"  # everything else from the app's settings


def test_lab_hostname_passes_django_host_validation():
    # Django rejects Host headers that don't match its host regex (e.g. underscores) even when allowed.
    import re
    host_re = re.compile(r"^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(:[0-9]+)?$")
    for label in ("asset:01HXYZ_abc", "PyGoat Repo!", "x" * 200):
        name = f"tirith-lab-{lab._slug(label)[:24]}-abcdef"
        assert host_re.match(f"{name}:8000") and len(name) <= 63


def test_overlay_when_settings_define_no_hosts(tmp_path, monkeypatch):
    src = _django_src(tmp_path, "DEBUG = False\n")
    ns = _load_overlay(tmp_path, src, lab.django_overlay("pygoat.settings", "tirith-lab-x-1", 8000), monkeypatch)
    assert ns["ALLOWED_HOSTS"] == lab.lab_hosts("tirith-lab-x-1")
    assert ns["CSRF_TRUSTED_ORIGINS"] == lab.lab_origins("tirith-lab-x-1", 8000)


def test_env_vars_the_settings_already_read_are_set(tmp_path, monkeypatch):
    src = _django_src(tmp_path, (
        "import os, environ\nenv = environ.Env()\n"
        'ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost").split(",")\n'
        'CSRF_TRUSTED_ORIGINS = env.list("CSRF_ORIGINS", default=[])\n'
    ))
    calls, overlays = [], {}
    monkeypatch.setattr(lab, "docker", _fake_docker(calls, overlays))
    monkeypatch.setattr(lab, "host_mode", lambda: True)
    h, _ = lab.start("tirith-lab/app:abc", src, "app", "tirith-lab")
    env = _envs(next(c for c in calls if c[0] == "create"))
    assert env["DJANGO_ALLOWED_HOSTS"].split(",") == lab.lab_hosts(h.container)
    assert env["CSRF_ORIGINS"].split(",") == lab.lab_origins(h.container, h.port)
    assert env["PYTHONPATH"] == "/tirith_lab"


def test_env_var_space_separated(tmp_path):
    src = _django_src(tmp_path, 'import os\nALLOWED_HOSTS = os.getenv("HOSTS", "").split()\n')
    env = lab.django_host_env(src, "pygoat.settings", "c1", 8000)
    assert env == {"HOSTS": " ".join(lab.lab_hosts("c1"))}


def test_hardcoded_settings_set_no_host_env(tmp_path):
    assert lab.django_host_env(_django_src(tmp_path), "pygoat.settings", "c1", 8000) == {}
    assert lab.django_host_env(tmp_path, "missing.settings", "c1", 8000) == {}


def test_non_django_image_gets_no_overlay(tmp_path, monkeypatch):
    src = tmp_path / "node"
    src.mkdir()
    calls, overlays = [], {}
    monkeypatch.setattr(lab, "docker", _fake_docker(calls, overlays))
    monkeypatch.setattr(lab, "host_mode", lambda: True)
    h, _ = lab.start("tirith-lab/node:abc", src, "node", "tirith-lab")
    env = _envs(next(c for c in calls if c[0] == "create"))
    assert "DJANGO_SETTINGS_MODULE" not in env and "PYTHONPATH" not in env
    assert not overlays and h.django_settings is None
