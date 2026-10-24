"""Authenticated ZAP baseline against the lab copy (the ZAP process is mocked)."""

import asyncio
import json
from pathlib import Path

import pytest

from app.models import Asset, Scan
from app.scanners import runner
from app.scanners import tools as tools_mod
from app.scanners.docker import RunResult

REPORT = {"site": [{"@name": "http://lab:8000", "alerts": [{
    "pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set", "riskcode": "2", "confidence": "3",
    "desc": "d", "solution": "s", "cweid": "693",
    "instances": [{"uri": "http://lab:8000/home", "method": "GET", "evidence": "Cookie: sessionid=SECRETSESSION"}],
}]}]}


def fake_process(seen: dict, report: dict | None = REPORT):
    async def run(args, *, cwd=None, **kw):
        cwd = Path(cwd)
        seen.update(args=args, cwd=cwd)
        if "-z" in args:
            prop = args[args.index("-z") + 1].split(" ", 1)[1]  # "-configfile <path>"
            seen["prop"] = Path(prop).read_text()
        if "--hook" in " ".join(args):
            seen["hook"] = next(Path(a.split("=", 1)[1]) for a in args if a.startswith("--hook="))
        if report is not None:
            (cwd / "zap.json").write_text(json.dumps(report))
        return RunResult(0, "", "")
    return run


def test_run_zap_with_session_and_cleans_up(monkeypatch, tmp_path):
    seen: dict = {}
    monkeypatch.setattr(tools_mod, "run_process", fake_process(seen))
    out = tmp_path / "scan" / "zap"
    res = asyncio.run(tools_mod.run_zap("http://lab:8000/", out, "n", network="tirith-lab",
                                        cookies={"sessionid": "SECRETSESSION", "csrftoken": "CSRFVAL"}))
    assert res.error is None and res.raw
    a = seen["args"]
    assert a[a.index("-z") + 1].startswith("-configfile ")
    assert "-a" not in a and "zap-full-scan.py" not in a  # passive baseline only
    assert seen["cwd"] == out  # the report lands in the outdir
    authdir = tmp_path / "scan" / "zap-auth"
    assert any(str(authdir) in a for a in a)
    assert "replacer.full_list(0).matchtype=REQ_HEADER" in seen["prop"]
    assert "replacer.full_list(0).replacement=sessionid=SECRETSESSION; csrftoken=CSRFVAL" in seen["prop"]
    assert "globalexcludeurl.url_list.url(0).regex=" in seen["prop"] and "logout" in seen["prop"]
    # the cookie values never appear in argv, and the props file is gone after the run
    assert "SECRETSESSION" not in " ".join(a)
    assert not (tmp_path / "scan" / "zap-auth").exists()
    # and are scrubbed from the saved report + parsed output
    assert "SECRETSESSION" not in (out / "zap.json").read_text()
    assert "SECRETSESSION" not in json.dumps(res.raw)


def test_run_zap_never_sends_session_off_the_lab_network(monkeypatch, tmp_path):
    seen: dict = {}
    monkeypatch.setattr(tools_mod, "run_process", fake_process(seen))
    asyncio.run(tools_mod.run_zap("http://lab:8000/", tmp_path / "zap", "n", network=None,
                                  cookies={"sessionid": "SECRETSESSION"}))
    assert "-z" not in seen["args"]
    assert seen["args"][:3] == ["zap-baseline.py", "-t", "http://lab:8000/"]  # no host alias


def test_run_zap_unauthenticated_unchanged(monkeypatch, tmp_path):
    seen: dict = {}
    monkeypatch.setattr(tools_mod, "run_process", fake_process(seen))
    asyncio.run(tools_mod.run_zap("http://lab:8000/", tmp_path / "zap", "n", network="tirith-lab"))
    assert seen["args"] == ["zap-baseline.py", "-t", "http://lab:8000/", "-J", "zap.json", "-I", "-m", "1"]


def test_props_file_removed_even_if_zap_crashes(monkeypatch, tmp_path):
    async def boom(*a, **k):
        raise RuntimeError("docker gone")
    monkeypatch.setattr(tools_mod, "run_process", boom)
    with pytest.raises(RuntimeError):
        asyncio.run(tools_mod.run_zap("http://lab:8000/", tmp_path / "zap", "n", network="tirith-lab",
                                      cookies={"sessionid": "x"}))
    assert not (tmp_path / "zap-auth").exists()


# --------------------------------------------------------------------------- runner wiring
@pytest.fixture()
def zap_env(tmp_store, tmp_path, monkeypatch):
    asset = Asset(kind="local_path", ref=str(tmp_path), name="lab-test")
    tmp_store.save_asset(asset)
    monkeypatch.setattr(runner, "enforce", lambda *a, **k: (True, "test"))
    lab_obj = tools_mod.LabTarget(url="http://lab:8000/", network="tirith-lab")
    monkeypatch.setattr(tools_mod, "get_lab_target", lambda a: lab_obj)
    got: dict = {}

    async def fake_zap(url, outdir, name, network=None, cookies=None, seeds=None):
        got.update(url=url, network=network, cookies=cookies, seeds=seeds)
        return tools_mod.ToolOutput(raw=REPORT)
    monkeypatch.setattr(tools_mod, "run_zap", fake_zap)

    def scan() -> Scan:
        s = Scan(asset_id=asset.id, tools=runner.plan_tools(asset, ["zap"]))
        tmp_store.save_scan(s)
        asyncio.run(runner.run_scan(s.id))
        return tmp_store.get_scan(s.id)
    return tmp_store, lab_obj, got, scan, monkeypatch


def test_runner_passes_lab_session_to_zap(zap_env):
    st, lab_obj, got, scan, mp = zap_env
    seen_lab = []
    mp.setattr(tools_mod, "get_lab_session", lambda lab: seen_lab.append(lab) or {"sessionid": "SECRETSESSION"})
    s = scan()
    assert s.tools["zap"] == "done" and sum(s.counts.values()) == 1
    assert seen_lab == [lab_obj]
    assert got == {"url": "http://lab:8000/", "network": "tirith-lab", "cookies": {"sessionid": "SECRETSESSION"},
                   "seeds": None}
    rows = json.dumps([e.model_dump() if hasattr(e, "model_dump") else e for e in st.list_audit(limit=50)])
    assert '"authenticated": true' in rows and "sessionid" in rows and "SECRETSESSION" not in rows


def test_runner_session_hook_failure_runs_unauthenticated(zap_env):
    st, lab_obj, got, scan, mp = zap_env

    def boom(lab):
        raise RuntimeError("exec failed")
    mp.setattr(tools_mod, "get_lab_session", boom)
    s = scan()
    assert s.tools["zap"] == "done"
    assert got["cookies"] is None


def test_runner_passes_lab_seeds(zap_env):
    st, lab_obj, got, scan, mp = zap_env
    mp.setattr(tools_mod, "get_lab_seeds", lambda lab: ["/xss", "/sql"])
    assert scan().tools["zap"] == "done"
    assert got["seeds"] == ["/xss", "/sql"]


def test_run_zap_seeds_use_hook_and_are_filtered(monkeypatch, tmp_path):
    seen: dict = {}

    async def run(args, *, cwd=None, **kw):
        hook = next(Path(a.split("=", 1)[1]) for a in args if a.startswith("--hook="))
        seen["args"] = args
        seen["files"] = {p.name: p.read_text() for p in hook.parent.iterdir()}
        (Path(cwd) / "zap.json").write_text(json.dumps(REPORT))
        return RunResult(0, "", "")
    monkeypatch.setattr(tools_mod, "run_process", run)
    asyncio.run(tools_mod.run_zap("http://lab:8000/", tmp_path / "zap", "n", network="tirith-lab",
                                  seeds=["/xss", "/../etc", "//evil.example/x", "http://evil/", "/ok/"]))
    assert any(a.startswith("--hook=") and a.endswith("seed_hook.py") for a in seen["args"])
    assert "-z" not in seen["args"]  # no session -> no replacer
    assert json.loads(seen["files"]["seeds.json"]) == ["/xss", "//evil.example/x", "/ok/"]
    assert "access_url" in seen["files"]["seed_hook.py"] and "netloc != origin" in seen["files"]["seed_hook.py"]
    assert not (tmp_path / "zap-auth").exists()


def test_seed_hook_stays_on_target_origin():
    ns: dict = {}
    exec(tools_mod.ZAP_SEED_HOOK, ns)  # noqa: S102 - our own fixed hook source

    class Core:
        def __init__(self):
            self.urls = []

        def access_url(self, url, followredirects):
            self.urls.append(url)

    class Zap:
        core = Core()

    import builtins
    real_open = builtins.open

    def fake_open(path, *a, **k):
        import io
        if str(path).endswith("seeds.json"):
            return io.StringIO(json.dumps(["/xss", "//evil.example/x", "/ok/"]))
        return real_open(path, *a, **k)
    builtins.open = fake_open
    try:
        ns["zap_started"](Zap, "http://lab:8000/")
    finally:
        builtins.open = real_open
    assert Zap.core.urls == ["http://lab:8000/xss", "http://lab:8000/evil.example/x", "http://lab:8000/ok/"]
