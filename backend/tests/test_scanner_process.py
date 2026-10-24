"""Local-process transport: argv carries real paths, no docker flags, nmap XML normalization."""

from pathlib import Path

from app.scanners import normalize, tools

DOWN = """<?xml version="1.0"?><nmaprun>
<host><status state="down" reason="no-response"/><address addr="192.168.50.10" addrtype="ipv4"/></host>
</nmaprun>"""

UP = """<?xml version="1.0"?><nmaprun>
<host><status state="up" reason="user-set"/><address addr="192.168.50.9" addrtype="ipv4"/>
<hostnames><hostname name="box.lan" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6" method="probed"/></port>
<port protocol="tcp" portid="99"><state state="closed"/><service name="unknown"/></port>
<port protocol="tcp" portid="8000"><state state="open"/>
<service name="http" product="uvicorn" method="probed"/>
<script id="http-title"><elem key="title">Tirith</elem><elem key="CVE-2024-1">x</elem></script></port>
</ports></host>
</nmaprun>"""


def _ctx(src: Path | None = None) -> normalize.Ctx:
    return normalize.Ctx(scan_id="scn", asset_id="ast", src_root=src)


def _no_docker(argv: list[str]) -> bool:
    return not any(a in ("run", "--rm", "--add-host", "-v", "--network", "--mount") for a in argv)


def test_source_scanners_run_relative_in_the_src_tree(tmp_path):
    sg = tools.semgrep_args()
    assert sg[:2] == ["semgrep", "scan"] and sg[-1] == "." and _no_docker(sg)
    gl = tools.gitleaks_args("dir")
    assert gl[1:3] == ["dir", "."] and _no_docker(gl)
    assert gl[gl.index("--config") + 1] == str(tools.CONFIG_DIR / "gitleaks.toml")
    tv = tools.trivy_args()
    assert tv[:2] == ["trivy", "fs"] and tv[-1] == "." and _no_docker(tv)
    # the config files are real paths that exist on this host
    assert (tools.CONFIG_DIR / "gitleaks.toml").is_file() and (tools.CONFIG_DIR / "trivy.yaml").is_file()


def test_zap_writes_to_the_cwd_and_points_at_auth_files(tmp_path):
    base = tools.zap_args("http://127.0.0.1:8000/", False)
    assert base == ["zap-baseline.py", "-t", "http://127.0.0.1:8000/", "-J", "zap.json", "-I", "-m", "1"]
    authed = tools.zap_args("http://127.0.0.1:8000/", True, True, authed=tmp_path)
    assert f"-configfile {tmp_path / 'auth.prop'}" == authed[authed.index("-z") + 1]
    assert f"--hook={tmp_path / 'seed_hook.py'}" in authed
    assert "-Dseed" in authed
    assert _no_docker(base + authed)


def test_host_scanner_argv():
    nm = tools.nmap_args("192.168.50.9")
    assert nm[0] == "nmap" and nm[-2:] == ["--", "192.168.50.9"] and "-oX" in nm and "-sT" in nm
    nk = tools.nikto_args("http://192.168.50.9:8000")
    assert nk[:4] == ["nikto", "-h", "http://192.168.50.9:8000", "-Format"] and "none" in nk
    assert tools.nikto_url("h", 80, "http") == "http://h" and tools.nikto_url("h", 8000, "http") == "http://h:8000"


def test_report_paths_resolve_both_relative_and_legacy(tmp_path):
    data = {"results": [{"check_id": "r", "path": "app/x.py", "start": {"line": 1}, "end": {"line": 1},
                         "extra": {"message": "m", "severity": "ERROR"}},
                        {"check_id": "r", "path": "/src/app/x.py", "start": {"line": 1}, "end": {"line": 1},
                         "extra": {"message": "m", "severity": "ERROR"}}]}
    assert [f.file for f in normalize.normalize_semgrep(data, _ctx())] == ["app/x.py", "app/x.py"]


def test_nmap_open_ports_become_medium_findings():
    fs = normalize.normalize_nmap(UP, _ctx())
    assert [f.severity for f in fs] == ["medium", "medium"]  # the closed port is dropped
    ssh = fs[0]
    assert ssh.tool == "nmap" and ssh.url == "tcp://192.168.50.9:22" and "OpenSSH 9.6" in ssh.title
    assert "host:192.168.50.9" in ssh.tags and "hostname:box.lan" in ssh.tags
    assert fs[1].cve == "CVE-2024-1"  # a CVE seen in a script result is kept
    assert len({f.fingerprint for f in fs}) == 2


def test_nmap_down_host_is_informational():
    fs = normalize.normalize_nmap(DOWN, _ctx())
    assert len(fs) == 1 and fs[0].severity == "info" and fs[0].rule_id == "nmap-host-down"
    assert "192.168.50.10" in fs[0].title


def test_nmap_unknown_service_keeps_port_open():
    fs = normalize.normalize_nmap(UP, _ctx())
    assert fs and all(f.severity in ("medium", "low") for f in fs)
    assert normalize.NORMALIZERS["nmap"] is normalize.normalize_nmap