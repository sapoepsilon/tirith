"""Isolated lab: build the target's Dockerfile and boot it on an `--internal` Docker network.

Two boot shapes, one handle (`LabHandle` = url + port + optional container):

  - **host mode** (Docker or podman present): `--network host`, so the app binds the guest loopback
    itself. The client and the destination are the same `127.0.0.1:<port>` string -- no translation,
    no `host.docker.internal`. Ports are allocated up front on loopback so two labs never collide.
    Hardening that host networking still allows is kept: no-new-privileges, all caps dropped, memory
    and pids limits, read-only supporting probes. Bootstrap = the image run through `sh -c`: it is
    just the app, `docker exec` reaches it for login/seeds/crawl.
  - **native mode** (no runtime): the profile's argv runs as a local process in the source directory,
    in its own session, killed at teardown. Same URL shape, same probes.

Where the app can egress is the host's business in both modes; `egress_check` reports what the
bridge allows instead of claiming a netns. Base images build with network, patched (LLM-written) trees
build with `--network none`; the base revision is built first so dependency layers are cached, and an
impossible offline build reports "lab boot unavailable" instead of granting network.

A Django project gets a lab-only settings overlay (ALLOWED_HOSTS / CSRF_TRUSTED_ORIGINS for the
loopback hosts) and `migrate`, so it boots against a fresh, empty SQLite DB (dummy data only).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..analystlab import copies
from . import core
from .core import Asset, Evidence
from .sh import Result, docker, git, run

log = logging.getLogger("tirith.lab")

LAB_NETWORK_DEFAULT = "tirith-lab"
LAB_BRIDGE = os.environ.get("TIRITH_LAB_BRIDGE", "tirith-lab0")  # host interface name (<=15 chars)
BUILD_TIMEOUT = int(os.environ.get("TIRITH_LAB_BUILD_TIMEOUT", "1500"))
BOOT_TIMEOUT = int(os.environ.get("TIRITH_LAB_BOOT_TIMEOUT", "120"))
# Peer probe runs a fixed curl image, never the (patchable) target image.
CURL_IMAGE = os.environ.get("TIRITH_LAB_CURL_IMAGE", "curlimages/curl:8.11.1")


def host_mode() -> bool:
    """A runtime is present, so a copy is a host-network container (else: a local process)."""
    return copies.available() is not None


GATEWAY_PORTS = [int(p) for p in os.environ.get("TIRITH_LAB_GATEWAY_PORTS", "22,80,443,2375,8000,8010").split(",")
                 if p.strip().isdigit()]


def host_firewall_rules(bridge: str = LAB_BRIDGE) -> list[str]:
    """iptables rules the HOST needs so lab containers cannot reach host services or anything off-bridge.

    INPUT: drops lab -> host (gateway IP, host LAN IP, any local port); DOCKER-USER: drops lab ->
    anywhere-but-the-lab-bridge for forwarded traffic. Same-bridge traffic (ZAP -> app) is untouched.
    """
    rules = []
    for ipt in ("iptables", "ip6tables"):
        rules += [f"{ipt} -I DOCKER-USER -i {bridge} ! -o {bridge} -j DROP",
                  f"{ipt} -I INPUT -i {bridge} -j DROP"]
    return rules


HOST_FIREWALL_RULES = "\n".join(host_firewall_rules())


class LabError(RuntimeError):
    pass


class LabUnavailable(LabError):
    """The lab cannot be built without granting network to patched code; reported, never worked around."""


def lab_network() -> str:
    try:
        return core.load_scope().lab_network or LAB_NETWORK_DEFAULT
    except Exception:
        return LAB_NETWORK_DEFAULT


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "target"


def ev(kind: str, label: str, content: str) -> Evidence:
    return Evidence(kind=kind, label=label, content=(content or "")[-6000:])


# ----------------------------------------------------------------------------- network
def ensure_network(name: str | None = None) -> tuple[str, Evidence]:
    name = name or lab_network()
    r = docker(["network", "inspect", name, "--format", "{{json .Internal}}"])
    if r.ok:
        if r.out.strip() != "true":
            raise LabError(f"docker network {name} exists but is NOT internal; refusing to use it")
    else:
        c = docker(["network", "create", "--internal", "--driver", "bridge", "--label", "tirith.lab=1",
                    "-o", f"com.docker.network.bridge.name={LAB_BRIDGE}", name])
        if not c.ok and "already exists" not in c.err:
            raise LabError(f"cannot create lab network {name}: {c.tail()}")
    insp = docker(["network", "inspect", name, "--format",
                   "name={{.Name}} driver={{.Driver}} internal={{.Internal}} subnet={{range .IPAM.Config}}{{.Subnet}}{{end}} "
                   "gateway={{range .IPAM.Config}}{{.Gateway}}{{end}} "
                   "bridge={{index .Options \"com.docker.network.bridge.name\"}}"])
    if "internal=true" not in insp.out:
        raise LabError(f"lab network {name} is not internal: {insp.tail()}")
    note = insp.out.strip()
    if f"bridge={LAB_BRIDGE}" not in note:
        note += (f"\nWARNING: bridge interface is not {LAB_BRIDGE}, so the host firewall rules below will not match. "
                 f"Recreate the network once (docker network rm {name}) so Tirith creates it with the fixed name.")
    return name, ev("note", "lab network", note + "\nHost firewall (lab -> host/off-bridge drop):\n" + HOST_FIREWALL_RULES)


# ----------------------------------------------------------------------------- build
def _tree_fingerprint(src: Path) -> str:
    """Hash of everything uncommitted that ends up in the build context: the full working-tree diff
    against HEAD (content, incl. binary) plus every untracked file's path and bytes."""
    h = hashlib.sha256()
    d = git(["diff", "HEAD", "--binary", "--no-ext-diff", "--no-textconv"], cwd=src)
    h.update(d.out.encode())
    u = git(["ls-files", "--others", "--exclude-standard", "-z"], cwd=src)
    for rel in sorted(p for p in u.out.split("\0") if p):
        fp = src / rel
        h.update(b"\0" + rel.encode() + b"\0")
        try:
            if fp.is_file() and not fp.is_symlink():
                h.update(fp.read_bytes())
            elif fp.is_symlink():
                h.update(os.readlink(fp).encode())
        except OSError:
            h.update(b"?")
    return h.hexdigest()


def image_tag(src: Path, label: str) -> str:
    r = git(["rev-parse", "HEAD"], cwd=src)
    if r.ok:
        h = r.out.strip()[:12]
        dirty = git(["status", "--porcelain"], cwd=src)
        if dirty.ok and dirty.out.strip():
            h += "-" + _tree_fingerprint(src)[:12]
    else:
        h = hashlib.sha256(f"{src}{time.time()}".encode()).hexdigest()[:12]
    return f"tirith-lab/{_slug(label)}:{h}"


def build(src: Path, label: str, *, network: bool = True) -> tuple[str, Result]:
    """docker build. network=False builds with `--network none` (for trees containing LLM-written code)."""
    if not (src / "Dockerfile").is_file():
        raise LabError(f"no Dockerfile at {src}")
    tag = image_tag(src, label)
    if docker(["image", "inspect", tag, "--format", "{{.Id}}"]).ok:
        return tag, Result(0, f"image {tag} already built (cache hit)", "")
    args = ["build", "--pull=false", "--label", "tirith.lab=1", "-t", tag]
    if not network:
        args += ["--network", "none"]
    r = docker([*args, str(src)], timeout=BUILD_TIMEOUT)
    if not r.ok:
        if not network:
            raise LabUnavailable("lab boot unavailable: the patched image could not be built without network access "
                                 f"(Tirith never gives network to patched code): {r.tail(800)}")
        raise LabError(f"docker build failed: {r.tail(1500)}")
    return tag, r


def _image_config(tag: str) -> dict[str, Any]:
    r = docker(["image", "inspect", tag, "--format", "{{json .Config}}"])
    try:
        return json.loads(r.out) if r.ok else {}
    except json.JSONDecodeError:
        return {}


@dataclass
class Profile:
    port: int = 8000
    argv: list[str] = field(default_factory=list)  # full command (entrypoint + cmd)
    django_settings: str | None = None
    seed_commands: list[str] = field(default_factory=list)  # Django management commands seeding demo data


# The repo's own compose setup (`python manage.py seed_x && python manage.py populate_y ...`) seeds the
# demo/lab metadata the UI is built from (PyGoat: sidebar lab links). Only data-seeding commands
# (seed*/populate*) that the repo actually ships are replayed, inside the network-less lab container.
_SEED_CMD = re.compile(r"manage\.py\s+((?:seed|populate)[a-z0-9_]{0,40})\b")
_COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


def seed_commands(src: Path) -> list[str]:
    found: list[str] = []
    for name in _COMPOSE_FILES:
        f = src / name
        if f.is_file() and not f.is_symlink():
            for cmd in _SEED_CMD.findall(f.read_text(errors="replace")[:200_000]):
                shipped = any(p.is_file() for p in src.glob(f"*/management/commands/{cmd}.py"))
                if shipped and cmd not in found:
                    found.append(cmd)
    return found[:10]


def detect_profile(src: Path, tag: str) -> Profile:
    cfg = _image_config(tag)
    ports = [int(p.split("/")[0]) for p in (cfg.get("ExposedPorts") or {}) if p.split("/")[0].isdigit()]
    argv = list(cfg.get("Entrypoint") or []) + list(cfg.get("Cmd") or [])
    prof = Profile(port=ports[0] if ports else 8000, argv=argv)
    mp = src / "manage.py"
    if mp.is_file():
        m = re.search(r"DJANGO_SETTINGS_MODULE['\"]\s*,\s*['\"]([\w.]+)['\"]", mp.read_text(errors="replace"))
        prof.django_settings = m.group(1) if m else None
        prof.seed_commands = seed_commands(src)
    return prof


# ----------------------------------------------------------------------------- run
@dataclass
class LabHandle:
    url: str
    network: str
    port: int
    container: str = ""  # "" = native process (no runtime): the client runs right here
    image: str = ""
    proc: int = 0  # pid of a native copy (its own session); 0 for a container
    src: Path | None = None  # source tree of a native copy (its process cwd)
    ok: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    started_at: str = field(default_factory=core.now_iso)
    django_settings: str | None = None  # set by start() for Django targets (enables session())

    @property
    def native(self) -> bool:
        return not self.container

    @property
    def proc_cwd(self) -> Path | None:
        return self.src if self.native else None

    def stop(self) -> None:
        if self.container:
            docker(["rm", "-f", self.container], timeout=60)
        elif self.proc:
            copies.stop_pid(self.proc)
            self.proc = 0
        _registry_drop(self)
        _session_drop(self)

    # dict-style access so callers can treat it as {url, network, stop()}
    def __getitem__(self, k: str) -> Any:
        return getattr(self, k)

    def as_dict(self) -> dict[str, Any]:
        return {"url": self.url, "network": self.network, "container": self.container, "image": self.image,
                "port": self.port, "mode": "native" if self.native else "host", "ok": self.ok,
                "started_at": self.started_at}


def _boot_script(prof: Profile) -> str:
    pre = ""
    if prof.django_settings:
        pre = "python manage.py migrate --noinput > /tmp/tirith-migrate.log 2>&1 || cat /tmp/tirith-migrate.log; "
        for cmd in prof.seed_commands:
            if re.fullmatch(r"[a-z][a-z0-9_]{0,48}", cmd):
                pre += (f"timeout 90 python manage.py {cmd} >> /tmp/tirith-seed.log 2>&1 "
                        f"|| echo 'tirith lab: seed {cmd} failed' >&2; ")
    return pre + 'exec "$@"'


# ----------------------------------------------------------------------------- Django host allow-list
# Django answers 400 DisallowedHost for any Host header outside ALLOWED_HOSTS, and lab requests arrive
# as `<container>:<port>` (ZAP, peer probe) or `127.0.0.1:<port>` (in-container probes, login, repro).
# Both are made acceptable without touching the checkout: env vars the settings already read (if any)
# plus a lab-only overlay module (DJANGO_SETTINGS_MODULE) that imports the original and extends lists.
def lab_hosts(container: str) -> list[str]:
    return [container, "localhost", "127.0.0.1", "[::1]"]


def lab_origins(container: str, port: int) -> list[str]:
    return [f"http://{h}:{port}" for h in lab_hosts(container)]


_ENV_READ = re.compile(r"""(?:getenv|environ\.get|environ\[|env(?:\.list|\.str)?|config)\(?\s*['"]([A-Z][A-Z0-9_]{0,60})['"]""")


def _settings_file(src: Path, module: str) -> Path | None:
    base = src.joinpath(*module.split("."))
    for p in (base.with_suffix(".py"), base / "__init__.py"):
        if p.is_file() and not p.is_symlink():
            return p
    return None


def django_host_env(src: Path, module: str | None, container: str, port: int) -> dict[str, str]:
    """{ENV: value} for env vars the target's settings read into ALLOWED_HOSTS / CSRF_TRUSTED_ORIGINS."""
    f = _settings_file(src, module) if module else None
    if f is None:
        return {}
    vals = {"ALLOWED_HOSTS": lab_hosts(container), "CSRF_TRUSTED_ORIGINS": lab_origins(container, port)}
    env: dict[str, str] = {}
    for ln in f.read_text(errors="replace")[:200_000].splitlines():
        m = re.match(r"\s*(ALLOWED_HOSTS|CSRF_TRUSTED_ORIGINS)\s*[:=]", ln)
        if not m:
            continue
        sep = " " if re.search(r"\.split\(\s*(?:['\"] ['\"])?\s*\)", ln) else ","
        for var in _ENV_READ.findall(ln):
            env[var] = sep.join(vals[m.group(1)])
    return env


def django_overlay(module: str, container: str, port: int) -> str:
    """Lab-only settings module: the app's own settings plus the lab host/origins (nothing removed)."""
    return (
        "# Tirith lab-only overlay: the app is reachable only on the internal lab network.\n"
        f"from {module} import *  # noqa: F401,F403\n"
        f"_LAB_HOSTS = {lab_hosts(container)!r}\n"
        f"_LAB_ORIGINS = {lab_origins(container, port)!r}\n"
        "try:\n"
        "    import django\n"
        "    if django.VERSION < (4, 0):  # pre-4.0 CSRF_TRUSTED_ORIGINS are bare hosts\n"
        "        _LAB_ORIGINS = _LAB_HOSTS\n"
        "except ImportError:\n"
        "    pass\n"
        "ALLOWED_HOSTS = list(globals().get('ALLOWED_HOSTS') or []) + _LAB_HOSTS\n"
        "CSRF_TRUSTED_ORIGINS = list(globals().get('CSRF_TRUSTED_ORIGINS') or []) + _LAB_ORIGINS\n"
    )


def _pythonpath(tag: str) -> str:
    """/tirith_lab first, keeping any PYTHONPATH the image already sets."""
    for kv in _image_config(tag).get("Env") or []:
        if str(kv).startswith("PYTHONPATH=") and str(kv)[11:]:
            return "/tirith_lab:" + str(kv)[11:]
    return "/tirith_lab"


def native_env(src: Path, prof: Profile, port: int) -> dict[str, str]:
    """Env for a native copy: the lab marker, the port, and (Django) the overlay on PYTHONPATH."""
    env = {"TIRITH_LAB": "1", "DEBUG_SEED": "dummy", "PORT": str(port)}
    if prof.django_settings:
        env.update(django_host_env(src, prof.django_settings, "127.0.0.1", port))
    return env


def start(tag: str, src: Path, label: str, network: str) -> tuple[LabHandle, Profile]:
    """Boot the copy: host-network container when a runtime exists, else a local process."""
    prof = detect_profile(src, tag)
    if not prof.argv:
        raise LabError("image has no CMD/ENTRYPOINT to boot")
    port = copies.free_port()
    if host_mode():
        name = f"tirith-lab-{_slug(label)[:24]}-{secrets.token_hex(3)}"
        args = [
            "create", "--name", name, "--hostname", name, "--network", "host", "--label", "tirith.lab=1",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--memory", "1g", "--pids-limit", "512",
            "-e", "TIRITH_LAB=1", "-e", "DEBUG_SEED=dummy", "-e", f"PORT={port}",
        ]
        if prof.django_settings:
            for k, v in django_host_env(src, prof.django_settings, name, port).items():
                args += ["-e", f"{k}={v}"]
            args += ["-e", "DJANGO_SETTINGS_MODULE=tirith_lab_settings", "-e", f"PYTHONPATH={_pythonpath(tag)}"]
        args += ["-p", str(port), "--entrypoint", "sh", tag, "-c", _boot_script(prof), "sh", *prof.argv]
        r = docker(args, timeout=60)
        if not r.ok:
            raise LabError(f"docker create failed: {r.tail()}")
        if prof.django_settings:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td) / "tirith_lab"
                d.mkdir()
                (d / "tirith_lab_settings.py").write_text(django_overlay(prof.django_settings, name, port))
                cp = docker(["cp", str(d), f"{name}:/tirith_lab"], timeout=60)
                if not cp.ok:
                    docker(["rm", "-f", name])
                    raise LabError(f"docker cp overlay failed: {cp.tail()}")
        started = docker(["start", name], timeout=60)
        if not started.ok:
            docker(["rm", "-f", name])
            raise LabError(f"docker start failed: {started.tail()}")
        return LabHandle(url=f"http://127.0.0.1:{port}/", network=network, port=port, container=name,
                         image=tag, django_settings=prof.django_settings), prof
    app = copies.spawn_detached(prof.argv, src, native_env(src, prof, port))
    return LabHandle(url=f"http://127.0.0.1:{port}/", network="host", port=port, proc=app.pid, src=src,
                     image=tag, django_settings=prof.django_settings), prof


_CURL = "curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:{port}{path}"
_PY = ("python -c \"import urllib.request,urllib.error,sys\ntry:\n r=urllib.request.urlopen('http://127.0.0.1:{port}{path}',timeout=5);print(r.status)\n"
       "except urllib.error.HTTPError as e: print(e.code)\nexcept Exception: print(0)\"")


def probe(h: LabHandle | str, port: int | None = None, path: str = "/") -> int:
    """`GET` status of the copy's own port, read by the same client everything else uses: `docker exec`
    in a host container, plain `sh -c` locally."""
    container, port = (h.container, h.port) if isinstance(h, LabHandle) else (h, port or 0)
    if not copies.waits("127.0.0.1", port, 1.0) and container:
        pass  # still exec: the app may not be listening yet, the probe is what discovers it
    cmd = f"if command -v curl >/dev/null; then {_CURL}; else {_PY}; fi".replace("{port}", str(port)).replace("{path}", path)
    argv = ["docker", "exec", container, "sh", "-c", cmd] if container else ["sh", "-c", cmd]
    r = run(argv, timeout=20)
    code = r.out.strip()[-3:]
    return int(code) if code.isdigit() else 0


def wait_ready(h: LabHandle, timeout: int = BOOT_TIMEOUT) -> int:
    deadline = time.monotonic() + timeout
    code = 0
    while time.monotonic() < deadline:
        if h.container:
            st = docker(["inspect", h.container, "--format", "{{.State.Status}}"], timeout=15).out.strip()
        else:
            st = "running" if copies.pid_alive(h.proc) else "exited"
        if st in ("exited", "dead"):
            return -1
        code = probe(h)
        if 200 <= code < 500:
            return code
        time.sleep(2)
    return code


def get_page(h: LabHandle, path: str = "/") -> tuple[str, str]:
    """Read-only GET of the copy's loopback port, from its container or right here."""
    path = path if path.startswith("/") else "/" + path
    path = re.sub(r"[^A-Za-z0-9/._~%?=&-]", "", path)[:300]
    url = f"http://127.0.0.1:{h.port}{path}"
    argv = (["docker", "exec", h.container, "curl", "-s", "-i", "--max-time", "8", url] if h.container
            else ["curl", "-s", "-i", "--max-time", "8", url])
    r = run(argv, timeout=20)
    body = r.out
    head, _, rest = body.partition("\r\n\r\n")
    return f"GET {path} HTTP/1.1\nHost: {h.container or '127.0.0.1'}:{h.port}", (head + "\r\n\r\n" + rest[:1500]).strip()


def peer_probe(h: LabHandle) -> Evidence:
    """Prove a client other than the app's own process reaches it: a host-network peer container
    (host mode) or a plain curl right here (native mode)."""
    if h.container:
        r = docker(["run", "--rm", "--pull", "missing", "--network", "host", "--security-opt", "no-new-privileges",
                    "--cap-drop", "ALL", "--read-only", "--user", "65534:65534", "--memory", "64m", "--pids-limit", "32",
                    "--cpus", "0.5", "--label", "tirith.lab=1", "--entrypoint", "curl",
                    CURL_IMAGE, "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", h.url], timeout=120)
        via = f"a peer container ({CURL_IMAGE})"
    else:
        r = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", h.url], timeout=60)
        via = "curl here on the guest loopback"
    return ev("response", "peer probe", f"GET {h.url} from {via} -> HTTP {r.out.strip() or r.tail(200)}")


def network_gateway(network: str) -> str:
    r = docker(["network", "inspect", network, "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"], timeout=15)
    gw = r.out.strip() if r.ok else ""
    return gw if re.fullmatch(r"[0-9a-fA-F.:]+", gw or "") else ""


_EGRESS_PY = """import socket
def tcp(h, p):
    try:
        socket.create_connection((h, p), 2).close(); return 'open'
    except ConnectionRefusedError: return 'refused'
    except socket.timeout: return 'timeout'
    except OSError as e: return type(e).__name__
print('internet', '1.1.1.1:443', tcp('1.1.1.1', 443))
for p in PORTS:
    if GW: print('gateway', GW + ':' + str(p), tcp(GW, p))
"""


def egress_check(h: LabHandle) -> Evidence:
    """One outbound connect to the internet + TCP probes of the bridge gateway (= the host).

    `--internal` only means something while the app sits on that bridge; a host-network copy shares
    the guest's stack and inherits whatever the guest may reach, so the verdict is reported as
    observed (EGRESS-OPEN there) instead of being claimed as blocked."""
    gw = network_gateway(h.network) if h.container else ""
    code = f"GW={gw!r}\nPORTS={GATEWAY_PORTS!r}\n" + _EGRESS_PY
    argv = ["docker", "exec", h.container, "python", "-c", code] if h.container else ["python", "-c", code]
    r = run(argv, timeout=30 + 3 * len(GATEWAY_PORTS))
    lines = [ln.split() for ln in r.out.splitlines() if len(ln.split()) == 3]
    inet = next((x[2] for x in lines if x[0] == "internet"), None)
    gw_res = [(x[1], x[2]) for x in lines if x[0] == "gateway"]
    parts = []
    if inet is None:
        parts.append(f"egress probe did not run: {r.tail(200)}")
    else:
        parts.append(f"outbound connect to 1.1.1.1:443 from the lab copy: "
                     f"{'EGRESS-OPEN' if inet == 'open' else 'EGRESS-BLOCKED'} ({inet})")
    if not gw:
        parts.append("gateway probe: no gateway address on the lab network")
    elif gw_res:
        reach = [f"{a} {b}" for a, b in gw_res if b in ("open", "refused")]
        verdict = "GATEWAY-REACHABLE" if reach else "GATEWAY-BLOCKED"
        parts.append(f"host gateway {gw} probe: {verdict} ({', '.join(f'{a}={b}' for a, b in gw_res)})")
        if reach:
            parts.append("The host answers on the lab bridge; apply on the host:\n" + HOST_FIREWALL_RULES)
    return ev("note", "egress check", "\n".join(parts))


def logs(h: LabHandle, n: int = 120) -> str:
    if h.container:
        r = docker(["logs", "--tail", str(n), h.container], timeout=30)
        return (r.out + r.err).strip()
    return copies.start_log(h.proc, n)


def boot(src: Path, label: str, *, keep: bool = True, on_step=None, network: bool = True,
         base_src: Path | None = None) -> LabHandle:
    """Build + boot + probe + capture evidence. Raises LabError on build/start failure
    (LabUnavailable when an offline build is impossible); a non-responsive app returns a handle
    with ok=False (and is stopped unless keep).

    network=False: `src` contains untrusted (LLM-written) code, so it is built with `--network none`.
    `base_src` (the unpatched revision) is built first WITH network to warm the dependency layers."""
    step = on_step or (lambda msg, **kw: None)
    lab_net, net_ev = ensure_network()
    step(f"Lab network {lab_net} ready (internal, no egress)")
    t0 = time.monotonic()
    if base_src is not None:
        step(f"Building base revision image from {base_src.name}/Dockerfile (dependency layers)")
        build(base_src, f"{label}-base", network=True)
    step(f"Building image from {src.name}/Dockerfile" + ("" if network else " with --network none"))
    tag, br = build(src, label, network=network)
    build_ev = ev("log", "docker build", f"image {tag} built in {time.monotonic() - t0:.0f}s\n" + br.tail(1500))
    h, prof = start(tag, src, label, lab_net)
    h.evidence += [net_ev, build_ev]
    step(f"Started {h.container or 'local pid ' + str(h.proc)} at {h.url}"
         + (f" on {lab_net} (no published ports)" if h.container else " (native process)"))
    code = wait_ready(h)
    h.ok = 200 <= code < 500
    h.evidence.append(ev("response", "boot probe", f"GET {h.url} -> HTTP {code}"
                         + (" (exited)" if code == -1 else "")))
    if h.ok:
        req, resp = get_page(h, "/")
        h.evidence.append(ev("request", "lab GET /", req))
        h.evidence.append(ev("response", "lab response /", resp))
        loc = re.search(r"^Location:\s*(/\S*)", resp, re.M | re.I)
        if loc and resp.split(" ", 2)[1:2] and resp.split(" ", 2)[1].startswith("3"):
            req2, resp2 = get_page(h, loc.group(1))
            h.evidence.append(ev("response", f"lab response {loc.group(1)[:60]}", resp2[:1200]))
        h.evidence.append(peer_probe(h))
        h.evidence.append(egress_check(h))
    h.evidence.append(ev("log", "lab logs", logs(h)))
    pub = docker(["port", h.container], timeout=15).out.strip() if h.container else "local port"
    h.evidence.append(ev("note", "published host ports", pub or "none"))
    step(f"Lab app {'responded HTTP ' + str(code) if h.ok else 'did not respond (code ' + str(code) + ')'}")
    _save_evidence(h, label)
    if not h.ok and not keep:
        h.stop()
    elif h.ok:
        _registry_put(label, h)
    return h


def _save_evidence(h: LabHandle, label: str) -> None:
    try:
        d = core.evidence_dir() / "lab"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{h.container or 'pid-' + str(h.proc)}.json").write_text(json.dumps(
            {"label": label, **h.as_dict(), "evidence": [e.model_dump() for e in h.evidence]}, indent=2))
    except OSError:
        log.exception("could not save lab evidence")


# ----------------------------------------------------------------------------- registry + core hook
_registry: dict[str, LabHandle] = {}
_reg_lock = threading.Lock()


def _registry_put(key: str, h: LabHandle) -> None:
    with _reg_lock:
        _registry[key] = h


def _registry_drop(h: LabHandle) -> None:
    with _reg_lock:
        for k, v in list(_registry.items()):
            if v.container == h.container:
                del _registry[k]


def running(key: str) -> LabHandle | None:
    with _reg_lock:
        h = _registry.get(key)
    alive = (docker(["inspect", h.container, "--format", "{{.State.Running}}"], timeout=15).out.strip() == "true"
             if h and h.container else (copies.pid_alive(h.proc) if h else False))
    if h and alive:
        return h
    if h:
        _registry_drop(h)
    return None


def get_lab_target(asset: Asset) -> LabHandle | None:
    """Core hook (app.scanners.tools.get_lab_target): {url, network, stop()} for the asset's lab copy.

    Reuses a running lab for the asset, else builds + boots one (blocking: call it via
    asyncio.to_thread from async code). Returns None for assets without a Dockerfile.
    """
    key = f"asset:{asset.id}"
    h = running(key)
    if h:
        return h
    if asset.kind == "url":
        return None
    src = core.source_dir(asset)
    if not src or not (src / "Dockerfile").is_file():
        return None
    core.audit("lab.boot", target=f"{asset.kind}:{asset.ref}", details={"network": lab_network()})
    try:
        h = boot(src, key, keep=False)
    except LabError as e:
        core.audit("lab.boot.failed", target=f"{asset.kind}:{asset.ref}", allowed=False, details={"error": str(e)[:500]})
        core.emit("validation.step", f"Lab boot failed: {e}", level="error", data={"asset_id": asset.id})
        return None
    if h.ok:
        _registry_put(key, h)
        return h
    return None


def stop_all() -> int:
    r = docker(["ps", "-aq", "--filter", "label=tirith.lab=1"], timeout=30)
    ids = r.out.split()
    if ids:
        docker(["rm", "-f", *ids], timeout=120)
    with _reg_lock:
        stops = list(_registry.values())
        _registry.clear()
    for h in stops:
        if h.proc:
            copies.stop_pid(h.proc)
    ids = ids + [f"pid {h.proc}" for h in stops if h.proc]
    with _sess_lock:
        _sessions.clear()
        _creds.clear()
    return len(ids)


# ----------------------------------------------------------------------------- lab test user + session
# A throwaway account created inside the lab copy only. Credentials are generated per copy, live only
# in this process (never logged, audited, written to evidence, or sent anywhere but the copy on stdin),
# and die with it.
LOGIN_PATHS = ("/login/", "/accounts/login/")
_SESSION_MARK = "TIRITH_LAB_SESSION="
# Django setup then the stdin script (`manage.py shell` races on stdin and may fall into a REPL).
_DJANGO_PY = ["python", "-c", "import sys, django; django.setup(); exec(compile(sys.stdin.read(), '<tirith-lab>', 'exec'))"]


@dataclass
class LabCreds:
    username: str
    password: str = field(repr=False)


_sessions: dict[str, dict[str, str]] = {}  # copy key -> cookies
_creds: dict[str, LabCreds] = {}  # copy key -> credentials
_sess_lock = threading.Lock()


def _key(h: LabHandle) -> str:
    return h.container or f"pid-{h.proc}"


def _session_drop(h: LabHandle) -> None:
    with _sess_lock:
        _sessions.pop(_key(h), None)
        _creds.pop(_key(h), None)


def _exec_py(h: LabHandle, argv: list[str], script: str, secret: str, timeout: int = 90) -> Result:
    """Run a Python script in the copy's own app, fed on stdin (never argv/env, so not in `ps` or
    `docker inspect`); `secret` is scrubbed from whatever comes back.

    Exec just means "in the copy": `docker exec -i` for a host container, the local process for a
    native copy (its cwd is the source tree, PYTHONPATH carries the overlay)."""
    exe = argv[0]
    if exe == "python" and not h.container:  # no `python` shim needed outside an image
        argv = [os.environ.get("TIRITH_LAB_PYTHON") or "python3", *argv[1:]]
    full = ["docker", "exec", "-i", h.container, *argv] if h.container else argv
    return run(full, input=script, timeout=timeout, secrets=(secret,))


_DJANGO_USER = """
from django.contrib.auth import get_user_model
U = get_user_model()
u = U.objects.filter(**{U.USERNAME_FIELD: NAME}).first() or U(**{U.USERNAME_FIELD: NAME})
if hasattr(u, "email") and not getattr(u, "email", None) and U.USERNAME_FIELD != "email":
    u.email = NAME + "@lab.invalid"
u.is_active = True
u.set_password(PW)
u.save()
print("TIRITH_LAB_USER_OK")
"""

# Real login through the app's own form (CSRF token + POST), from inside the container.
_DJANGO_FORM_LOGIN = """
import http.cookiejar, json, re, urllib.parse, urllib.request
base = "http://127.0.0.1:%d" % PORT
for path in PATHS:
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        html = op.open(base + path, timeout=10).read().decode("utf-8", "replace")
    except Exception:
        continue
    m = (re.search(r'name=["\\']csrfmiddlewaretoken["\\'][^>]*value=["\\']([^"\\']+)', html)
         or re.search(r'value=["\\']([^"\\']+)["\\'][^>]*name=["\\']csrfmiddlewaretoken', html))
    if not m:
        continue
    before = {c.name for c in jar}
    data = urllib.parse.urlencode({"csrfmiddlewaretoken": m.group(1), "username": NAME, "login": NAME,
                                   "password": PW}).encode()
    try:
        op.open(urllib.request.Request(base + path, data, headers={"Referer": base + path}), timeout=15).read()
    except Exception:
        pass
    cookies = {c.name: c.value for c in jar}
    if any("session" in k.lower() and k not in before for k in cookies):
        print(MARK + json.dumps({"via": path, "cookies": cookies}))
        break
"""

# Fallback: mint a session for the user directly in the app's session store.
_DJANGO_DIRECT = """
import json
from importlib import import_module
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, get_user_model
U = get_user_model()
u = U.objects.get(**{U.USERNAME_FIELD: NAME})
s = import_module(settings.SESSION_ENGINE).SessionStore()
s[SESSION_KEY] = str(u.pk)
s[BACKEND_SESSION_KEY] = "django.contrib.auth.backends.ModelBackend"
s[HASH_SESSION_KEY] = u.get_session_auth_hash()
s.create()
print(MARK + json.dumps({"via": "session-store", "cookies": {settings.SESSION_COOKIE_NAME: s.session_key}}))
"""


def _prelude(**kv: Any) -> str:
    return "".join(f"{k} = {v!r}\n" for k, v in kv.items())


def _parse_session(out: str) -> tuple[str, dict[str, str]] | None:
    for ln in reversed(out.splitlines()):
        if ln.startswith(_SESSION_MARK):
            try:
                d = json.loads(ln[len(_SESSION_MARK):])
            except json.JSONDecodeError:
                return None
            ck = {str(k): str(v) for k, v in (d.get("cookies") or {}).items()
                  if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(k)) and re.fullmatch(r"[\x21-\x7e]{1,512}", str(v))
                  and ";" not in str(v)}
            return (str(d.get("via") or "?"), ck) if ck else None
    return None


def _is_django(h: LabHandle) -> bool:
    if h.django_settings:
        return True
    if h.container:
        return docker(["exec", h.container, "test", "-f", "manage.py"], timeout=15).ok
    return bool(h.src) and (h.src / "manage.py").is_file()


def _login(h: LabHandle) -> dict[str, str]:
    if not _is_django(h):
        log.info("lab session: %s is not a Django app; no test user", h.container)
        return {}
    with _sess_lock:
        cr = _creds.get(_key(h))
        if cr is None:
            cr = _creds[_key(h)] = LabCreds(f"tirith-lab-{secrets.token_hex(4)}", secrets.token_urlsafe(24))
    base = _prelude(NAME=cr.username, PW=cr.password, PORT=h.port, PATHS=list(LOGIN_PATHS), MARK=_SESSION_MARK)
    u = _exec_py(h, _DJANGO_PY, base + _DJANGO_USER, cr.password)
    if "TIRITH_LAB_USER_OK" not in u.out:
        log.warning("lab session: creating the test user in %s failed: %s", h.container, u.tail(300))
        return {}
    got = _parse_session(_exec_py(h, ["python", "-"], base + _DJANGO_FORM_LOGIN, cr.password).out)
    if got is None:
        got = _parse_session(_exec_py(h, _DJANGO_PY, base + _DJANGO_DIRECT, cr.password).out)
    if got is None:
        log.warning("lab session: could not log the test user into %s", h.container)
        return {}
    via, cookies = got
    h.evidence.append(ev("note", "lab test user", f"signed in as lab-only test user {cr.username} via {via}; "
                                                  f"cookies: {', '.join(sorted(cookies))} (values withheld)"))
    return cookies


def session(h: LabHandle, refresh: bool = False) -> dict[str, str]:
    """Logged-in session cookies for the lab copy behind `h`, as {cookie name: value}.

    On first use creates a throwaway test account inside the lab container (Django: via
    `django.setup()` + ORM, credentials generated at runtime) and signs it in through the app's own
    login form (fallback: a session minted in the app's session store). Cached per handle
    (container); `refresh=True` logs in again. Returns {} when the app has no supported login.
    Blocking (docker exec): call via asyncio.to_thread from async code."""
    if not isinstance(h, LabHandle):
        return {}
    with _sess_lock:
        if not refresh and _key(h) in _sessions:
            return dict(_sessions[_key(h)])
    cookies = _login(h)
    if cookies:
        with _sess_lock:
            _sessions[_key(h)] = cookies
        _publish_cookies(_key(h), cookies)
    return dict(cookies)


def session_of(h: object) -> dict[str, str]:
    """The cached (already logged-in) session for a copy handle, or {}. A live handle has no copy and no
    session: it is reached unauthenticated, exactly as it stands."""
    if not isinstance(h, LabHandle):
        return {}
    with _sess_lock:
        return dict(_sessions.get(_key(h)) or {})


_COOKIE_AUDIT = "lab.session"
_COOKIE_LIMIT = 250


def _publish_cookies(container: str, cookies: dict[str, str]) -> None:
    """Record the cookie VALUES in the audit log, so a report rendered outside this process can mask them.

    Values only, never the whole jar: the dashboard's report route reads the audit tail and blanks any
    of these before serving a page."""
    from ..audit import audit
    from ..store import get_store

    rows = [a for a in get_store().list_audit(_COOKIE_LIMIT) if a.action == _COOKIE_AUDIT]
    known = set()
    for a in rows:
        known.update((a.details or {}).values())
    fresh = {k: v for k, v in cookies.items() if v and v not in known}
    if fresh:
        audit(_COOKIE_AUDIT, target=container, details=fresh)


# ----------------------------------------------------------------------------- crawl seeds
# Many apps (PyGoat included) link their pages from JavaScript, so a plain spider started at `/`
# never finds them. For Django targets we read the URL map inside the lab container and hand ZAP
# the parameter-free GET routes as extra start points (it requests each once through its proxy, so
# the passive rules see them, signed in). Routes that could end the session or change state by
# name are skipped.
SEED_SKIP = re.compile(r"(logout|log-out|signout|sign-out|password|delete|remove|reset|deactivate|disable|stop|"
                       r"^admin/|^static/|^media/|^__debug__/)", re.I)
_DJANGO_ROUTES = """
import json
from django.urls import URLPattern, URLResolver, get_resolver
out = []
def walk(pats, prefix):
    for p in pats:
        if isinstance(p, URLResolver):
            walk(p.url_patterns, prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            out.append(prefix + str(p.pattern))
walk(get_resolver().url_patterns, "")
print(MARK + json.dumps(out[:2000]))
"""


def crawl_seeds(h: LabHandle) -> list[str]:
    """Parameter-free GET paths of the lab app (e.g. ["/", "/xss", "/sql"]), [] if unknown. Blocking."""
    if not isinstance(h, LabHandle) or not _is_django(h):
        return []
    py = list(_DJANGO_PY)
    if not h.container:
        py[0] = os.environ.get("TIRITH_LAB_PYTHON") or "python3"
        argv = py
    else:
        argv = ["docker", "exec", "-i", h.container, *py]
    r = run(argv, input=_prelude(MARK=_SESSION_MARK) + _DJANGO_ROUTES, timeout=60)
    line = next((ln for ln in reversed(r.out.splitlines()) if ln.startswith(_SESSION_MARK)), None)
    try:
        routes = json.loads(line[len(_SESSION_MARK):]) if line else []
    except json.JSONDecodeError:
        return []
    seeds: list[str] = []
    for route in routes if isinstance(routes, list) else []:
        route = str(route)
        route = route.replace("^", "").replace("\\Z", "").replace("$", "")
        if not re.fullmatch(r"[A-Za-z0-9_./-]*", route) or SEED_SKIP.search(route):
            continue
        path = "/" + route.lstrip("/")
        if path not in seeds:
            seeds.append(path)
    return seeds[:300]
