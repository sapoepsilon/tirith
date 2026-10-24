"""Local lab copies: run an app natively in this guest, on its own loopback port.

Two launchers, one shape:

  - `LocalCopy.start()` -- the tracked, bounded copy. With a container runtime it is
    `docker run -d --network host` (the app binds the guest loopback directly, so the client and
    the destination use the same `127.0.0.1:<port>` string); without one it is a plain
    `subprocess.Popen` in its own session, with the source directory bind-mounted into the
    guest (`podman` keeps the mount for the fallback; it is not required).
  - `detached()` -- the owned, demo-only copy booted once (the analyst-lab target): a host-network
    container when possible, else a native process started in its own session that outlives the
    boot call and is killed by PID at reset.

Every launcher owns exactly one thing: a teardown that leaves nothing behind (container removed by
name, or the process group killed and reaped). `available()` decides nothing else -- the caller
reports which mode it got.

Env: TIRITH_CHROMIUM_BIN is not used here; TIRITH_LAB_PYTHON (default `sys.executable`) is the
interpreter a native demo copy boots with.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..scanners.docker import docker_available
from ..remediation.sh import Result, docker

log = logging.getLogger("tirith.copies")

BOOT_TIMEOUT = int(os.environ.get("TIRITH_LAB_BOOT_TIMEOUT", "120"))
_STOP_GRACE = 5.0
LOG_DIR = Path(tempfile.gettempdir())
LOG_TAIL = 4000
# Ports a copy may bind. Kept off the app's usual 8000/8080 so a running Tirith is never masked.
PORT_RANGE = (18000, 18999)


class CopyError(RuntimeError):
    """A copy could not be started or did not answer."""


def _bindable(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError:
            return False
    return True


def free_port(host: str = "127.0.0.1") -> int:
    """A loopback port that is free right now (bind test). Racy by nature; callers treat bind failure
    as a normal boot failure and the next attempt picks another port."""
    lo, hi = PORT_RANGE
    for _ in range(200):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            port = s.getsockname()[1]
        if lo <= port <= hi and _bindable(host, port):
            return port
    for port in range(lo, hi + 1):
        if _bindable(host, port):
            return port
    raise CopyError(f"no free loopback port in {lo}-{hi}")


def waits(host: str, port: int, seconds: float = 1.0) -> bool:
    """Does something accept a TCP connect on `host:port`?"""
    try:
        with socket.create_connection((host, port), timeout=seconds):
            return True
    except OSError:
        return False


def available() -> str | None:
    """The container runtime a host-mode copy can use, or None for the native fallback."""
    if docker_available():
        return "docker"
    return None


def status(rc: int) -> str:
    return {0: "exited cleanly", -signal.SIGTERM: "stopped (SIGTERM)", -signal.SIGKILL: "killed (SIGKILL)"}.get(
        rc, f"exit {rc}")


# ----------------------------------------------------------------------------- native process
@dataclass
class NativeApp:
    """An app process in its own session. `stop()` kills the whole group and reaps it."""

    argv: list[str]
    cwd: Path
    env: dict[str, str]
    proc: subprocess.Popen | None = field(default=None, repr=False)
    log_path: Path | None = field(default=None, repr=False)

    def start(self) -> "NativeApp":
        self.cwd.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix="tirith-copy-", suffix=".log")
        self.log_path = Path(path)
        try:
            self.proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                self.argv, cwd=str(self.cwd), env=self.env, stdin=subprocess.DEVNULL,
                stdout=fd, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except FileNotFoundError as e:
            raise CopyError(f"{self.argv[0]} not found: {e}") from e
        finally:
            os.close(fd)
        return self

    def poll(self) -> int | None:
        return self.proc.poll() if self.proc else None

    def logs(self, n: int = LOG_TAIL) -> str:
        try:
            return (self.log_path.read_text(errors="replace") if self.log_path else "")[-n:]
        except OSError:
            return ""

    def stop(self) -> None:
        p = self.proc
        if p is None or p.poll() is not None:
            if self.log_path:
                self.log_path.unlink(missing_ok=True)
                self.log_path = None
            return
        for sig, wait in ((signal.SIGTERM, _STOP_GRACE), (signal.SIGKILL, 5.0)):
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                break
            try:
                p.wait(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                continue
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log.warning("copy process %s survived SIGKILL", p.pid)
        self.proc = None
        if self.log_path:
            self.log_path.unlink(missing_ok=True)
            self.log_path = None


# ----------------------------------------------------------------------------- host-mode container
@dataclass
class HostContainer:
    """A `docker run -d --network host` copy. `stop()` removes it by name."""

    name: str
    image: str
    extra: list[str] = field(default_factory=list)  # argv after the image (exposed port, command)


def run_container(image: str, *, name: str, ports: list[int] | None = None, labels: dict[str, str] | None = None,
                  env: dict[str, str] | None = None, command: list[str] | None = None) -> Result:
    args = ["run", "-d", "--name", name, "--hostname", name, "--network", "host",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL", "--memory", "512m", "--pids-limit", "256"]
    for k, v in (labels or {}).items():
        args += ["--label", f"{k}={v}"]
    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]
    args.append(image)
    for p in ports or []:
        args += ["-p", str(p)]
    args += list(command or [])
    return docker(args, timeout=90)


def logs_container(name: str, n: int = 120) -> str:
    r = docker(["logs", "--tail", str(n), name], timeout=30)
    return (r.out + r.err).strip()


def remove_container(name: str) -> None:
    docker(["rm", "-f", name], timeout=60)


def container_running(name: str) -> bool:
    r = docker(["inspect", name, "--format", "{{.State.Running}}"], timeout=15)
    return r.ok and r.out.strip() == "true"


# ----------------------------------------------------------------------------- one shared copy
@dataclass
class LocalCopy:
    """Reserve + start a copy of `src` for one asset. `port` is fixed before the start so the URL is
    known first; start() picks the mode and launches."""

    src: Path
    label: str
    ports: list[int]
    image: str | None = None
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    kind: str = ""  # "docker" | "native" | "injected"
    detail: str = ""  # why the fallback was taken (reported, never silently dropped)
    stop_fn: object = None
    extra: list[str] = field(default_factory=list)
    host: str = "127.0.0.1"

    @property
    def name(self) -> str:
        slug = "".join(c if c.isalnum() else "-" for c in self.label.lower()).strip("-")[:24] or "copy"
        return f"tirith-lab-{slug}-{os.urandom(3).hex()}"

    def stop(self) -> None:
        fn = self.stop_fn
        self.stop_fn = None
        if callable(fn):
            try:
                fn()
            except Exception:  # noqa: BLE001 - teardown never raises
                log.exception("copy teardown failed for %s", self.name)

    def start(self) -> "LocalCopy":
        family = available()
        if family == "docker" and self.image:
            r = run_container(self.image, name=self.name, ports=self.ports, command=self.extra or None)
            if r.ok:
                self.kind = "docker"
                self.stop_fn = lambda: remove_container(self.name)
                return self
            self.detail = f"host container did not start ({r.tail(300)}); ran it as a local process"
            remove_container(self.name)  # a half-created container would keep the name
        if not self.argv:
            raise CopyError(f"no way to run {self.src}: no container runtime and no command")
        self.kind = "native"
        if not self.detail:
            self.detail = "no container runtime: native process"
        app = NativeApp(self.argv, self.src, {**os.environ, **self.env}).start()
        self.stop_fn = app.stop
        self.app = app
        port = self.ports[-1] if self.ports else 0
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            rc = app.poll()
            if rc is not None and not (port and waits(self.host, port, 0.2)):
                raise CopyError(f"copy exited during boot: {status(rc)}\n{app.logs(1200)}")
            if port and waits(self.host, port, 0.5):
                return self
            time.sleep(0.4)
        raise CopyError(f"copy did not answer on {self.host}:{port}\n{app.logs(1200)}")

    def logs(self, n: int = LOG_TAIL) -> str:
        if self.kind == "native":
            return self.app.logs(n)
        return logs_container(self.name, n)

    def alive(self) -> bool:
        if self.kind == "native":
            return self.app.poll() is None
        if self.kind == "docker":
            return container_running(self.name)
        return True


# ----------------------------------------------------------------------------- detached demo copy
@dataclass
class Detached:
    """An owned copy whose lifetime is a PID (native) or a container name, not this call."""

    pid: int | None = None
    container: str = ""
    port: int = 0
    log_path: Path | None = None

    @property
    def mode(self) -> str:
        return "docker" if self.container else "process"

    def stop(self) -> None:
        if self.container:
            remove_container(self.container)
            self.container = ""
        if self.pid:
            try:
                os.killpg(self.pid, signal.SIGTERM)
                deadline = time.monotonic() + _STOP_GRACE
                while time.monotonic() < deadline and _pid_alive(self.pid):
                    time.sleep(0.2)
                if _pid_alive(self.pid):
                    os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.pid = None

    def tail(self, n: int = LOG_TAIL) -> str:
        if self.container:
            return logs_container(self.container, 120)[-n:]
        try:
            return (self.log_path.read_text(errors="replace") if self.log_path else "")[-n:]
        except OSError:
            return ""


def pid_alive(pid: int) -> bool:
    """Is the process group `pid` still there?"""
    return bool(pid) and _pid_alive(pid)


def _pid_alive(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def spawn_detached(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> Detached:
    """Start `argv` in its own session with stdout/stderr on a kept log file; the caller stores the PID."""
    cwd.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="tirith-demo-", suffix=".log", dir=str(LOG_DIR))
    try:
        p = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv, cwd=str(cwd), env={**os.environ, **(env or {})}, stdin=subprocess.DEVNULL,
            stdout=fd, stderr=subprocess.STDOUT, start_new_session=True,
        )
    except FileNotFoundError as e:
        os.close(fd)
        Path(path).unlink(missing_ok=True)
        raise CopyError(f"{argv[0]} not found: {e}") from e
    os.close(fd)
    return Detached(pid=p.pid, log_path=Path(path))


def start_log(pid: int, n: int = LOG_TAIL) -> str:
    """Tail of a detached process' log file (`spawn_detached` keeps it at /tmp/tirith-demo-<pid>.log)."""
    path = LOG_DIR / f"tirith-demo-{pid}.log"
    try:
        return path.read_text(errors="replace")[-n:]
    except OSError:
        return ""


def stop_pid(pid: int) -> None:
    """Stop a detached process group by pid (SIGTERM, then SIGKILL)."""
    if not pid:
        return
    for sig, wait in ((signal.SIGTERM, _STOP_GRACE), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):  # gone, or not (yet) ours to signal
            return
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and _pid_alive(pid):
            time.sleep(0.2)
        if not _pid_alive(pid):
            return


def wait_http(host: str, port: int, timeout: float = BOOT_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if waits(host, port, 0.5):
            return True
        time.sleep(0.4)
    return False