"""Scanner process runner: one local binary, fixed argv, no shell.

Every scanner is a CLI in the guest's PATH. `start_new_session=True` makes the child a process-group
leader, so a timeout (or an oversized report) kills the whole tool tree with `os.killpg` instead of
leaving orphans behind. `docker_available()` is kept for the lab/analyst lane, which may still use
containers when a daemon is present.
"""

from __future__ import annotations

import asyncio
import os
import signal
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Output caps: stdout is the tool's report (bounded, refuse beyond); stderr keeps only its tail.
MAX_STDOUT_BYTES = 64 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
_CHUNK = 64 * 1024
# Grace between SIGTERM and SIGKILL when a tool has to be stopped.
KILL_GRACE_S = 3.0


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False  # stdout exceeded MAX_STDOUT_BYTES; the process group was killed

    @property
    def rc(self) -> int:
        return self.returncode

    @property
    def out(self) -> str:
        return self.stdout

    @property
    def err(self) -> str:
        return self.stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.truncated

    def tail(self, n: int = 800) -> str:
        return (self.stderr.strip() or self.stdout.strip())[-n:]


def docker_available() -> bool:
    """Whether the lab lane may use containers. TIRITH_NO_DOCKER=1 forces the native processes even
    when a docker CLI happens to be installed."""
    if os.environ.get("TIRITH_NO_DOCKER", "").strip().lower() in ("1", "true", "yes"):
        return False
    return shutil.which("docker") is not None


def run_local(argv: list[str], *, timeout: int = 300, input: str | None = None,
              cwd: Path | str | None = None) -> RunResult:
    """Run a fixed argv as a plain local process (no shell), in its own process group.

    The blocking twin of `run_process`, for callers that are already off the event loop: same
    group-kill on timeout, same output caps, same RunResult."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv, cwd=str(cwd) if cwd else None, start_new_session=True, text=True,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        return RunResult(127, "", f"{argv[0]} not found: {e}")
    try:
        out, err = proc.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group_sync(proc)
        out, err = proc.communicate()
        return RunResult(-1, (out or "")[:MAX_STDOUT_BYTES], f"timed out after {timeout}s", timed_out=True)
    if len(out) > MAX_STDOUT_BYTES:
        return RunResult(-1, out[:MAX_STDOUT_BYTES], f"output exceeded {MAX_STDOUT_BYTES} bytes", truncated=True)
    return RunResult(proc.returncode, out, err[-MAX_STDERR_BYTES:])


def _kill_group_sync(proc: subprocess.Popen) -> None:
    for sig, wait in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def missing_tools(names: tuple[str, ...]) -> list[str]:
    """CLI names from `names` that are not resolvable in PATH (for the health report)."""
    return [n for n in names if shutil.which(n) is None]


async def _read_capped(stream: asyncio.StreamReader, cap: int, keep_tail: bool) -> tuple[bytes, bool]:
    """Read until EOF. Over `cap`: keep the tail (keep_tail) or stop and report overflow."""
    buf = bytearray()
    while True:
        chunk = await stream.read(_CHUNK)
        if not chunk:
            return bytes(buf), False
        buf += chunk
        if len(buf) > cap:
            if keep_tail:
                del buf[: len(buf) - cap]
            else:
                return bytes(buf[:cap]), True


async def kill_group(proc: asyncio.subprocess.Process) -> None:
    """SIGTERM the whole group, SIGKILL after a grace period; safe when the group is already gone."""
    for sig, wait in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        except OSError:
            try:  # no process group of ours (e.g. session already reaped): fall back to the child
                proc.kill()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=wait)
            return
        except asyncio.TimeoutError:
            continue


async def _collect(proc: asyncio.subprocess.Process, cap: int) -> tuple[bytes, bool, bytes]:
    """out, over, err. Whatever stops the read (cap overflow, timeout, cancel) still tears the whole
    process group down and reaps it here, so the child can never outlive this coroutine."""
    out_t = asyncio.ensure_future(_read_capped(proc.stdout, cap, keep_tail=False))
    err_t = asyncio.ensure_future(_read_capped(proc.stderr, MAX_STDERR_BYTES, keep_tail=True))
    try:
        out, over = await out_t
        if over:
            await kill_group(proc)
        err, _ = await err_t
    finally:
        if proc.returncode is None:
            await kill_group(proc)
        await proc.wait()
        for t in (out_t, err_t):
            if not t.done():
                t.cancel()
    return out, over, err


async def run_process(
    argv: list[str],
    *,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 900,
    max_stdout: int = MAX_STDOUT_BYTES,
) -> RunResult:
    """Run `argv` (first element = binary name from PATH) in its own process group."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        start_new_session=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, over, err = await asyncio.wait_for(_collect(proc, max_stdout), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        if isinstance(e, asyncio.CancelledError):
            raise
        return RunResult(-1, "", f"timed out after {timeout}s", timed_out=True)
    if over:
        return RunResult(-1, "", f"output exceeded {max_stdout} bytes; process killed", truncated=True)
    return RunResult(proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace"))