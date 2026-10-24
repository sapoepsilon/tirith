"""Fixed-argv subprocess helpers (no shell). Secrets are scrubbed from any captured output."""

from __future__ import annotations

import base64
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Result:
    rc: int
    out: str
    err: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    def tail(self, n: int = 800) -> str:
        s = (self.err.strip() or self.out.strip())
        return s[-n:]


def run(argv: list[str], *, cwd: Path | str | None = None, timeout: int = 300, env: dict | None = None,
        input: str | None = None, secrets: tuple[str, ...] = ()) -> Result:
    try:
        p = subprocess.run(argv, cwd=str(cwd) if cwd else None, capture_output=True, text=True,
                           timeout=timeout, env=env, input=input, errors="replace")
        r = Result(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired as e:
        r = Result(-1, (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                   f"timed out after {timeout}s", True)
    except FileNotFoundError as e:
        r = Result(127, "", f"{argv[0]} not found: {e}")
    for s in secrets:
        if s:
            r.out, r.err = r.out.replace(s, "***"), r.err.replace(s, "***")
    return r


# ----------------------------------------------------------------------------- git
def git_env(token: str | None) -> dict[str, str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/echo"}
    if token:
        # Token travels via env config, never argv/remote URL, so it never lands in ps, logs or .git/config.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        })
    return env


IDENT = ["-c", "user.name=Tirith", "-c", "user.email=tirith-bot@users.noreply.github.com", "-c", "commit.gpgsign=false"]


def git(args: list[str], cwd: Path | str | None = None, token: str | None = None, timeout: int = 300) -> Result:
    secrets = (token,) if token else ()
    if token:
        secrets += (base64.b64encode(f"x-access-token:{token}".encode()).decode(),)
    return run(["git", *IDENT, *args], cwd=cwd, timeout=timeout, env=git_env(token), secrets=secrets)


# ----------------------------------------------------------------------------- docker
def docker(args: list[str], timeout: int = 300, cwd: Path | str | None = None,
           input: str | None = None) -> Result:
    return run(["docker", *args], timeout=timeout, cwd=cwd, input=input)
