"""Minimal GitHub REST client for fix PRs. Token from TIRITH_GITHUB_TOKEN or `gh auth token`; never logged.

Every call is pinned to a repo that passed `core.check_pr_repo` (TIRITH_PR_REPOS allowlist AND
scope.yaml). PRs are created on that repo's own endpoint with a same-repo head branch, so they can
never target a fork's upstream parent.
"""

from __future__ import annotations

from typing import Any

import httpx

from . import core

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class PolicyError(GitHubError):
    pass


def _client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url=API, timeout=httpx.Timeout(30.0),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "tirith-remediation"},
    )


class GitHub:
    def __init__(self, repo: str, token: str | None = None):
        ok, reason = core.check_pr_repo(repo)
        if not ok:
            core.audit("github.denied", target=f"github_repo:{repo}", allowed=False, details={"reason": reason})
            core.emit("policy.denied", f"PR target {repo} denied: {reason}", level="warn", data={"repo": repo})
            raise PolicyError(f"PR target {repo} not allowed: {reason}")
        self.repo = repo
        self._token = token or core.github_token()
        if not self._token:
            raise GitHubError("no GitHub token (set TIRITH_GITHUB_TOKEN or run `gh auth login`)")

    @property
    def token(self) -> str:
        return self._token

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        try:
            with _client(self._token) as c:
                r = c.request(method, path, **kw)
        except httpx.HTTPError as e:  # network/timeout: surface as a GitHub failure (502), never a crash
            raise GitHubError(f"{method} {path} failed: {type(e).__name__}: {str(e).replace(self._token, '***')[:200]}") from None
        if r.status_code >= 400:
            msg = r.text[:400].replace(self._token, "***")
            raise GitHubError(f"{method} {path} -> HTTP {r.status_code}: {msg}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError:
            raise GitHubError(f"{method} {path} returned non-JSON (HTTP {r.status_code})") from None

    def repo_info(self) -> dict:
        d = self._req("GET", f"/repos/{self.repo}")
        if (d.get("full_name") or "").lower() != self.repo.lower():
            raise PolicyError(f"repo {self.repo} resolved to {d.get('full_name')} (renamed/redirected); refusing")
        return d

    def base_branch(self) -> str:
        return self.repo_info().get("default_branch") or "main"

    def open_pr(self, branch: str, base: str, title: str, body: str) -> dict:
        if ":" in branch:
            raise PolicyError("cross-repo head branches are not allowed")
        d = self._req("POST", f"/repos/{self.repo}/pulls", json={"title": title, "head": branch, "base": base, "body": body,
                                                                 "maintainer_can_modify": False})
        dest = ((d.get("base") or {}).get("repo") or {}).get("full_name", "")
        if dest.lower() != self.repo.lower():  # belt and braces: never leave a PR on another repo
            self._req("PATCH", f"/repos/{dest}/pulls/{d['number']}", json={"state": "closed"})
            raise PolicyError(f"PR landed on {dest}, expected {self.repo}; closed it")
        return d

    def get_pr(self, number: int) -> dict:
        return self._req("GET", f"/repos/{self.repo}/pulls/{number}")

    def merge_pr(self, number: int, title: str | None = None, sha: str | None = None) -> dict:
        """Merge only if the PR head is still `sha` (the commit Tirith verified); GitHub returns 409 otherwise."""
        body: dict[str, Any] = {"merge_method": "merge"}
        if sha:
            body["sha"] = sha
        if title:
            body["commit_title"] = title
        return self._req("PUT", f"/repos/{self.repo}/pulls/{number}/merge", json=body)

    def close_pr(self, number: int) -> dict:
        return self._req("PATCH", f"/repos/{self.repo}/pulls/{number}", json={"state": "closed"})

    def comment(self, number: int, body: str) -> dict:
        return self._req("POST", f"/repos/{self.repo}/issues/{number}/comments", json={"body": body})

    def delete_branch(self, branch: str) -> None:
        try:
            self._req("DELETE", f"/repos/{self.repo}/git/refs/heads/{branch}")
        except GitHubError:
            pass

    def clone_url(self) -> str:
        return f"https://github.com/{self.repo}.git"
