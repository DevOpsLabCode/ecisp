"""Thin GitHub REST API client (PAT auth) plus a `git clone` helper.

Deliberately not PyGithub -- org/repo discovery, issue search, and issue
creation are three simple REST calls, and a raw `httpx` client keeps the
dependency footprint small and every request's shape explicit.
"""
from __future__ import annotations

import subprocess  # nosec B404 -- used only for a fixed `git clone` invocation, see clone() below
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

API_BASE = "https://api.github.com"
_HEADERS_TEMPLATE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubAuthError(Exception):
    """The PAT is missing, malformed, or rejected by GitHub."""


class GitHubClient:
    def __init__(self, token: str, timeout: float = 30.0, transport: httpx.BaseTransport | None = None):
        if not token or not token.strip():
            raise GitHubAuthError("A GitHub personal access token is required")
        self._token = token.strip()
        self._client = httpx.Client(
            base_url=API_BASE,
            headers={**_HEADERS_TEMPLATE, "Authorization": f"Bearer {self._token}"},
            timeout=timeout,
            transport=transport,  # None uses httpx's real network transport; tests inject a MockTransport
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def verify(self) -> dict:
        """Confirms the PAT is valid and returns the authenticated user."""
        resp = self._client.get("/user")
        if resp.status_code == 401:
            raise GitHubAuthError("GitHub rejected this token (401 Unauthorized) -- check it hasn't expired")
        resp.raise_for_status()
        return resp.json()

    def _paginated(self, path: str, params: dict | None = None) -> Iterator[dict]:
        url = path
        query = {**(params or {}), "per_page": 100}
        while url:
            resp = self._client.get(url, params=query)
            if resp.status_code == 401:
                raise GitHubAuthError("GitHub rejected this token (401 Unauthorized)")
            if resp.status_code == 403:
                raise GitHubAuthError(
                    f"GitHub returned 403 for {path} -- the token likely lacks the required scope, "
                    "or the org enforces SSO authorization for this token"
                )
            resp.raise_for_status()
            yield from resp.json()
            url = resp.links.get("next", {}).get("url")
            query = None  # the "next" link already carries all query params

    def list_org_repos(self, org: str, include_archived: bool = False) -> list[dict]:
        # "Organization" in the everyday sense (the account/namespace to
        # scan) doesn't always mean a real GitHub Organization -- plenty of
        # small teams and this project's own account (DevOpsLabCode) are
        # personal User accounts. /orgs/{name}/repos 404s for those, so try
        # it first and fall back to /users/{name}/repos rather than forcing
        # the caller to know GitHub's internal account-type distinction.
        try:
            repos = list(self._paginated(f"/orgs/{org}/repos", {"type": "all"}))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            repos = list(self._paginated(f"/users/{org}/repos", {"type": "all"}))
        if not include_archived:
            repos = [r for r in repos if not r.get("archived")]
        return repos

    def find_open_issue_by_title(self, owner: str, repo: str, title: str) -> dict | None:
        for issue in self._paginated(
            f"/repos/{owner}/{repo}/issues",
            {"state": "open", "labels": "security,sast,automated"},
        ):
            if issue.get("title") == title and "pull_request" not in issue:
                return issue
        return None

    def create_issue(self, owner: str, repo: str, title: str, body: str, labels: list[str]) -> dict:
        resp = self._client.post(
            f"/repos/{owner}/{repo}/issues",
            json={"title": title, "body": body, "labels": labels},
        )
        resp.raise_for_status()
        return resp.json()

    @contextmanager
    def clone(self, owner: str, repo: str, default_branch: str | None = None):
        """Shallow-clones a repo into a temp dir using the PAT for auth,
        yielding the path, and always cleans up on exit."""
        clone_url = f"https://x-access-token:{self._token}@github.com/{owner}/{repo}.git"
        with tempfile.TemporaryDirectory(prefix="orgscan-") as tmp_dir:
            dest = Path(tmp_dir) / repo
            args = ["git", "clone", "--depth", "1", "--single-branch"]
            if default_branch:
                args += ["--branch", default_branch]
            args += [clone_url, str(dest)]
            # fixed git invocation, no shell=True -- owner/repo/PAT are
            # interpolated into argv entries, never shell-interpreted.
            proc = subprocess.run(args, capture_output=True, text=True, timeout=300, check=False)  # nosec B603
            if proc.returncode != 0:
                # The PAT is embedded in clone_url -- never let it leak into an
                # exception message that might end up in a log or the UI.
                safe_stderr = proc.stderr.replace(self._token, "<redacted>")
                raise RuntimeError(f"git clone failed for {owner}/{repo}: {safe_stderr[-1000:]}")
            # .resolve() matters on macOS: tempfile.TemporaryDirectory()
            # gives a /var/... path that's actually a symlink to
            # /private/var/..., and scanner subprocesses resolve it -- so
            # every SARIF/JSON artifact URI they emit is physical-path-based.
            # Yielding the unresolved logical path here makes every
            # os.path.relpath() downstream compute a bogus, symlink-crossing
            # "relative" path instead of the repo-relative one we want.
            yield dest.resolve()
