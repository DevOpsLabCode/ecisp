"""Thin GitHub REST API client (PAT or OAuth bearer token, or anonymous for
public repos) plus a `git clone` helper.

Deliberately not PyGithub -- org/repo discovery, issue search, and issue
creation are three simple REST calls, and a raw `httpx` client keeps the
dependency footprint small and every request's shape explicit.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404 -- used only for fixed `git` invocations, see clone()/commit_sha() below
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

_REPO_URL_RE = re.compile(
    r"^(?:(?:https?://)?(?:www\.)?|git@)github\.com[/:]([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?(?:[/#?].*)?$"
)


class GitHubAuthError(Exception):
    """The token is missing (for an operation that needs one), malformed, or rejected by GitHub."""


def parse_repo_url(url: str) -> tuple[str, str]:
    """Parses `owner/repo` out of any of the URL shapes a user might paste:
    `https://github.com/owner/repo`, with or without `.git`, a trailing
    slash, or extra path segments (`/tree/branch`, `/blob/...`)."""
    match = _REPO_URL_RE.match(url.strip())
    if not match:
        raise ValueError(f"Not a recognizable GitHub repository URL: {url!r}")
    return match.group(1), match.group(2)


class GitHubClient:
    def __init__(self, token: str | None, timeout: float = 30.0, transport: httpx.BaseTransport | None = None):
        # A token is only required for private-repo/write operations --
        # public-repo discovery, branch listing, and cloning all work
        # unauthenticated (subject to GitHub's lower anonymous rate limit),
        # which is exactly what use case 1's "public repo: scan directly,
        # no auth" requirement needs.
        self._token = (token or "").strip() or None
        headers = dict(_HEADERS_TEMPLATE)
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self._client = httpx.Client(
            base_url=API_BASE,
            headers=headers,
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
        """Confirms the token is valid and returns the authenticated user."""
        if not self._token:
            raise GitHubAuthError("No token to verify -- this client was constructed for anonymous access")
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

    def get_repo(self, owner: str, repo: str) -> dict:
        """Repo metadata -- notably `private` (whether this client's token,
        if any, needs read access) and `default_branch`."""
        resp = self._client.get(f"/repos/{owner}/{repo}")
        if resp.status_code == 404:
            raise GitHubAuthError(f"{owner}/{repo} not found (or private and this token can't see it)")
        resp.raise_for_status()
        return resp.json()

    def list_branches(self, owner: str, repo: str) -> list[str]:
        return [b["name"] for b in self._paginated(f"/repos/{owner}/{repo}/branches")]

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
        """Shallow-clones a repo into a temp dir, yielding the path and
        always cleaning up on exit. Uses the token for auth when this
        client has one; a public repo clones anonymously over plain
        https, no credentials embedded in the URL at all."""
        if self._token:
            clone_url = f"https://x-access-token:{self._token}@github.com/{owner}/{repo}.git"
        else:
            clone_url = f"https://github.com/{owner}/{repo}.git"
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
                # The token is embedded in clone_url when present -- never
                # let it leak into an exception message that might end up
                # in a log or the UI.
                safe_stderr = proc.stderr.replace(self._token, "<redacted>") if self._token else proc.stderr
                raise RuntimeError(f"git clone failed for {owner}/{repo}: {safe_stderr[-1000:]}")
            # .resolve() matters on macOS: tempfile.TemporaryDirectory()
            # gives a /var/... path that's actually a symlink to
            # /private/var/..., and scanner subprocesses resolve it -- so
            # every SARIF/JSON artifact URI they emit is physical-path-based.
            # Yielding the unresolved logical path here makes every
            # os.path.relpath() downstream compute a bogus, symlink-crossing
            # "relative" path instead of the repo-relative one we want.
            yield dest.resolve()


def commit_sha(repo_dir: Path) -> str:
    """The exact commit a `clone()`d directory is checked out at -- use
    case 2 requires recording this per scan, and a `--depth 1` shallow
    clone still has HEAD resolvable even though the rest of history isn't
    fetched."""
    proc = subprocess.run(  # nosec B603 B607 -- fixed git invocation against our own clone, no shell
        ["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True, timeout=30, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD failed: {proc.stderr[-500:]}")
    return proc.stdout.strip()
