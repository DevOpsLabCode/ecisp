import subprocess

import httpx
import pytest

from app.orgscan.github_client import GitHubAuthError, GitHubClient


def _client(handler) -> GitHubClient:
    return GitHubClient("fake-token", transport=httpx.MockTransport(handler))


def test_rejects_empty_token():
    with pytest.raises(GitHubAuthError):
        GitHubClient("")
    with pytest.raises(GitHubAuthError):
        GitHubClient("   ")


def test_verify_returns_user_on_success():
    def handler(request):
        assert request.headers["Authorization"] == "Bearer fake-token"
        return httpx.Response(200, json={"login": "someuser"})

    with _client(handler) as gh:
        assert gh.verify()["login"] == "someuser"


def test_verify_raises_auth_error_on_401():
    def handler(request):
        return httpx.Response(401, json={"message": "Bad credentials"})

    with _client(handler) as gh, pytest.raises(GitHubAuthError):
        gh.verify()


def test_list_org_repos_tries_orgs_endpoint_first():
    def handler(request):
        assert "/orgs/my-org/repos" in str(request.url)
        return httpx.Response(200, json=[{"full_name": "my-org/repo1", "archived": False}])

    with _client(handler) as gh:
        repos = gh.list_org_repos("my-org")
    assert len(repos) == 1


def test_list_org_repos_falls_back_to_users_endpoint_on_404():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if "/orgs/" in str(request.url):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=[{"full_name": "personal-account/repo1", "archived": False}])

    with _client(handler) as gh:
        repos = gh.list_org_repos("personal-account")
    assert len(repos) == 1
    assert any("/orgs/" in c for c in calls)
    assert any("/users/" in c for c in calls)


def test_list_org_repos_reraises_non_404_errors():
    def handler(request):
        return httpx.Response(500, json={"message": "server error"})

    with _client(handler) as gh, pytest.raises(httpx.HTTPStatusError):
        gh.list_org_repos("my-org")


def test_list_org_repos_filters_archived_by_default():
    def handler(request):
        return httpx.Response(
            200, json=[{"full_name": "org/active", "archived": False}, {"full_name": "org/old", "archived": True}]
        )

    with _client(handler) as gh:
        repos = gh.list_org_repos("org")
    assert [r["full_name"] for r in repos] == ["org/active"]


def test_list_org_repos_include_archived():
    def handler(request):
        return httpx.Response(
            200, json=[{"full_name": "org/active", "archived": False}, {"full_name": "org/old", "archived": True}]
        )

    with _client(handler) as gh:
        repos = gh.list_org_repos("org", include_archived=True)
    assert len(repos) == 2


def test_pagination_follows_link_header():
    def handler(request):
        if "page2marker" not in str(request.url):
            return httpx.Response(
                200,
                json=[{"full_name": "org/repo1", "archived": False}],
                headers={"Link": '<https://api.github.com/orgs/org/repos?page2marker=1>; rel="next"'},
            )
        return httpx.Response(200, json=[{"full_name": "org/repo2", "archived": False}])

    with _client(handler) as gh:
        repos = gh.list_org_repos("org")
    assert {r["full_name"] for r in repos} == {"org/repo1", "org/repo2"}


def test_403_raises_scoped_auth_error():
    def handler(request):
        return httpx.Response(403, json={"message": "Forbidden"})

    with _client(handler) as gh, pytest.raises(GitHubAuthError, match="403"):
        list(gh._paginated("/orgs/org/repos"))


def test_find_open_issue_by_title_match():
    def handler(request):
        return httpx.Response(
            200, json=[{"title": "[Security] SAST findings - repo - 2026-01-01", "html_url": "https://x/1"}]
        )

    with _client(handler) as gh:
        issue = gh.find_open_issue_by_title("org", "repo", "[Security] SAST findings - repo - 2026-01-01")
    assert issue["html_url"] == "https://x/1"


def test_find_open_issue_by_title_no_match():
    def handler(request):
        return httpx.Response(200, json=[{"title": "unrelated issue", "html_url": "https://x/1"}])

    with _client(handler) as gh:
        assert gh.find_open_issue_by_title("org", "repo", "[Security] SAST findings - repo - 2026-01-01") is None


def test_find_open_issue_ignores_pull_requests():
    def handler(request):
        return httpx.Response(200, json=[{"title": "match", "html_url": "https://x/1", "pull_request": {}}])

    with _client(handler) as gh:
        assert gh.find_open_issue_by_title("org", "repo", "match") is None


def test_create_issue_posts_expected_payload():
    captured = {}

    def handler(request):
        import json as _json

        captured["body"] = _json.loads(request.content)
        return httpx.Response(201, json={"html_url": "https://x/2"})

    with _client(handler) as gh:
        issue = gh.create_issue("org", "repo", "title", "body text", ["security"])
    assert issue["html_url"] == "https://x/2"
    assert captured["body"] == {"title": "title", "body": "body text", "labels": ["security"]}


def test_clone_yields_resolved_path(tmp_path, monkeypatch):
    def fake_run(args, capture_output, text, timeout, check):
        dest = args[-1]
        import pathlib

        pathlib.Path(dest).mkdir(parents=True)
        (pathlib.Path(dest) / "file.txt").write_text("hi")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with GitHubClient("fake-token") as gh, gh.clone("org", "repo") as repo_dir:
        assert repo_dir.is_absolute()
        assert (repo_dir / "file.txt").exists()
        assert repo_dir == repo_dir.resolve()


def test_clone_redacts_token_from_error_message(monkeypatch):
    def fake_run(args, capture_output, text, timeout, check):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="fatal: auth failed with token fake-token-xyz")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with GitHubClient("fake-token-xyz") as gh:
        with pytest.raises(RuntimeError) as exc_info, gh.clone("org", "repo"):
            pass
    assert "fake-token-xyz" not in str(exc_info.value)
    assert "<redacted>" in str(exc_info.value)
