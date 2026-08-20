import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import main
from app.codescan import code_scan_job, github_oauth
from app.codescan.github_oauth import OAuthError
from app.main import app

client = TestClient(app)


@pytest.fixture
def isolated_manager(tmp_path, monkeypatch):
    monkeypatch.setattr(code_scan_job, "REPORT_DIR", tmp_path / "codescan-reports")
    monkeypatch.setattr(code_scan_job, "UPLOAD_DIR", tmp_path / "codescan-uploads")
    fresh = code_scan_job.CodeScanManager()
    monkeypatch.setattr(main, "code_scan_manager", fresh)
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path / "codescan-uploads")
    yield fresh
    fresh.shutdown()


@pytest.fixture(autouse=True)
def _clear_oauth_stores():
    github_oauth.oauth_states._entries.clear()
    github_oauth.oauth_sessions._entries.clear()
    yield
    github_oauth.oauth_states._entries.clear()
    github_oauth.oauth_sessions._entries.clear()


def _wait_for_terminal(scan_id, timeout=60, attr="status"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/api/code-scans/{scan_id}")
        if resp.json()[attr] in ("completed", "failed"):
            return resp.json()
        time.sleep(0.05)
    raise AssertionError(f"scan.{attr} did not reach a terminal state in time")


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_upload_rejects_empty_file(isolated_manager):
    resp = client.post("/api/code-scans/upload", files={"file": ("empty.zip", b"", "application/zip")})
    assert resp.status_code == 400


def test_upload_rejects_oversized_file(isolated_manager, monkeypatch):
    monkeypatch.setattr(main, "MAX_CODE_UPLOAD_BYTES", 10)
    resp = client.post("/api/code-scans/upload", files={"file": ("big.zip", b"x" * 100, "application/zip")})
    assert resp.status_code == 413


def test_upload_queues_a_scan_and_completes(isolated_manager):
    archive = _zip_bytes({"myproj/requirements.txt": b"flask\n"})
    resp = client.post("/api/code-scans/upload", files={"file": ("myproj.zip", archive, "application/zip")})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_type"] == "upload"
    assert body["source_label"] == "myproj.zip"

    finished = _wait_for_terminal(body["id"])
    assert finished["status"] == "completed"


def test_upload_rejects_a_malicious_archive(isolated_manager):
    archive = _zip_bytes({"../../../../tmp/pwned.txt": b"pwned"})
    resp = client.post("/api/code-scans/upload", files={"file": ("evil.zip", archive, "application/zip")})
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    finished = _wait_for_terminal(scan_id)
    assert finished["status"] == "failed"
    assert "Archive rejected" in finished["error"]


def test_repo_scan_rejects_an_invalid_url(isolated_manager):
    resp = client.post("/api/code-scans/repo", json={"repo_url": "https://gitlab.com/o/r", "branch": None})
    assert resp.status_code == 400


def test_repo_scan_queues_and_completes_for_a_public_repo(isolated_manager, monkeypatch):
    class _FakeClient:
        def __init__(self, token):
            self.token = token

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get_repo(self, owner, repo):
            return {"private": False, "default_branch": "main"}

        def clone(self, owner, repo, default_branch=None):
            import tempfile
            from contextlib import contextmanager
            from pathlib import Path

            @contextmanager
            def _cm():
                with tempfile.TemporaryDirectory() as d:
                    (Path(d) / "app.py").write_text("print(1)\n")
                    yield Path(d)

            return _cm()

    monkeypatch.setattr(code_scan_job, "GitHubClient", _FakeClient)
    monkeypatch.setattr(code_scan_job, "commit_sha", lambda repo_dir: "abc123")

    resp = client.post("/api/code-scans/repo", json={"repo_url": "https://github.com/octocat/Hello-World"})
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    finished = _wait_for_terminal(scan_id)
    assert finished["status"] == "completed"
    assert finished["commit_sha"] == "abc123"


def test_list_and_get_code_scans(isolated_manager):
    archive = _zip_bytes({"a.py": b"1"})
    resp = client.post("/api/code-scans/upload", files={"file": ("a.zip", archive, "application/zip")})
    scan_id = resp.json()["id"]

    listing = client.get("/api/code-scans")
    assert listing.status_code == 200
    assert any(s["id"] == scan_id for s in listing.json())

    detail = client.get(f"/api/code-scans/{scan_id}")
    assert detail.status_code == 200
    assert "findings" in detail.json()


def test_get_code_scan_404_for_unknown_id(isolated_manager):
    resp = client.get("/api/code-scans/does-not-exist")
    assert resp.status_code == 404


def test_dast_returns_409_before_source_scan_completes(isolated_manager):
    scan = code_scan_job.CodeScan("scan-1", "upload", "a.zip")
    isolated_manager._scans["scan-1"] = scan
    isolated_manager._order.insert(0, "scan-1")

    resp = client.post("/api/code-scans/scan-1/dast", json={"target_url": "http://target"})
    assert resp.status_code == 409


def test_dast_404_for_unknown_scan(isolated_manager):
    resp = client.post("/api/code-scans/does-not-exist/dast", json={"target_url": "http://target"})
    assert resp.status_code == 404


def test_dast_triggers_when_source_scan_completed(isolated_manager, monkeypatch):
    from app.orgscan.models import Finding, RepoScanResult

    scan = code_scan_job.CodeScan("scan-1", "upload", "a.zip")
    scan.status = "completed"
    scan.result = RepoScanResult(repository="a.zip", technologies=[], scanners_run=[], scanners_skipped={}, findings=[])
    isolated_manager._scans["scan-1"] = scan
    isolated_manager._order.insert(0, "scan-1")

    dast_finding = Finding(
        repository="http://target",
        file="http://target",
        scanner="zap",
        rule_id="10020",
        severity="medium",
        category="dast",
        message="m",
    )
    monkeypatch.setattr(code_scan_job, "run_dast", lambda url, spider, active: [dast_finding])

    resp = client.post("/api/code-scans/scan-1/dast", json={"target_url": "http://target"})
    assert resp.status_code == 200

    deadline = time.time() + 5
    while time.time() < deadline and isolated_manager.get("scan-1").dast_status == "running":
        time.sleep(0.02)
    assert isolated_manager.get("scan-1").dast_status == "completed"


def test_report_download_404_before_completion(isolated_manager):
    scan = code_scan_job.CodeScan("scan-1", "upload", "a.zip")
    isolated_manager._scans["scan-1"] = scan
    isolated_manager._order.insert(0, "scan-1")

    resp = client.get("/api/code-scans/scan-1/report.json")
    assert resp.status_code == 409


def test_report_download_succeeds_for_completed_scan(isolated_manager):
    archive = _zip_bytes({"a.py": b"1"})
    resp = client.post("/api/code-scans/upload", files={"file": ("a.zip", archive, "application/zip")})
    scan_id = resp.json()["id"]
    _wait_for_terminal(scan_id)

    report_resp = client.get(f"/api/code-scans/{scan_id}/report.sarif")
    assert report_resp.status_code == 200
    assert report_resp.headers["content-type"].startswith("application/sarif+json")


# --- OAuth ---


def test_oauth_login_returns_500_when_not_configured(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    resp = client.get("/api/github/oauth/login", follow_redirects=False)
    assert resp.status_code == 500


def test_oauth_login_redirects_when_configured(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "test-client-id")
    resp = client.get("/api/github/oauth/login", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert "github.com/login/oauth/authorize" in resp.headers["location"]
    assert "client_id=test-client-id" in resp.headers["location"]


def test_oauth_callback_rejects_invalid_state():
    resp = client.get("/api/github/oauth/callback?code=abc&state=nonexistent", follow_redirects=False)
    assert resp.status_code == 400


def test_oauth_callback_sets_session_cookie_on_success(monkeypatch):
    state = github_oauth.oauth_states.create("pending")
    monkeypatch.setattr(github_oauth, "exchange_code", lambda code, redirect_uri: "gho_realtoken")

    resp = client.get(f"/api/github/oauth/callback?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.cookies.get(github_oauth.SESSION_COOKIE_NAME) is not None


def test_oauth_callback_400_on_exchange_failure(monkeypatch):
    state = github_oauth.oauth_states.create("pending")

    def raising_exchange(code, redirect_uri):
        raise OAuthError("bad code")

    monkeypatch.setattr(github_oauth, "exchange_code", raising_exchange)
    resp = client.get(f"/api/github/oauth/callback?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code == 400


def test_oauth_status_reflects_no_session():
    resp = client.get("/api/github/oauth/status")
    assert resp.status_code == 200
    assert resp.json()["connected"] is False


def test_oauth_status_reflects_active_session(monkeypatch):
    state = github_oauth.oauth_states.create("pending")
    monkeypatch.setattr(github_oauth, "exchange_code", lambda code, redirect_uri: "gho_realtoken")
    callback_resp = client.get(f"/api/github/oauth/callback?code=abc&state={state}", follow_redirects=False)
    session_cookie = callback_resp.cookies.get(github_oauth.SESSION_COOKIE_NAME)

    client.cookies.set(github_oauth.SESSION_COOKIE_NAME, session_cookie)
    status_resp = client.get("/api/github/oauth/status")
    client.cookies.clear()
    assert status_resp.json()["connected"] is True


def test_oauth_logout_clears_session(monkeypatch):
    state = github_oauth.oauth_states.create("pending")
    monkeypatch.setattr(github_oauth, "exchange_code", lambda code, redirect_uri: "gho_realtoken")
    callback_resp = client.get(f"/api/github/oauth/callback?code=abc&state={state}", follow_redirects=False)
    session_cookie = callback_resp.cookies.get(github_oauth.SESSION_COOKIE_NAME)

    client.cookies.set(github_oauth.SESSION_COOKIE_NAME, session_cookie)
    client.post("/api/github/oauth/logout")
    status_resp = client.get("/api/github/oauth/status")
    client.cookies.clear()
    assert status_resp.json()["connected"] is False


def test_branches_endpoint_returns_branch_list(isolated_manager, monkeypatch):
    class _FakeClient:
        def __init__(self, token):
            self.token = token

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get_repo(self, owner, repo):
            return {"private": False, "default_branch": "main"}

        def list_branches(self, owner, repo):
            return ["main", "develop"]

    monkeypatch.setattr(main, "GitHubClient", _FakeClient)
    resp = client.get("/api/code-scans/branches", params={"repo_url": "https://github.com/octocat/Hello-World"})
    assert resp.status_code == 200
    assert resp.json()["branches"] == ["main", "develop"]
    assert resp.json()["private"] is False


def test_branches_endpoint_rejects_invalid_url(isolated_manager):
    resp = client.get("/api/code-scans/branches", params={"repo_url": "not-a-url"})
    assert resp.status_code == 400
