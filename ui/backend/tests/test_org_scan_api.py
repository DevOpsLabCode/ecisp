import time

import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.orgscan import org_scan_job
from app.orgscan.github_client import GitHubAuthError
from app.orgscan.models import Finding, RepoScanResult

client = TestClient(app)


class _FakeVerifyClient:
    def __init__(self, token, verify_error=None):
        self.token = token
        self._verify_error = verify_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify(self):
        if self._verify_error:
            raise self._verify_error
        return {"login": "tester"}

    def list_org_repos(self, org, include_archived=False):
        return [{"full_name": "org/repo1", "default_branch": "main", "archived": False}]


@pytest.fixture
def isolated_manager(tmp_path, monkeypatch):
    monkeypatch.setattr(org_scan_job, "REPORT_DIR", tmp_path / "orgscan-reports")
    fresh = org_scan_job.OrgScanManager()
    monkeypatch.setattr(main, "org_scan_manager", fresh)
    yield fresh
    fresh.shutdown()


def _wait_for_terminal(scan_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/api/org-scans/{scan_id}")
        if resp.json()["status"] in ("completed", "failed"):
            return resp.json()
        time.sleep(0.02)
    raise AssertionError("scan did not finish in time")


def test_create_org_scan_rejects_bad_token(monkeypatch):
    monkeypatch.setattr(
        main, "GitHubClient", lambda token: _FakeVerifyClient(token, verify_error=GitHubAuthError("bad token"))
    )
    resp = client.post("/api/org-scans", json={"org": "my-org", "github_token": "bad"})
    assert resp.status_code == 400
    assert "bad token" in resp.json()["detail"]


def test_create_org_scan_rejects_blank_token_with_400_not_500():
    # Reproduced against the real (unmocked) GitHubClient: constructing it
    # with a blank token raises GitHubAuthError from __init__ itself, not
    # from verify() -- that exception has to be caught around the whole
    # `with GitHubClient(...)` block in main.py, not just around the
    # verify() call inside it, or it escapes as an unhandled 500.
    resp = client.post("/api/org-scans", json={"org": "my-org", "github_token": ""})
    assert resp.status_code == 400
    assert "token" in resp.json()["detail"].lower()


def test_create_org_scan_succeeds_and_queues(monkeypatch, isolated_manager):
    monkeypatch.setattr(main, "GitHubClient", lambda token: _FakeVerifyClient(token))
    monkeypatch.setattr(org_scan_job, "GitHubClient", lambda token: _FakeVerifyClient(token))

    resp = client.post("/api/org-scans", json={"org": "my-org", "github_token": "good-token", "create_issues": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["org"] == "my-org"
    assert "github_token" not in body  # the PAT must never be echoed back


def test_list_org_scans(monkeypatch, isolated_manager):
    monkeypatch.setattr(main, "GitHubClient", lambda token: _FakeVerifyClient(token))
    monkeypatch.setattr(org_scan_job, "GitHubClient", lambda token: _FakeVerifyClient(token))
    client.post("/api/org-scans", json={"org": "my-org", "github_token": "tok", "create_issues": False})

    resp = client.get("/api/org-scans")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_get_org_scan_404_for_unknown_id(isolated_manager):
    resp = client.get("/api/org-scans/does-not-exist")
    assert resp.status_code == 404


def test_get_org_scan_report_404_before_completion(monkeypatch, isolated_manager):
    # A scan that will hang in "running" forever (list_org_repos blocks) --
    # simulated by monkeypatching the manager to never advance past queued.
    monkeypatch.setattr(main, "GitHubClient", lambda token: _FakeVerifyClient(token))
    scan = org_scan_job.OrgScan("fake-id", "my-org", None, False, 1)
    isolated_manager._scans["fake-id"] = scan
    isolated_manager._order.insert(0, "fake-id")

    resp = client.get("/api/org-scans/fake-id/report.json")
    assert resp.status_code == 409


def test_get_org_scan_report_404_for_unknown_format(monkeypatch, isolated_manager):
    scan = org_scan_job.OrgScan("fake-id", "my-org", None, False, 1)
    scan.status = "completed"
    isolated_manager._scans["fake-id"] = scan
    isolated_manager._order.insert(0, "fake-id")

    resp = client.get("/api/org-scans/fake-id/report.docx")
    assert resp.status_code == 404


def test_get_org_scan_report_downloads_real_file(monkeypatch, isolated_manager):
    monkeypatch.setattr(main, "GitHubClient", lambda token: _FakeVerifyClient(token))
    monkeypatch.setattr(org_scan_job, "GitHubClient", lambda token: _FakeVerifyClient(token))
    fake_result = RepoScanResult(
        repository="org/repo1",
        technologies=["bandit"],
        scanners_run=["bandit"],
        scanners_skipped={},
        findings=[
            Finding(
                repository="org/repo1",
                file="a.py",
                line=1,
                scanner="bandit",
                rule_id="R1",
                severity="high",
                category="sast",
                message="m",
            )
        ],
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)
    monkeypatch.setattr(org_scan_job, "create_issues_for_scan", lambda gh, results, scan_date=None: {})

    resp = client.post("/api/org-scans", json={"org": "my-org", "github_token": "tok", "create_issues": False})
    scan_id = resp.json()["id"]
    _wait_for_terminal(scan_id)

    report_resp = client.get(f"/api/org-scans/{scan_id}/report.json")
    assert report_resp.status_code == 200
    assert report_resp.json()["organization"] == "my-org"

    sarif_resp = client.get(f"/api/org-scans/{scan_id}/report.sarif")
    assert sarif_resp.status_code == 200
    assert sarif_resp.headers["content-type"].startswith("application/sarif+json")
