import json
import time

import pytest

from app.orgscan import org_scan_job
from app.orgscan.github_client import GitHubAuthError
from app.orgscan.models import Finding, RepoScanResult


class _FakeGitHubClient:
    def __init__(self, token, repos=None, verify_error=None):
        self.token = token
        self._repos = (
            repos if repos is not None else [{"full_name": "org/repo1", "default_branch": "main", "archived": False}]
        )
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
        return self._repos


def _make_fake_client_factory(**kwargs):
    def factory(token):
        return _FakeGitHubClient(token, **kwargs)

    return factory


def _wait_for_terminal_status(manager, scan_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = manager.get(scan_id)
        if scan.status in ("completed", "failed"):
            return scan
        time.sleep(0.02)
    raise AssertionError("scan did not reach a terminal status in time")


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(org_scan_job, "REPORT_DIR", tmp_path / "orgscan-reports")
    mgr = org_scan_job.OrgScanManager()
    yield mgr
    mgr.shutdown()


def test_shutdown_stops_the_worker_thread(manager):
    assert manager._worker.is_alive()
    manager.shutdown()
    assert not manager._worker.is_alive()


def test_create_returns_queued_scan_immediately(manager, monkeypatch):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())
    scan = manager.create(org="my-org", token="tok")
    assert scan.status in ("queued", "running", "completed")  # worker may already be racing
    assert manager.get(scan.id) is scan
    assert scan in manager.list()


def test_execute_completes_and_writes_reports(manager, monkeypatch, tmp_path):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())

    finding = Finding(
        repository="org/repo1",
        file="a.py",
        line=1,
        scanner="bandit",
        rule_id="R1",
        severity="high",
        category="sast",
        message="m",
    )
    fake_result = RepoScanResult(
        repository="org/repo1",
        technologies=["bandit"],
        scanners_run=["bandit"],
        scanners_skipped={},
        findings=[finding],
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)
    monkeypatch.setattr(org_scan_job, "create_issues_for_scan", lambda gh, results, scan_date=None: {})

    scan = manager.create(org="my-org", token="tok", notify_email=None, create_issues=False)
    finished = _wait_for_terminal_status(manager, scan.id)

    assert finished.status == "completed"
    assert finished.total_repos == 1
    assert finished.completed_repos == 1
    assert finished.repo_results[0].repository == "org/repo1"

    report_dir = (tmp_path / "orgscan-reports") / scan.id
    assert (report_dir / "security-findings.sarif").exists()
    assert (report_dir / "security-findings.json").exists()
    assert (report_dir / "security-findings.csv").exists()
    assert (report_dir / "security-report.html").exists()

    doc = json.loads((report_dir / "security-findings.json").read_text())
    assert doc["organization"] == "my-org"


def test_execute_fails_scan_on_bad_token(manager, monkeypatch):
    monkeypatch.setattr(
        org_scan_job, "GitHubClient", _make_fake_client_factory(verify_error=GitHubAuthError("bad token"))
    )

    scan = manager.create(org="my-org", token="bad-tok")
    finished = _wait_for_terminal_status(manager, scan.id)

    assert finished.status == "failed"
    assert "bad token" in finished.error


def test_execute_creates_issues_when_enabled(manager, monkeypatch):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())
    fake_result = RepoScanResult(
        repository="org/repo1", technologies=[], scanners_run=[], scanners_skipped={}, findings=[]
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)

    captured = {}

    def fake_create_issues(gh, results, scan_date=None):
        captured["called"] = True
        return {"org/repo1": {"action": "created", "issue_url": "https://x/1"}}

    monkeypatch.setattr(org_scan_job, "create_issues_for_scan", fake_create_issues)

    scan = manager.create(org="my-org", token="tok", create_issues=True)
    finished = _wait_for_terminal_status(manager, scan.id)

    assert captured.get("called") is True
    assert finished.issue_outcomes["org/repo1"]["action"] == "created"
    assert finished.summary()["issues_created"] == 1


def test_execute_sends_email_when_notify_address_given(manager, monkeypatch):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())
    fake_result = RepoScanResult(
        repository="org/repo1", technologies=[], scanners_run=[], scanners_skipped={}, findings=[]
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)
    monkeypatch.setattr(org_scan_job, "create_issues_for_scan", lambda gh, results, scan_date=None: {})

    sent_to = {}

    def fake_send_report(to_address, org, results, status, attachments):
        sent_to["address"] = to_address
        sent_to["attachment_count"] = len(attachments)
        return True

    monkeypatch.setattr(org_scan_job.email_report, "send_report", fake_send_report)

    scan = manager.create(org="my-org", token="tok", notify_email="security@example.com", create_issues=False)
    finished = _wait_for_terminal_status(manager, scan.id)

    assert finished.email_sent is True
    assert sent_to["address"] == "security@example.com"
    assert sent_to["attachment_count"] >= 4


def test_execute_email_failure_does_not_fail_the_scan(manager, monkeypatch):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())
    fake_result = RepoScanResult(
        repository="org/repo1", technologies=[], scanners_run=[], scanners_skipped={}, findings=[]
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)
    monkeypatch.setattr(org_scan_job, "create_issues_for_scan", lambda gh, results, scan_date=None: {})

    def failing_send_report(*args, **kwargs):
        raise RuntimeError("smtp down")

    monkeypatch.setattr(org_scan_job.email_report, "send_report", failing_send_report)

    scan = manager.create(org="my-org", token="tok", notify_email="security@example.com", create_issues=False)
    finished = _wait_for_terminal_status(manager, scan.id)

    assert finished.status == "completed"
    assert finished.email_sent is False


def test_one_repo_failing_to_clone_does_not_abort_the_scan(manager, monkeypatch):
    # Deliberately does NOT mock _scan_one_repo, so the real function runs
    # against _FakeGitHubClient -- which has no .clone() method, so calling
    # it raises AttributeError. _scan_one_repo's own broad except should
    # turn that into a RepoScanResult(error=...) instead of propagating and
    # aborting the whole org scan.
    monkeypatch.setattr(
        org_scan_job,
        "GitHubClient",
        _make_fake_client_factory(repos=[{"full_name": "org/broken", "default_branch": "main"}]),
    )

    scan = manager.create(org="my-org", token="tok", create_issues=False)
    finished = _wait_for_terminal_status(manager, scan.id)

    assert finished.status == "completed"
    assert finished.repo_results[0].error is not None


def test_summary_and_detail_shapes(manager, monkeypatch):
    monkeypatch.setattr(org_scan_job, "GitHubClient", _make_fake_client_factory())
    finding = Finding(
        repository="org/repo1",
        file="a.py",
        line=1,
        scanner="bandit",
        rule_id="R1",
        severity="critical",
        category="sast",
        message="m",
    )
    fake_result = RepoScanResult(
        repository="org/repo1",
        technologies=["bandit"],
        scanners_run=["bandit"],
        scanners_skipped={"gosec": "n/a"},
        findings=[finding],
    )
    monkeypatch.setattr(org_scan_job, "_scan_one_repo", lambda gh, repo: fake_result)
    monkeypatch.setattr(
        org_scan_job,
        "create_issues_for_scan",
        lambda gh, results, scan_date=None: {"org/repo1": {"action": "created", "issue_url": "https://x/1"}},
    )

    scan = manager.create(org="my-org", token="tok", create_issues=True)
    finished = _wait_for_terminal_status(manager, scan.id)

    summary = finished.summary()
    assert summary["severity_totals"]["critical"] == 1
    detail = finished.detail()
    assert detail["repositories"][0]["issue"]["action"] == "created"
    assert detail["repositories"][0]["scanners_skipped"] == {"gosec": "n/a"}
