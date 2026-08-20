import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from app.codescan import code_scan_job
from app.codescan.dast_scanner import DastExecutionError
from app.orgscan.github_client import GitHubAuthError
from app.orgscan.models import Finding, RepoScanResult


def _wait_for_terminal(manager, scan_id, timeout=5, attr="status"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = manager.get(scan_id)
        if getattr(scan, attr) in ("completed", "failed"):
            return scan
        time.sleep(0.02)
    raise AssertionError(f"scan.{attr} did not reach a terminal state in time")


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(code_scan_job, "REPORT_DIR", tmp_path / "codescan-reports")
    mgr = code_scan_job.CodeScanManager()
    yield mgr
    mgr.shutdown()


def _make_zip(tmp_path, entries: dict[str, bytes]) -> Path:
    archive = tmp_path / "upload.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return archive


class _FakeGitHubClient:
    def __init__(self, token, repo_info=None, branches=None, clone_fails=False):
        self.token = token
        self._repo_info = repo_info or {"private": False, "default_branch": "main"}
        self._branches = branches or ["main"]
        self._clone_fails = clone_fails

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_repo(self, owner, repo):
        return self._repo_info

    def list_branches(self, owner, repo):
        return self._branches

    def clone(self, owner, repo, default_branch=None):
        import tempfile

        @contextmanager
        def _cm():
            if self._clone_fails:
                raise RuntimeError("git clone failed")
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "app.py").write_text("print(1)\n")
                yield Path(d)

        return _cm()


def _fake_result(label="repo"):
    finding = Finding(
        repository=label,
        file="a.py",
        line=1,
        scanner="bandit",
        rule_id="R1",
        severity="high",
        category="sast",
        message="m",
    )
    return RepoScanResult(
        repository=label, technologies=["bandit"], scanners_run=["bandit"], scanners_skipped={}, findings=[finding]
    )


def test_shutdown_stops_the_worker_thread(manager):
    assert manager._worker.is_alive()
    manager.shutdown()
    assert not manager._worker.is_alive()


def test_upload_scan_completes_and_writes_reports(manager, tmp_path):
    # Deliberately exercises the real scanner registry (bandit/semgrep/
    # trivy all genuinely run against this fixture), unlike the other tests
    # here that mock scan internals -- a real integration check that the
    # extract -> scan_repo -> report pipeline works end to end, at the cost
    # of needing a longer timeout than the mocked tests do.
    archive = _make_zip(tmp_path, {"myproj/requirements.txt": b"flask\n", "myproj/app.py": b"print(1)\n"})
    scan = manager.create_from_upload(archive, "upload.zip")
    finished = _wait_for_terminal(manager, scan.id, timeout=60)

    assert finished.status == "completed"
    assert finished.source_type == "upload"
    assert finished.result is not None
    report_dir = finished._report_dir()
    assert (report_dir / "security-findings.sarif").exists()
    assert (report_dir / "security-report.html").exists()


def test_upload_scan_never_runs_build_dependent_scanners(manager, tmp_path):
    # pom.xml would normally trigger spotbugs -- for an uploaded archive it
    # must show up as an explicit skip instead, never actually run.
    archive = _make_zip(tmp_path, {"proj/pom.xml": b"<project></project>\n", "proj/App.java": b"class App {}\n"})
    scan = manager.create_from_upload(archive, "upload.zip")
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "completed"
    assert "spotbugs" not in finished.result.scanners_run
    assert "spotbugs" in finished.result.scanners_skipped
    assert "disabled for uploaded archives" in finished.result.scanners_skipped["spotbugs"]


def test_upload_scan_rejects_a_zip_slip_archive(manager, tmp_path):
    archive = _make_zip(tmp_path, {"../../../../tmp/pwned.txt": b"pwned"})
    scan = manager.create_from_upload(archive, "evil.zip")
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "failed"
    assert "Archive rejected" in finished.error
    assert finished.result is None


def test_upload_scan_deletes_the_uploaded_archive_after_processing(manager, tmp_path):
    archive = _make_zip(tmp_path, {"a.py": b"1"})
    scan = manager.create_from_upload(archive, "upload.zip")
    _wait_for_terminal(manager, scan.id)
    assert not archive.exists()


def test_repo_url_scan_completes_for_a_public_repo(manager, monkeypatch):
    monkeypatch.setattr(code_scan_job, "GitHubClient", lambda token: _FakeGitHubClient(token))
    monkeypatch.setattr(code_scan_job, "commit_sha", lambda repo_dir: "abc123")

    scan = manager.create_from_repo_url("https://github.com/octocat/Hello-World", branch=None, github_token=None)
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "completed"
    assert finished.source_type == "repo_url"
    assert finished.source_label == "octocat/Hello-World"
    assert finished.commit_sha == "abc123"


def test_repo_url_scan_fails_cleanly_for_a_private_repo_without_a_token(manager, monkeypatch):
    monkeypatch.setattr(
        code_scan_job,
        "GitHubClient",
        lambda token: _FakeGitHubClient(token, repo_info={"private": True, "default_branch": "main"}),
    )

    scan = manager.create_from_repo_url("https://github.com/org/private-repo", branch=None, github_token=None)
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "failed"
    assert "private" in finished.error
    assert "connect github" in finished.error.lower()


def test_repo_url_scan_succeeds_for_a_private_repo_with_a_token(manager, monkeypatch):
    monkeypatch.setattr(
        code_scan_job,
        "GitHubClient",
        lambda token: _FakeGitHubClient(token, repo_info={"private": True, "default_branch": "main"}),
    )
    monkeypatch.setattr(code_scan_job, "commit_sha", lambda repo_dir: "def456")

    scan = manager.create_from_repo_url(
        "https://github.com/org/private-repo", branch=None, github_token="gho_faketoken"
    )
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "completed"
    assert finished.commit_sha == "def456"


def test_repo_url_scan_uses_explicit_branch_when_given(manager, monkeypatch):
    captured = {}

    class _CapturingClient(_FakeGitHubClient):
        def clone(self, owner, repo, default_branch=None):
            captured["branch"] = default_branch
            return super().clone(owner, repo, default_branch)

    monkeypatch.setattr(code_scan_job, "GitHubClient", lambda token: _CapturingClient(token))
    monkeypatch.setattr(code_scan_job, "commit_sha", lambda repo_dir: "sha")

    scan = manager.create_from_repo_url("https://github.com/octocat/Hello-World", branch="develop", github_token=None)
    _wait_for_terminal(manager, scan.id)

    assert captured["branch"] == "develop"


def test_repo_url_scan_fails_cleanly_when_repo_not_found(manager, monkeypatch):
    class _RaisingClient(_FakeGitHubClient):
        def get_repo(self, owner, repo):
            raise GitHubAuthError(f"{owner}/{repo} not found")

    monkeypatch.setattr(code_scan_job, "GitHubClient", lambda token: _RaisingClient(token))

    scan = manager.create_from_repo_url("https://github.com/o/does-not-exist", branch=None, github_token=None)
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "failed"
    assert "not found" in finished.error


def test_dast_merges_findings_into_existing_scan_result(manager, monkeypatch):
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

    scan = code_scan_job.CodeScan("scan-1", "upload", "upload.zip")
    scan.result = _fake_result()
    scan.status = "completed"
    manager._scans["scan-1"] = scan
    manager._order.insert(0, "scan-1")

    manager.add_dast("scan-1", "http://target", spider_minutes=1, active_scan_minutes=1)
    finished = _wait_for_terminal(manager, "scan-1", attr="dast_status")

    assert finished.dast_status == "completed"
    assert any(f.scanner == "zap" for f in finished.result.findings)
    assert "zap" in finished.result.scanners_run


def test_dast_failure_is_recorded_without_touching_the_source_scan(manager, monkeypatch):
    def raising_dast(url, spider, active):
        raise DastExecutionError("zap blew up")

    monkeypatch.setattr(code_scan_job, "run_dast", raising_dast)

    scan = code_scan_job.CodeScan("scan-2", "upload", "upload.zip")
    scan.result = _fake_result()
    scan.status = "completed"
    manager._scans["scan-2"] = scan
    manager._order.insert(0, "scan-2")

    manager.add_dast("scan-2", "http://target", spider_minutes=1, active_scan_minutes=1)
    finished = _wait_for_terminal(manager, "scan-2", attr="dast_status")

    assert finished.dast_status == "failed"
    assert "zap blew up" in finished.dast_error
    assert len(finished.result.findings) == 1  # untouched


def test_summary_and_detail_shapes(manager, tmp_path):
    archive = _make_zip(tmp_path, {"myproj/requirements.txt": b"flask\n"})
    scan = manager.create_from_upload(archive, "upload.zip")
    finished = _wait_for_terminal(manager, scan.id)

    summary = finished.summary()
    assert summary["source_type"] == "upload"
    assert summary["dast_status"] == "not_run"
    detail = finished.detail()
    assert "findings" in detail
    assert "technologies" in detail


def test_list_and_get(manager, tmp_path):
    archive = _make_zip(tmp_path, {"a.py": b"1"})
    scan = manager.create_from_upload(archive, "upload.zip")
    assert manager.get(scan.id) is scan
    assert scan in manager.list()
