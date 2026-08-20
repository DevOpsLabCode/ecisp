import time

import pytest

from app.orgscan.models import Finding
from app.registryscan import registry_scan_job
from app.registryscan.image_scanner import ScannerExecutionError, ScannerUnavailable


def _wait_for_terminal(manager, scan_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = manager.get(scan_id)
        if scan.status in ("completed", "failed"):
            return scan
        time.sleep(0.02)
    raise AssertionError("scan.status did not reach a terminal state in time")


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "REPORT_DIR", tmp_path / "registryscan-reports")
    mgr = registry_scan_job.RegistryScanManager()
    yield mgr
    mgr.shutdown()


def _fake_finding(severity="high"):
    return Finding(
        repository="node:14.0.0",
        file="node:14.0.0",
        scanner="trivy",
        rule_id="CVE-2020-27350",
        severity=severity,
        category="sca",
        message="m",
    )


def test_shutdown_stops_the_worker_thread(manager):
    assert manager._worker.is_alive()
    manager.shutdown()
    assert not manager._worker.is_alive()


def test_scan_completes_and_writes_reports(manager, monkeypatch):
    monkeypatch.setattr(
        registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [_fake_finding(), _fake_finding("critical")]
    )

    scan = manager.create("node:14.0.0")
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "completed"
    assert finished.image_ref == "node:14.0.0"
    assert len(finished.result.findings) == 2
    assert finished.result.scanners_run == ["trivy"]
    report_dir = finished._report_dir()
    assert (report_dir / "security-findings.sarif").exists()
    assert (report_dir / "security-report.html").exists()


def test_scan_passes_credentials_through_to_the_scanner(manager, monkeypatch):
    captured = {}

    def fake_scan(image_ref, username=None, password=None, registry_token=None, insecure=False):
        captured.update(
            image_ref=image_ref, username=username, password=password, registry_token=registry_token, insecure=insecure
        )
        return [_fake_finding()]

    monkeypatch.setattr(registry_scan_job, "run_registry_scan", fake_scan)

    scan = manager.create(
        "myregistry.jfrog.io/docker-local/app:1.0",
        username="deploy",
        password="s3cret",
        registry_token=None,
        insecure=True,
    )
    _wait_for_terminal(manager, scan.id)

    assert captured == {
        "image_ref": "myregistry.jfrog.io/docker-local/app:1.0",
        "username": "deploy",
        "password": "s3cret",
        "registry_token": None,
        "insecure": True,
    }


def test_scan_records_a_clean_failure_on_bad_credentials(manager, monkeypatch):
    def raising_scan(image_ref, **kw):
        raise ScannerExecutionError(f"could not scan '{image_ref}': DENIED: denied")

    monkeypatch.setattr(registry_scan_job, "run_registry_scan", raising_scan)

    scan = manager.create("private.example/secret:1.0", username="bad", password="wrong")
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "failed"
    assert "DENIED" in finished.error
    assert finished.result is None


def test_scan_records_a_clean_failure_when_trivy_missing(manager, monkeypatch):
    def raising_scan(image_ref, **kw):
        raise ScannerUnavailable("'trivy' is not installed")

    monkeypatch.setattr(registry_scan_job, "run_registry_scan", raising_scan)

    scan = manager.create("alpine:3.18")
    finished = _wait_for_terminal(manager, scan.id)

    assert finished.status == "failed"
    assert "not installed" in finished.error


def test_summary_and_detail_shapes(manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [_fake_finding()])

    scan = manager.create("alpine:3.18")
    finished = _wait_for_terminal(manager, scan.id)

    summary = finished.summary()
    assert summary["image_ref"] == "alpine:3.18"
    assert summary["finding_count"] == 1
    assert summary["severity_counts"]["high"] == 1
    detail = finished.detail()
    assert detail["scanners_run"] == ["trivy"]
    assert len(detail["findings"]) == 1


def test_summary_has_null_counts_before_completion():
    scan = registry_scan_job.RegistryScan("scan-1", "alpine:3.18")
    summary = scan.summary()
    assert summary["severity_counts"] is None
    assert summary["finding_count"] is None


def test_list_and_get(manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [])
    scan = manager.create("alpine:3.18")
    assert manager.get(scan.id) is scan
    assert scan in manager.list()


def test_get_returns_none_for_unknown_id(manager):
    assert manager.get("does-not-exist") is None
