import time

import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app
from app.orgscan.models import Finding
from app.registryscan import registry_scan_job

client = TestClient(app)


@pytest.fixture
def isolated_manager(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "REPORT_DIR", tmp_path / "registryscan-reports")
    fresh = registry_scan_job.RegistryScanManager()
    monkeypatch.setattr(main, "registry_scan_manager", fresh)
    yield fresh
    fresh.shutdown()


def _wait_for_terminal(scan_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/api/registry-scans/{scan_id}")
        if resp.json()["status"] in ("completed", "failed"):
            return resp.json()
        time.sleep(0.02)
    raise AssertionError("scan.status did not reach a terminal state in time")


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


def test_create_scan_rejects_an_empty_image_ref(isolated_manager):
    resp = client.post("/api/registry-scans", json={"image_ref": "  "})
    assert resp.status_code == 400


def test_create_scan_queues_and_completes(isolated_manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [_fake_finding()])

    resp = client.post("/api/registry-scans", json={"image_ref": "node:14.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["image_ref"] == "node:14.0.0"

    finished = _wait_for_terminal(body["id"])
    assert finished["status"] == "completed"
    assert finished["finding_count"] == 1


def test_create_scan_passes_credentials_to_the_scanner(isolated_manager, monkeypatch):
    captured = {}

    def fake_scan(image_ref, username=None, password=None, registry_token=None, insecure=False):
        captured.update(username=username, password=password, registry_token=registry_token, insecure=insecure)
        return [_fake_finding()]

    monkeypatch.setattr(registry_scan_job, "run_registry_scan", fake_scan)

    resp = client.post(
        "/api/registry-scans",
        json={
            "image_ref": "myregistry.jfrog.io/docker-local/app:1.0",
            "username": "deploy",
            "password": "s3cret",
            "insecure": True,
        },
    )
    scan_id = resp.json()["id"]
    _wait_for_terminal(scan_id)

    assert captured["username"] == "deploy"
    assert captured["password"] == "s3cret"
    assert captured["insecure"] is True


def test_create_scan_records_a_clean_failure(isolated_manager, monkeypatch):
    from app.registryscan.image_scanner import ScannerExecutionError

    def raising_scan(image_ref, **kw):
        raise ScannerExecutionError(f"could not scan '{image_ref}': DENIED: denied")

    monkeypatch.setattr(registry_scan_job, "run_registry_scan", raising_scan)

    resp = client.post("/api/registry-scans", json={"image_ref": "private.example/secret:1.0"})
    scan_id = resp.json()["id"]
    finished = _wait_for_terminal(scan_id)

    assert finished["status"] == "failed"
    assert "DENIED" in finished["error"]


def test_list_and_get_registry_scans(isolated_manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [])
    resp = client.post("/api/registry-scans", json={"image_ref": "alpine:3.18"})
    scan_id = resp.json()["id"]

    listing = client.get("/api/registry-scans")
    assert listing.status_code == 200
    assert any(s["id"] == scan_id for s in listing.json())

    detail = client.get(f"/api/registry-scans/{scan_id}")
    assert detail.status_code == 200
    assert "findings" in detail.json()


def test_get_registry_scan_404_for_unknown_id(isolated_manager):
    resp = client.get("/api/registry-scans/does-not-exist")
    assert resp.status_code == 404


def test_report_download_409_before_completion(isolated_manager):
    scan = registry_scan_job.RegistryScan("scan-1", "alpine:3.18")
    isolated_manager._scans["scan-1"] = scan
    isolated_manager._order.insert(0, "scan-1")

    resp = client.get("/api/registry-scans/scan-1/report.json")
    assert resp.status_code == 409


def test_report_download_404_for_unknown_scan(isolated_manager):
    resp = client.get("/api/registry-scans/does-not-exist/report.json")
    assert resp.status_code == 404


def test_report_download_succeeds_for_a_completed_scan(isolated_manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [_fake_finding()])

    resp = client.post("/api/registry-scans", json={"image_ref": "alpine:3.18"})
    scan_id = resp.json()["id"]
    _wait_for_terminal(scan_id)

    report_resp = client.get(f"/api/registry-scans/{scan_id}/report.sarif")
    assert report_resp.status_code == 200
    assert report_resp.headers["content-type"].startswith("application/sarif+json")


def test_report_download_unknown_format_404s(isolated_manager, monkeypatch):
    monkeypatch.setattr(registry_scan_job, "run_registry_scan", lambda image_ref, **kw: [_fake_finding()])
    resp = client.post("/api/registry-scans", json={"image_ref": "alpine:3.18"})
    scan_id = resp.json()["id"]
    _wait_for_terminal(scan_id)

    report_resp = client.get(f"/api/registry-scans/{scan_id}/report.yaml")
    assert report_resp.status_code == 404
