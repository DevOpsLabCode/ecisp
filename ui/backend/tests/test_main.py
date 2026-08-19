import time

from fastapi.testclient import TestClient

from app import engine_runner
from app.main import app

client = TestClient(app)


def wait_for_status(job_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    detail = {}
    while time.time() < deadline:
        detail = client.get(f"/api/scans/{job_id}").json()
        if detail["status"] in ("completed", "failed"):
            return detail
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never reached a terminal status: {detail}")


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "engine_available" in body


def test_providers_endpoint_lists_all_providers():
    res = client.get("/api/providers")
    assert res.status_code == 200
    codes = {p["code"] for p in res.json()}
    assert codes == {"aws", "azure", "gcp", "aliyun", "oci", "do", "kubernetes"}


def test_create_scan_rejects_unknown_provider():
    res = client.post("/api/scans", json={"provider": "nope", "auth_method": "profile"})
    assert res.status_code == 400
    assert "Unknown provider" in res.json()["detail"]


def test_create_scan_rejects_missing_required_field():
    res = client.post("/api/scans", json={"provider": "aws", "auth_method": "profile", "auth": {}})
    assert res.status_code == 400
    assert "Missing required field" in res.json()["detail"]


def test_create_scan_rejects_malformed_body():
    res = client.post("/api/scans", json={"auth_method": "profile"})  # missing required 'provider'
    assert res.status_code == 422


def test_create_and_fetch_scan_lifecycle(monkeypatch):
    monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
    monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

    create_res = client.post(
        "/api/scans",
        json={
            "provider": "aws",
            "auth_method": "profile",
            "auth": {"profile": "audit"},
            "report_name": "api-lifecycle-test",
        },
    )
    assert create_res.status_code == 200
    job_id = create_res.json()["id"]

    detail = wait_for_status(job_id)
    assert detail["status"] == "completed"
    assert detail["exit_code"] == 0
    assert detail["request"]["report_name"] == "api-lifecycle-test"
    assert "log" in detail


def test_list_scans_includes_created_job():
    create_res = client.post(
        "/api/scans",
        json={
            "provider": "aws",
            "auth_method": "profile",
            "auth": {"profile": "audit"},
            "report_name": "api-list-test",
        },
    )
    job_id = create_res.json()["id"]
    wait_for_status(job_id)

    listed = client.get("/api/scans").json()
    assert any(j["id"] == job_id for j in listed)


def test_get_scan_404_for_unknown_id():
    res = client.get("/api/scans/does-not-exist")
    assert res.status_code == 404


def test_get_scan_results_404_for_unknown_job():
    res = client.get("/api/scans/does-not-exist/results")
    assert res.status_code == 404


def test_get_scan_results_409_when_not_completed(monkeypatch):
    # Never let the worker finish this one before we check its status.
    monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", False)
    create_res = client.post(
        "/api/scans",
        json={
            "provider": "aws",
            "auth_method": "profile",
            "auth": {"profile": "audit"},
            "report_name": "api-409-test",
        },
    )
    job_id = create_res.json()["id"]
    wait_for_status(job_id)  # this run fails fast since ENGINE_AVAILABLE is False

    res = client.get(f"/api/scans/{job_id}/results")
    assert res.status_code == 409


def test_get_scan_results_returns_parsed_results(monkeypatch):
    monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
    monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

    create_res = client.post(
        "/api/scans",
        json={
            "provider": "aws",
            "auth_method": "profile",
            "auth": {"profile": "audit"},
            "report_name": "api-results-test",
        },
    )
    job_id = create_res.json()["id"]
    wait_for_status(job_id)

    class FakeEncoder:
        def __init__(self, report_name=None, report_dir=None):
            pass

        def load_from_file(self, file_type):
            return {"provider_code": "aws", "services": {"iam": {"findings": {}}}}

    monkeypatch.setattr(engine_runner, "JavaScriptEncoder", FakeEncoder)

    res = client.get(f"/api/scans/{job_id}/results")
    assert res.status_code == 200
    assert res.json()["provider_code"] == "aws"


def test_get_scan_results_500_when_encoder_raises(monkeypatch):
    monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
    monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

    create_res = client.post(
        "/api/scans",
        json={
            "provider": "aws",
            "auth_method": "profile",
            "auth": {"profile": "audit"},
            "report_name": "api-results-error-test",
        },
    )
    job_id = create_res.json()["id"]
    wait_for_status(job_id)

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(engine_runner, "JavaScriptEncoder", boom)

    res = client.get(f"/api/scans/{job_id}/results")
    assert res.status_code == 500
    assert "Failed to load results" in res.json()["detail"]
