import time

from fastapi.testclient import TestClient

from app import engine_runner
from app.main import app, parse_cors_origins

client = TestClient(app)


def test_parse_cors_origins_splits_and_trims():
    assert parse_cors_origins("http://a.example, http://b.example ,http://c.example") == [
        "http://a.example",
        "http://b.example",
        "http://c.example",
    ]


def test_parse_cors_origins_drops_empty_entries():
    assert parse_cors_origins("http://a.example,,  ,http://b.example") == [
        "http://a.example",
        "http://b.example",
    ]


def test_parse_cors_origins_empty_string_yields_no_origins():
    assert parse_cors_origins("") == []


def test_cors_headers_present_for_configured_dev_origin():
    res = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    assert res.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_headers_absent_for_unconfigured_origin():
    res = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in res.headers


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
    detail = wait_for_status(job_id)
    # Regression check: this doesn't monkeypatch engine_run, so it goes
    # through the default stub, which calls asyncio.get_event_loop() just
    # like the real engine -- see JobManager._run_worker.
    assert detail["status"] == "completed", detail["error"]

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


def wait_for_batch_status(batch_id: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    detail = {}
    while time.time() < deadline:
        detail = client.get(f"/api/batches/{batch_id}").json()
        counts = detail["status_counts"]
        if counts["queued"] == 0 and counts["running"] == 0 and detail["queued_jobs"] > 0:
            return detail
        if detail["queued_jobs"] == 0:
            return detail
        time.sleep(0.02)
    raise AssertionError(f"batch {batch_id} jobs never reached a terminal status: {detail}")


def test_batch_template_download():
    res = client.get("/api/batches/template.csv")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    assert res.text.splitlines()[0].startswith("provider,auth_method")


def test_create_batch_rejects_empty_file():
    res = client.post("/api/batches", files={"file": ("accounts.csv", b"", "text/csv")})
    assert res.status_code == 400


def test_create_batch_rejects_corrupted_xlsx():
    # Real-world scenario: a user uploads a file that merely has an .xlsx
    # extension but isn't valid XLSX (renamed, truncated, wrong export).
    # openpyxl raises on load, well before our own RowParseError -- the
    # generic except-Exception path in create_batch must still turn this
    # into a clean 400, not a 500.
    res = client.post(
        "/api/batches", files={"file": ("accounts.xlsx", b"not actually an xlsx file", "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Could not parse" in res.json()["detail"]


def test_create_batch_rejects_unsupported_extension():
    res = client.post("/api/batches", files={"file": ("accounts.txt", b"provider,auth_method\n", "text/plain")})
    assert res.status_code == 400
    assert "Unsupported file type" in res.json()["detail"]


def test_create_batch_rejects_file_over_size_limit(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, "MAX_BATCH_UPLOAD_BYTES", 10)
    data = b"provider,auth_method\naws,profile\n"
    res = client.post("/api/batches", files={"file": ("accounts.csv", data, "text/csv")})
    assert res.status_code == 413


def test_create_and_fetch_batch(monkeypatch):
    monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
    monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

    csv_data = (
        b"provider,auth_method,report_name,profile\n"
        b"aws,profile,api-batch-1,audit-1\n"
        b"aws,profile,api-batch-2,audit-2\n"
        b"bogus,profile,api-batch-bad,x\n"
    )
    res = client.post("/api/batches", files={"file": ("accounts.csv", csv_data, "text/csv")})
    assert res.status_code == 200
    summary = res.json()
    assert summary["queued_jobs"] == 2
    assert summary["skipped_rows"] == 1

    detail = wait_for_batch_status(summary["id"])
    assert len(detail["jobs"]) == 2
    assert len(detail["errors"]) == 1
    assert detail["status_counts"]["completed"] == 2


def test_list_batches_includes_created_batch():
    res = client.post("/api/batches", files={"file": ("list-test.csv", b"provider,auth_method\n", "text/csv")})
    batch_id = res.json()["id"]
    listed = client.get("/api/batches").json()
    assert any(b["id"] == batch_id for b in listed)


def test_get_batch_404_for_unknown_id():
    res = client.get("/api/batches/does-not-exist")
    assert res.status_code == 404
