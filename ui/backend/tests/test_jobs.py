import time

from app import engine_runner
from app.jobs import JobManager, manager
from app.schemas import ScanCreateRequest


def make_req(**overrides) -> ScanCreateRequest:
    defaults = dict(provider="aws", auth_method="profile", auth={"profile": "audit"}, scope={})
    defaults.update(overrides)
    return ScanCreateRequest(**defaults)


def wait_for_terminal_status(job, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if job.status in ("completed", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job.id} did not reach a terminal status in {timeout}s (status={job.status})")


class TestValidate:
    def test_unknown_provider(self):
        req = make_req(provider="not-a-real-provider")
        error = manager.validate(req)
        assert "Unknown provider" in error

    def test_unknown_auth_method(self):
        req = make_req(auth_method="not-a-real-method")
        error = manager.validate(req)
        assert "Unknown auth method" in error

    def test_missing_required_field(self):
        req = make_req(auth={})
        error = manager.validate(req)
        assert "Missing required field" in error
        assert "profile" in error

    def test_valid_request_returns_none(self):
        req = make_req()
        assert manager.validate(req) is None

    def test_method_with_no_required_fields_is_valid(self):
        req = make_req(provider="azure", auth_method="cli", auth={})
        assert manager.validate(req) is None


class TestRedact:
    def test_redacts_known_secret_keys_when_present(self):
        redacted = JobManager._redact({"aws_secret_access_key": "shh", "profile": "audit"})
        assert redacted["aws_secret_access_key"] == "<redacted>"
        assert redacted["profile"] == "audit"

    def test_does_not_redact_falsy_secret_values(self):
        redacted = JobManager._redact({"token": "", "password": None})
        assert redacted["token"] == ""
        assert redacted["password"] is None


class TestJobLifecycle:
    def test_create_returns_queued_job_with_expected_fields(self):
        req = make_req(report_name="lifecycle-test-1")
        job = manager.create(req)
        assert job.provider == "aws"
        assert job.report_name == "lifecycle-test-1"
        assert job.status in ("queued", "running", "completed", "failed")
        assert job.id
        wait_for_terminal_status(job)

    def test_report_name_is_generated_when_absent(self):
        req = make_req(report_name=None)
        job = manager.create(req)
        assert job.report_name.startswith("aws-")
        wait_for_terminal_status(job)

    def test_successful_run_marks_job_completed(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)
        req = make_req(report_name="lifecycle-success")
        job = manager.create(req)
        wait_for_terminal_status(job)
        assert job.status == "completed"
        assert job.exit_code == 0
        assert job.error is None
        assert job.started_at is not None
        assert job.finished_at is not None

    def test_run_completed_with_handled_errors_counts_as_completed(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 200)
        req = make_req(report_name="lifecycle-200")
        job = manager.create(req)
        wait_for_terminal_status(job)
        assert job.status == "completed"
        assert job.exit_code == 200

    def test_failed_run_marks_job_failed(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)

        def boom(**kwargs):
            raise RuntimeError("auth failed")

        monkeypatch.setattr(engine_runner, "engine_run", boom)
        req = make_req(report_name="lifecycle-failure")
        job = manager.create(req)
        wait_for_terminal_status(job)
        assert job.status == "failed"
        assert "auth failed" in job.error

    def test_resolved_kwargs_are_redacted_in_request_snapshot(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)
        req = make_req(
            auth_method="access_keys",
            auth={"aws_access_key_id": "AKIA1", "aws_secret_access_key": "supersecret"},
            report_name="lifecycle-redact",
        )
        job = manager.create(req)
        wait_for_terminal_status(job)
        resolved = job.request["resolved_kwargs"]
        assert resolved["aws_secret_access_key"] == "<redacted>"
        assert resolved["aws_access_key_id"] == "AKIA1"


class TestManagerQueries:
    def test_get_returns_none_for_unknown_id(self):
        assert manager.get("does-not-exist") is None

    def test_get_returns_created_job(self):
        req = make_req(report_name="query-test")
        job = manager.create(req)
        assert manager.get(job.id) is job
        wait_for_terminal_status(job)

    def test_list_includes_newly_created_job_first(self):
        req = make_req(report_name="query-list-test")
        job = manager.create(req)
        listed = manager.list()
        assert listed[0].id == job.id
        wait_for_terminal_status(job)


def test_new_manager_instance_starts_its_own_worker():
    # Sanity check that JobManager isn't hard-wired to the module singleton;
    # a fresh instance should be independently usable.
    fresh = JobManager()
    req = make_req(report_name="fresh-manager-test")
    job = fresh.create(req)
    wait_for_terminal_status(job)
    assert job.status in ("completed", "failed")
