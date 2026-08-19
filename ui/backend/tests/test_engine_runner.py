import logging

import pytest

from app import engine_runner
from app.schemas import ScanCreateRequest


def make_req(**overrides) -> ScanCreateRequest:
    defaults = dict(provider="aws", auth_method="profile", auth={}, scope={})
    defaults.update(overrides)
    return ScanCreateRequest(**defaults)


class TestBuildRunKwargs:
    def test_aws_profile(self):
        req = make_req(auth_method="profile", auth={"profile": "audit"})
        kwargs = engine_runner.build_run_kwargs(req, "/tmp/reports")
        assert kwargs["provider"] == "aws"
        assert kwargs["profile"] == "audit"
        assert kwargs["report_dir"] == "/tmp/reports"
        assert kwargs["no_browser"] is True
        assert kwargs["force_write"] is True
        assert kwargs["result_format"] == "json"

    def test_aws_access_keys(self):
        req = make_req(
            auth_method="access_keys",
            auth={"aws_access_key_id": "AKIA123", "aws_secret_access_key": "secret"},
            scope={"regions": ["us-east-1"], "excluded_regions": []},
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp/reports")
        assert kwargs["aws_access_key_id"] == "AKIA123"
        assert kwargs["aws_secret_access_key"] == "secret"
        assert "aws_session_token" not in kwargs  # not provided, not sent
        assert kwargs["regions"] == ["us-east-1"]
        assert "excluded_regions" not in kwargs  # empty list filtered out

    def test_azure_cli_sets_boolean_flag(self):
        req = make_req(provider="azure", auth_method="cli", auth={})
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["cli"] is True
        assert "user_account" not in kwargs

    def test_azure_service_principal_sets_flag_and_fields(self):
        req = make_req(
            provider="azure",
            auth_method="service_principal",
            auth={"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"},
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["service_principal"] is True
        assert kwargs["tenant_id"] == "t1"
        assert kwargs["client_id"] == "c1"
        assert kwargs["client_secret"] == "s1"

    def test_gcp_user_account_sets_flag(self):
        req = make_req(provider="gcp", auth_method="user_account", auth={})
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["user_account"] is True

    def test_gcp_service_account_does_not_set_user_account_flag(self):
        req = make_req(
            provider="gcp", auth_method="service_account", auth={"service_account": "./key.json"}
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert "user_account" not in kwargs
        assert kwargs["service_account"] == "./key.json"

    def test_aliyun_access_keys(self):
        req = make_req(
            provider="aliyun",
            auth_method="access_keys",
            auth={"access_key_id": "id1", "access_key_secret": "secret1"},
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["access_key_id"] == "id1"
        assert kwargs["access_key_secret"] == "secret1"

    def test_oci_profile(self):
        req = make_req(provider="oci", auth_method="profile", auth={"profile": "AUDIT"})
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["profile"] == "AUDIT"

    def test_digitalocean_token(self):
        req = make_req(provider="do", auth_method="token", auth={"token": "tok123"})
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["token"] == "tok123"
        assert "access_key" not in kwargs

    def test_kubernetes_kubeconfig(self):
        req = make_req(
            provider="kubernetes",
            auth_method="kubeconfig",
            auth={"kubernetes_context": "prod", "kubernetes_cluster_provider": "eks"},
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["kubernetes_context"] == "prod"
        assert kwargs["kubernetes_cluster_provider"] == "eks"

    def test_general_options_pass_through(self):
        req = make_req(
            report_name="my-report",
            services=["iam", "s3"],
            skipped_services=["emr"],
            ruleset="custom.json",
            max_workers=3,
            max_rate=7,
            debug=True,
        )
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["report_name"] == "my-report"
        assert kwargs["services"] == ["iam", "s3"]
        assert kwargs["skipped_services"] == ["emr"]
        assert kwargs["ruleset"] == "custom.json"
        assert kwargs["max_workers"] == 3
        assert kwargs["max_rate"] == 7
        assert kwargs["debug"] is True

    def test_ruleset_and_max_workers_fall_back_when_falsy(self):
        req = make_req(ruleset="", max_workers=0)
        kwargs = engine_runner.build_run_kwargs(req, "/tmp")
        assert kwargs["ruleset"] == "default.json"
        assert kwargs["max_workers"] == 10


class TestJobLogCapture:
    def test_captures_formatted_records(self):
        capture = engine_runner.JobLogCapture()
        capture.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
        logger = logging.getLogger("test-capture-logger")
        logger.addHandler(capture)
        logger.setLevel(logging.INFO)
        try:
            logger.info("hello world")
        finally:
            logger.removeHandler(capture)
        assert "INFO:hello world" in capture.text()

    def test_emit_swallows_formatting_errors(self):
        capture = engine_runner.JobLogCapture()

        class BoomRecord:
            pass

        # format() will raise on a malformed record; emit() must not propagate.
        capture.emit(BoomRecord())
        assert capture.lines == []


class TestExecute:
    def test_returns_error_when_engine_unavailable(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", False)
        monkeypatch.setattr(engine_runner, "ENGINE_IMPORT_ERROR", "boom, not installed")
        exit_code, log, error = engine_runner.execute({"provider": "aws"})
        assert exit_code == 1
        assert log == ""
        assert error == "boom, not installed"

    def test_success_path_calls_engine_run(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)
        exit_code, log, error = engine_runner.execute({"provider": "aws"})
        assert exit_code == 0
        assert error is None

    def test_engine_run_exception_is_captured(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)

        def boom(**kwargs):
            raise ValueError("bad credentials")

        monkeypatch.setattr(engine_runner, "engine_run", boom)
        exit_code, log, error = engine_runner.execute({"provider": "aws"})
        assert exit_code == 1
        assert "ValueError: bad credentials" in error

    def test_log_handler_is_removed_after_run(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)
        logger = logging.getLogger(engine_runner.ENGINE_LOGGER_NAME)
        before = len(logger.handlers)
        engine_runner.execute({"provider": "aws"})
        assert len(logger.handlers) == before


class TestLoadResults:
    def test_raises_when_engine_unavailable(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", False)
        monkeypatch.setattr(engine_runner, "ENGINE_IMPORT_ERROR", "not installed")
        with pytest.raises(RuntimeError, match="not installed"):
            engine_runner.load_results("aws-report", "/tmp/reports")

    def test_loads_via_encoder_when_available(self, monkeypatch):
        captured = {}

        class FakeEncoder:
            def __init__(self, report_name=None, report_dir=None):
                captured["report_name"] = report_name
                captured["report_dir"] = report_dir

            def load_from_file(self, file_type):
                captured["file_type"] = file_type
                return {"provider_code": "aws", "services": {}}

        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "JavaScriptEncoder", FakeEncoder)

        result = engine_runner.load_results("aws-report", "/tmp/reports")
        assert result == {"provider_code": "aws", "services": {}}
        assert captured == {
            "report_name": "aws-report",
            "report_dir": "/tmp/reports",
            "file_type": "RESULTS",
        }
