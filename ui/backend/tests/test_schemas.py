from app.schemas import JobDetail, JobSummary, ScanCreateRequest


def test_scan_create_request_defaults():
    req = ScanCreateRequest(provider="aws", auth_method="profile")
    assert req.auth == {}
    assert req.scope == {}
    assert req.report_name is None
    assert req.services == []
    assert req.skipped_services == []
    assert req.ruleset == "default.json"
    assert req.max_workers == 10
    assert req.max_rate is None
    assert req.debug is False


def test_scan_create_request_overrides():
    req = ScanCreateRequest(
        provider="aws",
        auth_method="access_keys",
        auth={"aws_access_key_id": "AKIA..."},
        scope={"regions": ["us-east-1"]},
        report_name="my-report",
        services=["iam"],
        skipped_services=["emr"],
        ruleset="custom.json",
        max_workers=5,
        max_rate=8,
        debug=True,
    )
    assert req.auth["aws_access_key_id"] == "AKIA..."
    assert req.scope["regions"] == ["us-east-1"]
    assert req.report_name == "my-report"
    assert req.max_rate == 8
    assert req.debug is True


def test_job_summary_roundtrip():
    summary = JobSummary(
        id="abc",
        provider="aws",
        report_name="aws-abc",
        status="queued",
        created_at="2026-01-01T00:00:00Z",
    )
    assert summary.started_at is None
    assert summary.exit_code is None


def test_job_detail_includes_request_and_log():
    detail = JobDetail(
        id="abc",
        provider="aws",
        report_name="aws-abc",
        status="completed",
        created_at="2026-01-01T00:00:00Z",
        request={"provider": "aws"},
        log="hello",
    )
    assert detail.request == {"provider": "aws"}
    assert detail.log == "hello"
