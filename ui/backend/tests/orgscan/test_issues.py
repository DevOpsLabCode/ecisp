import httpx

from app.orgscan.github_client import GitHubClient
from app.orgscan.issues import create_issues_for_scan, issue_body, issue_title
from app.orgscan.models import Finding, RepoScanResult


def _result_with_severities(*severities, repository="org/repo"):
    findings = [
        Finding(
            repository=repository,
            file=f"f{i}.py",
            line=i,
            scanner="bandit",
            rule_id=f"R{i}",
            severity=sev,
            category="sast",
            message=f"finding {i}",
        )
        for i, sev in enumerate(severities)
    ]
    return RepoScanResult(
        repository=repository, technologies=["bandit"], scanners_run=["bandit"], scanners_skipped={}, findings=findings
    )


def test_issue_title_strips_owner_prefix():
    assert issue_title("my-org/payments-api", "2026-08-19") == "[Security] SAST findings - payments-api - 2026-08-19"


def test_issue_body_includes_severity_counts_and_findings():
    result = _result_with_severities("critical", "high", "medium", "low")
    body = issue_body(result, "2026-08-19")
    assert "Critical: 1" in body
    assert "High: 1" in body
    assert "Medium: 1" in body
    assert "Low: 1" in body
    # only critical/high findings are itemized in the body
    assert body.count("**finding") == 2


def test_issue_body_embeds_fingerprint_marker_for_dedup():
    result = _result_with_severities("high")
    body = issue_body(result, "2026-08-19")
    assert "golem-org-scan fingerprint-set:" in body


def test_create_issues_skips_repos_with_no_qualifying_findings():
    result = _result_with_severities("medium", "low")

    def handler(request):
        raise AssertionError("should never call GitHub API when nothing qualifies")

    with GitHubClient("token", transport=httpx.MockTransport(handler)) as gh:
        outcomes = create_issues_for_scan(gh, [result])
    assert outcomes == {}


def test_create_issues_creates_new_issue_when_none_exists():
    result = _result_with_severities("high")

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=[])  # no existing issues
        return httpx.Response(201, json={"html_url": "https://github.com/org/repo/issues/1"})

    with GitHubClient("token", transport=httpx.MockTransport(handler)) as gh:
        outcomes = create_issues_for_scan(gh, [result], scan_date="2026-08-19")
    assert outcomes["org/repo"] == {"action": "created", "issue_url": "https://github.com/org/repo/issues/1"}


def test_create_issues_reuses_existing_open_issue():
    result = _result_with_severities("critical")
    title = issue_title("org/repo", "2026-08-19")

    def handler(request):
        assert request.method == "GET"  # create_issue (POST) must never be called
        return httpx.Response(200, json=[{"title": title, "html_url": "https://github.com/org/repo/issues/5"}])

    with GitHubClient("token", transport=httpx.MockTransport(handler)) as gh:
        outcomes = create_issues_for_scan(gh, [result], scan_date="2026-08-19")
    assert outcomes["org/repo"] == {"action": "skipped_existing", "issue_url": "https://github.com/org/repo/issues/5"}


def test_create_issues_records_failure_without_aborting_other_repos():
    results = [
        _result_with_severities("high", repository="org/repo-a"),
        _result_with_severities("high", repository="org/repo-b"),
    ]

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=[])
        if "repo-a" in str(request.url):
            return httpx.Response(410, json={"message": "Issues are disabled for this repo"})
        return httpx.Response(201, json={"html_url": "https://github.com/org/repo-b/issues/1"})

    with GitHubClient("token", transport=httpx.MockTransport(handler)) as gh:
        outcomes = create_issues_for_scan(gh, results, scan_date="2026-08-19")
    assert outcomes["org/repo-a"]["action"] == "failed"
    assert outcomes["org/repo-b"]["action"] == "created"
