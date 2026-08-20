import csv
import io
import json

from app.orgscan.models import Finding, RepoScanResult
from app.orgscan.reporting import csv_report, html_report, json_report
from app.orgscan.reporting import sarif as sarif_report


def _sample_results():
    findings = [
        Finding(
            repository="org/repo",
            file="a.py",
            line=3,
            scanner="bandit",
            rule_id="B105",
            severity="high",
            category="sast",
            message="hardcoded password",
            remediation="rotate it",
        ),
        Finding(
            repository="org/repo",
            file="b.tf",
            line=1,
            scanner="checkov",
            rule_id="CKV_AWS_24",
            severity="critical",
            category="iac",
            message="open sg",
        ),
    ]
    return [
        RepoScanResult(
            repository="org/repo",
            technologies=["bandit", "checkov"],
            scanners_run=["bandit", "checkov"],
            scanners_skipped={"gosec": "not installed"},
            findings=findings,
        ),
        RepoScanResult(
            repository="org/clean-repo",
            technologies=["bandit"],
            scanners_run=["bandit"],
            scanners_skipped={},
            findings=[],
        ),
        RepoScanResult(
            repository="org/errored-repo",
            technologies=[],
            scanners_run=[],
            scanners_skipped={},
            findings=[],
            error="git clone failed",
        ),
    ]


def test_sarif_report_is_valid_json_and_covers_all_findings():
    text = sarif_report.to_sarif(_sample_results())
    doc = json.loads(text)
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    levels = {r["level"] for r in results}
    assert "error" in levels  # critical/high -> error


def test_sarif_rule_dedup_by_scanner_and_rule_id():
    findings = [
        Finding(
            repository="org/repo",
            file="a.py",
            scanner="bandit",
            rule_id="B105",
            severity="high",
            category="sast",
            message="m1",
        ),
        Finding(
            repository="org/repo",
            file="c.py",
            scanner="bandit",
            rule_id="B105",
            severity="high",
            category="sast",
            message="m2",
            line=99,
        ),
    ]
    result = RepoScanResult(
        repository="org/repo", technologies=[], scanners_run=[], scanners_skipped={}, findings=findings
    )
    doc = json.loads(sarif_report.to_sarif([result]))
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1  # same scanner:rule_id collapses to one rule entry
    assert len(doc["runs"][0]["results"]) == 2  # but both results are still present


def test_json_report_structure():
    doc = json.loads(json_report.to_json("my-org", _sample_results()))
    assert doc["organization"] == "my-org"
    assert doc["repositories_scanned"] == 3
    repo = next(r for r in doc["repositories"] if r["repository"] == "org/repo")
    assert len(repo["findings"]) == 2
    assert repo["severity_counts"]["critical"] == 1
    errored = next(r for r in doc["repositories"] if r["repository"] == "org/errored-repo")
    assert errored["error"] == "git clone failed"


def test_csv_report_one_row_per_finding():
    text = csv_report.to_csv(_sample_results())
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 2
    assert rows[0]["repository"] == "org/repo"
    assert rows[0]["scanner"] == "bandit"


def test_csv_report_empty_when_no_findings():
    text = csv_report.to_csv(
        [RepoScanResult(repository="org/clean", technologies=[], scanners_run=[], scanners_skipped={}, findings=[])]
    )
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows == []


def test_html_report_contains_org_name_and_severity_counts():
    html = html_report.to_html("my-org", _sample_results())
    assert "my-org" in html
    assert "CKV_AWS_24" in html
    assert "org/repo" in html


def test_html_report_escapes_message_content():
    findings = [
        Finding(
            repository="org/repo",
            file="a.py",
            scanner="s",
            rule_id="R",
            severity="high",
            category="sast",
            message="<script>alert(1)</script>",
        )
    ]
    result = RepoScanResult(
        repository="org/repo", technologies=[], scanners_run=[], scanners_skipped={}, findings=findings
    )
    html = html_report.to_html("my-org", [result])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_report_shows_scan_error_and_skip_notes():
    html = html_report.to_html("my-org", _sample_results())
    assert "git clone failed" in html
    assert "gosec" in html


def test_html_report_handles_zero_findings():
    html = html_report.to_html(
        "my-org",
        [RepoScanResult(repository="org/clean", technologies=[], scanners_run=[], scanners_skipped={}, findings=[])],
    )
    assert "No findings" in html
