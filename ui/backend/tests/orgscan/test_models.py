import pytest

from app.orgscan.models import Finding, RepoScanResult


def test_finding_computes_fingerprint_deterministically():
    f1 = Finding(
        repository="org/repo",
        file="a.py",
        line=3,
        scanner="bandit",
        rule_id="B105",
        severity="high",
        category="sast",
        message="m",
    )
    f2 = Finding(
        repository="org/repo",
        file="a.py",
        line=3,
        scanner="semgrep",
        rule_id="B105",
        severity="low",
        category="sast",
        message="different",
    )
    assert f1.fingerprint == f2.fingerprint  # same (repo, file, rule, line) regardless of scanner/message


def test_finding_fingerprint_differs_on_line():
    f1 = Finding(
        repository="org/repo",
        file="a.py",
        line=3,
        scanner="bandit",
        rule_id="B105",
        severity="high",
        category="sast",
        message="m",
    )
    f2 = Finding(
        repository="org/repo",
        file="a.py",
        line=4,
        scanner="bandit",
        rule_id="B105",
        severity="high",
        category="sast",
        message="m",
    )
    assert f1.fingerprint != f2.fingerprint


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError, match="Unknown severity"):
        Finding(
            repository="org/repo",
            file="a.py",
            scanner="bandit",
            rule_id="B105",
            severity="ultra",
            category="sast",
            message="m",
        )


def test_finding_to_dict_has_all_fields():
    f = Finding(
        repository="org/repo",
        file="a.py",
        line=3,
        scanner="bandit",
        rule_id="B105",
        severity="high",
        category="sast",
        message="m",
        remediation="fix it",
    )
    d = f.to_dict()
    assert d["repository"] == "org/repo"
    assert d["remediation"] == "fix it"
    assert "fingerprint" in d


def test_repo_scan_result_severity_counts():
    findings = [
        Finding(
            repository="org/repo", file="a.py", scanner="s", rule_id="r1", severity="high", category="sast", message="m"
        ),
        Finding(
            repository="org/repo", file="a.py", scanner="s", rule_id="r2", severity="high", category="sast", message="m"
        ),
        Finding(
            repository="org/repo", file="a.py", scanner="s", rule_id="r3", severity="low", category="sast", message="m"
        ),
    ]
    result = RepoScanResult(
        repository="org/repo", technologies=["bandit"], scanners_run=["bandit"], scanners_skipped={}, findings=findings
    )
    counts = result.severity_counts()
    assert counts == {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0}
