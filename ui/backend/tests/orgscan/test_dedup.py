from app.orgscan.dedup import dedupe
from app.orgscan.models import Finding


def _f(scanner, severity, line=1, rule_id="R1", file="a.py"):
    return Finding(
        repository="org/repo",
        file=file,
        line=line,
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        category="sast",
        message="m",
    )


def test_dedupe_collapses_identical_fingerprints():
    findings = [_f("bandit", "high"), _f("bandit", "high")]
    result = dedupe(findings)
    assert len(result) == 1


def test_dedupe_keeps_most_severe_instance():
    findings = [_f("bandit", "low"), _f("semgrep", "high")]
    result = dedupe(findings)
    assert len(result) == 1
    assert result[0].severity == "high"


def test_dedupe_merges_scanner_names_when_multiple_tools_agree():
    findings = [_f("bandit", "high"), _f("semgrep", "high")]
    result = dedupe(findings)
    assert result[0].scanner == "bandit+semgrep"


def test_dedupe_keeps_distinct_findings_separate():
    findings = [_f("bandit", "high", rule_id="R1"), _f("bandit", "high", rule_id="R2")]
    result = dedupe(findings)
    assert len(result) == 2


def test_dedupe_sorts_by_severity_then_location():
    findings = [_f("bandit", "low", rule_id="R2"), _f("bandit", "critical", rule_id="R1")]
    result = dedupe(findings)
    assert result[0].severity == "critical"
    assert result[1].severity == "low"


def test_dedupe_empty_list():
    assert dedupe([]) == []
