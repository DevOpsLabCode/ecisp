import json

from app.orgscan.normalize import parse_sarif


def _sarif(rules, results):
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test", "rules": rules}}, "results": results}],
        }
    )


def test_parses_basic_result_with_ruleindex():
    text = _sarif(
        rules=[{"id": "RULE1", "defaultConfiguration": {"level": "error"}}],
        results=[
            {
                "ruleId": "RULE1",
                "ruleIndex": 0,
                "level": "error",
                "message": {"text": "bad thing"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 5}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast")
    assert len(findings) == 1
    f = findings[0]
    assert f.file == "a.py"
    assert f.line == 5
    assert f.severity == "high"  # level:error -> high
    assert f.message == "bad thing"
    assert f.repository == "org/repo"


def test_falls_back_to_rule_lookup_by_id_when_ruleindex_missing():
    # Reproduces real semgrep SARIF output: results omit both `level` and
    # `ruleIndex`, only carrying `ruleId` -- verified against a real
    # semgrep install (see scanners/semgrep.py's docstring).
    text = _sarif(
        rules=[{"id": "my-rule", "defaultConfiguration": {"level": "warning"}}],
        results=[
            {
                "ruleId": "my-rule",
                "message": {"text": "m"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.js"}, "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="semgrep", category="sast")
    assert findings[0].severity == "medium"  # level:warning -> medium


def test_skips_level_none_results():
    text = _sarif(
        rules=[{"id": "PASSED_CHECK"}],
        results=[
            {
                "ruleId": "PASSED_CHECK",
                "level": "none",
                "message": {"text": "passed"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "c.tf"}, "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="checkov", category="iac")
    assert findings == []


def test_prefers_bandit_issue_severity_property_over_level():
    text = _sarif(
        rules=[{"id": "B105"}],
        results=[
            {
                "ruleId": "B105",
                "level": "note",  # generic SARIF level would say "low"
                "properties": {"issue_severity": "HIGH", "issue_confidence": "HIGH"},
                "message": {"text": "hardcoded password"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "d.py"}, "region": {"startLine": 2}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="bandit", category="sast")
    assert findings[0].severity == "high"  # issue_severity wins over level


def test_security_severity_score_takes_priority():
    text = _sarif(
        rules=[{"id": "CVE-RULE"}],
        results=[
            {
                "ruleId": "CVE-RULE",
                "level": "warning",
                "properties": {"security-severity": "9.8"},
                "message": {"text": "critical cve"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "e.py"}, "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast")
    assert findings[0].severity == "critical"


def test_security_severity_score_bands():
    from app.orgscan.normalize import _security_severity_score

    assert _security_severity_score({"security-severity": "9.5"}) == "critical"
    assert _security_severity_score({"security-severity": "7.5"}) == "high"
    assert _security_severity_score({"security-severity": "5.0"}) == "medium"
    assert _security_severity_score({"security-severity": "1.0"}) == "low"
    assert _security_severity_score({"security-severity": "not-a-number"}) is None
    assert _security_severity_score({}) is None


def test_missing_locations_defaults_to_unknown_file():
    text = _sarif(rules=[{"id": "R"}], results=[{"ruleId": "R", "level": "error", "message": {"text": "m"}}])
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast")
    assert findings[0].file == "unknown"
    assert findings[0].line is None


def test_missing_message_falls_back_to_rule_id():
    text = _sarif(
        rules=[{"id": "R"}],
        results=[
            {
                "ruleId": "R",
                "level": "error",
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.py"}, "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast")
    assert findings[0].message == "R"


def test_message_as_bare_string_is_handled():
    # SARIF 2.1.0 requires `message` to be an object with a `text` property,
    # but .NET's own `/p:ErrorLog=` SARIF logger emits a bare string --
    # reproduced against a real `dotnet build` run (see
    # scanners/security_code_scan.py's docstring).
    text = _sarif(
        rules=[{"id": "SCS0006"}],
        results=[
            {
                "ruleId": "SCS0006",
                "level": "warning",
                "message": "Weak hashing function.",
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "Program.cs"}, "region": {"startLine": 6}}}
                ],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="security_code_scan", category="sast")
    assert findings[0].message == "Weak hashing function."


def test_resultfile_location_shape_with_absolute_file_uri(tmp_path):
    # Reproduced against a real `dotnet build /p:ErrorLog=...,version=2.1`
    # run: locations use the pre-2.1 `resultFile` key (not
    # `physicalLocation`) with an absolute file:// URI, not a repo-relative
    # path -- see scanners/security_code_scan.py's docstring.
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    text = _sarif(
        rules=[{"id": "SCS0006"}],
        results=[
            {
                "ruleId": "SCS0006",
                "level": "warning",
                "message": "Weak hashing function.",
                "locations": [{"resultFile": {"uri": f"file://{repo_dir}/Program.cs", "region": {"startLine": 6}}}],
            }
        ],
    )
    findings = parse_sarif(
        text, repository="org/repo", scanner="security_code_scan", category="sast", base_dir=repo_dir
    )
    assert findings[0].file == "Program.cs"
    assert findings[0].line == 6


def test_resultfile_location_without_base_dir_keeps_absolute_path():
    text = _sarif(
        rules=[{"id": "R"}],
        results=[
            {
                "ruleId": "R",
                "level": "warning",
                "message": "m",
                "locations": [{"resultFile": {"uri": "file:///abs/path/Program.cs", "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast")
    assert findings[0].file == "/abs/path/Program.cs"


def test_remediation_hint_is_attached():
    text = _sarif(
        rules=[{"id": "R"}],
        results=[
            {
                "ruleId": "R",
                "level": "error",
                "message": {"text": "m"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "g.py"}, "region": {"startLine": 1}}}],
            }
        ],
    )
    findings = parse_sarif(text, repository="org/repo", scanner="tool", category="sast", remediation_hint="fix it")
    assert findings[0].remediation == "fix it"


def test_multiple_runs_are_all_parsed():
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "t1", "rules": [{"id": "R1"}]}},
                "results": [
                    {
                        "ruleId": "R1",
                        "level": "error",
                        "message": {"text": "m1"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "h.py"}, "region": {"startLine": 1}}}
                        ],
                    }
                ],
            },
            {
                "tool": {"driver": {"name": "t2", "rules": [{"id": "R2"}]}},
                "results": [
                    {
                        "ruleId": "R2",
                        "level": "error",
                        "message": {"text": "m2"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "i.py"}, "region": {"startLine": 1}}}
                        ],
                    }
                ],
            },
        ],
    }
    findings = parse_sarif(json.dumps(doc), repository="org/repo", scanner="tool", category="sast")
    assert len(findings) == 2
