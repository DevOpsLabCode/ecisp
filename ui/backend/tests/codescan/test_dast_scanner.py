"""Shape captured from a real ZAP 2.17.0 `-cmd -autorun` run (Automation
Framework, `sarif-json` report template) against this project's own live
dev stack; see dast_scanner.py's docstring.
"""

import json
from pathlib import Path

import pytest

from app.codescan import dast_scanner
from app.codescan.dast_scanner import DastExecutionError, DastUnavailable, run_dast

_REAL_ZAP_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "ZAP",
                    "rules": [{"id": "10020", "defaultConfiguration": {"level": "warning"}}],
                }
            },
            "results": [
                {
                    "ruleId": "10020",
                    "level": "warning",
                    "message": {"text": "The response does not protect against 'ClickJacking' attacks."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "http://target.example"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                },
                {
                    # ZAP's own "informational, not actually a finding" level -- parse_sarif already
                    # skips these for every other scanner, verified here it does the same for ZAP's.
                    "ruleId": "99999",
                    "level": "none",
                    "message": {"text": "informational only"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "http://target.example"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


def test_run_dast_parses_real_sarif_shape(tmp_path, monkeypatch):
    def fake_run(args, capture_output, text, check):
        report_dir_idx = args.index("-autorun") + 1
        plan_text = Path(args[report_dir_idx]).read_text()
        assert "http://target.example" in plan_text
        # Locate the report path the plan asked for and write the fixture there.
        report_dir_line = next(line for line in plan_text.splitlines() if "reportDir:" in line)
        report_file_line = next(line for line in plan_text.splitlines() if "reportFile:" in line)
        report_dir = report_dir_line.split("reportDir:", 1)[1].strip()
        report_file = report_file_line.split("reportFile:", 1)[1].strip()
        Path(report_dir, f"{report_file}.json").write_text(json.dumps(_REAL_ZAP_SARIF))
        return type("P", (), {"stdout": "Automation plan succeeded!", "stderr": ""})()

    monkeypatch.setattr(dast_scanner.shutil, "which", lambda binary: "/usr/local/bin/zap.sh")
    monkeypatch.setattr(dast_scanner.subprocess, "run", fake_run)

    findings = run_dast("http://target.example", spider_minutes=1, active_scan_minutes=1)
    assert len(findings) == 1  # the "none" level result is filtered out
    assert findings[0].rule_id == "10020"
    assert findings[0].category == "dast"
    assert findings[0].severity == "medium"  # level:warning -> medium
    assert findings[0].file == "http://target.example"


def test_run_dast_raises_unavailable_when_zap_missing(monkeypatch):
    monkeypatch.setattr(dast_scanner.shutil, "which", lambda binary: None)
    with pytest.raises(DastUnavailable):
        run_dast("http://target.example")


def test_run_dast_raises_execution_error_when_plan_fails(monkeypatch):
    def fake_run(args, capture_output, text, check):
        return type("P", (), {"stdout": "Automation plan failures:\nsomething broke", "stderr": ""})()

    monkeypatch.setattr(dast_scanner.shutil, "which", lambda binary: "/usr/local/bin/zap.sh")
    monkeypatch.setattr(dast_scanner.subprocess, "run", fake_run)

    with pytest.raises(DastExecutionError, match="did not succeed"):
        run_dast("http://target.example")


def test_run_dast_raises_execution_error_when_report_missing(monkeypatch):
    def fake_run(args, capture_output, text, check):
        return type("P", (), {"stdout": "Automation plan succeeded!", "stderr": ""})()

    monkeypatch.setattr(dast_scanner.shutil, "which", lambda binary: "/usr/local/bin/zap.sh")
    monkeypatch.setattr(dast_scanner.subprocess, "run", fake_run)

    with pytest.raises(DastExecutionError, match="did not produce a report"):
        run_dast("http://target.example")


def test_plan_yaml_includes_target_url_and_durations():
    plan = dast_scanner._plan_yaml("http://target.example", Path("/tmp/out/report"), 3, 10)
    assert "http://target.example" in plan
    assert "maxDuration: 3" in plan
    assert "maxScanDurationInMins: 10" in plan
    assert "template: sarif-json" in plan
