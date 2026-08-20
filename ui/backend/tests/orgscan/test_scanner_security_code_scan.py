"""Not verified against a real .NET SDK (none in this sandbox -- see
scanners/security_code_scan.py's docstring); exercises the adapter's own
Directory.Build.props injection/cleanup and SARIF handling against the
documented `dotnet build /p:ErrorLog=<path>,version=2.1` contract.
"""

import json
from pathlib import Path

import pytest

from app.orgscan.scanners import security_code_scan
from app.orgscan.scanners.base import ScannerExecutionError

_DOCUMENTED_ROSLYN_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {"name": "Roslyn", "rules": [{"id": "SCS0002", "defaultConfiguration": {"level": "error"}}]}
            },
            "results": [
                {
                    "ruleId": "SCS0002",
                    "message": {"text": "SQL Injection possible"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "Program.cs"}, "region": {"startLine": 12}}}
                    ],
                }
            ],
        }
    ],
}


def _errorlog_path(args: list[str]) -> str:
    flag = next(a for a in args if a.startswith("/p:ErrorLog="))
    return flag.split("=", 1)[1].split(",")[0]


def test_security_code_scan_parses_output_and_injects_props(tmp_path, monkeypatch):
    (tmp_path / "App.csproj").write_text("<Project></Project>")

    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        Path(_errorlog_path(args)).write_text(json.dumps(_DOCUMENTED_ROSLYN_SARIF))
        return ""

    monkeypatch.setattr(security_code_scan, "require", lambda binary: "/usr/bin/dotnet")
    monkeypatch.setattr(security_code_scan, "run_capture", fake_run_capture)

    findings = security_code_scan.run(tmp_path, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "SCS0002"
    # the injected Directory.Build.props must be cleaned up afterward
    assert not (tmp_path / "Directory.Build.props").exists()


def test_security_code_scan_does_not_overwrite_existing_props(tmp_path, monkeypatch):
    existing = tmp_path / "Directory.Build.props"
    existing.write_text("<Project><!-- existing repo config --></Project>")

    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        Path(_errorlog_path(args)).write_text(json.dumps(_DOCUMENTED_ROSLYN_SARIF))
        return ""

    monkeypatch.setattr(security_code_scan, "require", lambda binary: "/usr/bin/dotnet")
    monkeypatch.setattr(security_code_scan, "run_capture", fake_run_capture)

    security_code_scan.run(tmp_path, "org/repo")
    assert "existing repo config" in existing.read_text()


def test_security_code_scan_raises_when_no_sarif_produced(tmp_path, monkeypatch):
    monkeypatch.setattr(security_code_scan, "require", lambda binary: "/usr/bin/dotnet")
    monkeypatch.setattr(security_code_scan, "run_capture", lambda *a, **k: "")
    with pytest.raises(ScannerExecutionError):
        security_code_scan.run(tmp_path, "org/repo")
