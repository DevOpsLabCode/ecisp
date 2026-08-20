"""Mocks run_capture's subprocess call but writes a real, previously-captured
checkov SARIF shape into the --output-file-path dir it's given, so the
file-reading + parsing code path is exercised for real. See checkov.py's
docstring for how this shape was verified against an actual checkov install.
"""

import json
from pathlib import Path

import pytest

from app.orgscan.scanners import checkov
from app.orgscan.scanners.base import ScannerExecutionError, ScannerUnavailable

_REAL_CHECKOV_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "checkov",
                    "rules": [{"id": "CKV_AWS_24", "defaultConfiguration": {"level": "error"}}],
                }
            },
            "results": [
                {
                    "ruleId": "CKV_AWS_24",
                    "level": "error",
                    "message": {"text": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 1}}}
                    ],
                }
            ],
        }
    ],
}


def test_checkov_run_parses_written_sarif_file(tmp_path, monkeypatch):
    def fake_run_capture(args, cwd, ok_exit_codes, timeout=600):
        out_dir = args[args.index("--output-file-path") + 1]
        (Path(out_dir) / "results_sarif.sarif").write_text(json.dumps(_REAL_CHECKOV_SARIF))
        return ""

    monkeypatch.setattr(checkov, "require", lambda binary: "/usr/bin/checkov")
    monkeypatch.setattr(checkov, "run_capture", fake_run_capture)

    findings = checkov.run(tmp_path, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "CKV_AWS_24"
    assert findings[0].severity == "high"
    assert findings[0].category == "iac"


def test_checkov_raises_when_binary_missing(tmp_path, monkeypatch):
    def fake_require(binary):
        raise ScannerUnavailable(f"'{binary}' is not installed")

    monkeypatch.setattr(checkov, "require", fake_require)
    with pytest.raises(ScannerUnavailable):
        checkov.run(tmp_path, "org/repo")


def test_checkov_raises_execution_error_when_sarif_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(checkov, "require", lambda binary: "/usr/bin/checkov")
    monkeypatch.setattr(checkov, "run_capture", lambda *a, **k: "")
    with pytest.raises(ScannerExecutionError):
        checkov.run(tmp_path, "org/repo")
