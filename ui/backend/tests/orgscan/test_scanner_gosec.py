"""Not verified against a real gosec binary (no Go toolchain in this
sandbox -- see scanners/gosec.py's docstring); this exercises the adapter's
own logic (arg construction, SARIF file handling) against gosec's
documented `-fmt=sarif -out=<file>` contract.
"""

import json
from pathlib import Path

import pytest

from app.orgscan.scanners import gosec
from app.orgscan.scanners.base import ScannerExecutionError

_DOCUMENTED_GOSEC_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {"name": "gosec", "rules": [{"id": "G101", "defaultConfiguration": {"level": "error"}}]}
            },
            "results": [
                {
                    "ruleId": "G101",
                    "message": {"text": "Potential hardcoded credentials"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "main.go"}, "region": {"startLine": 10}}}
                    ],
                }
            ],
        }
    ],
}


def test_gosec_parses_output_written_to_out_flag(tmp_path, monkeypatch):
    def fake_run_capture(args, cwd, ok_exit_codes, timeout=600):
        out_arg = next(a for a in args if a.startswith("-out="))
        out_path = out_arg.split("=", 1)[1]
        Path(out_path).write_text(json.dumps(_DOCUMENTED_GOSEC_SARIF))
        return ""

    monkeypatch.setattr(gosec, "require", lambda binary: "/usr/bin/gosec")
    monkeypatch.setattr(gosec, "run_capture", fake_run_capture)

    findings = gosec.run(tmp_path, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "G101"
    assert findings[0].file == "main.go"


def test_gosec_raises_when_output_file_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(gosec, "require", lambda binary: "/usr/bin/gosec")
    monkeypatch.setattr(gosec, "run_capture", lambda *a, **k: "")
    with pytest.raises(ScannerExecutionError):
        gosec.run(tmp_path, "org/repo")
