"""Shape captured from a real brakeman 5.4.1 run against a minimal Rails
fixture; see scanners/brakeman.py's docstring.
"""

import json

import pytest

from app.orgscan.scanners import brakeman
from app.orgscan.scanners.base import ScannerExecutionError

_REAL_BRAKEMAN_JSON = {
    "warnings": [
        {
            "warning_type": "SQL Injection",
            "check_name": "SQL",
            "message": "Possible SQL injection",
            "file": "app/controllers/users_controller.rb",
            "line": 3,
            "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
            "confidence": "Medium",
        }
    ],
    "errors": [],
}


def test_brakeman_parses_real_output(tmp_path, monkeypatch):
    monkeypatch.setattr(brakeman, "require", lambda binary: "/usr/bin/brakeman")
    monkeypatch.setattr(brakeman, "run_capture", lambda *a, **k: json.dumps(_REAL_BRAKEMAN_JSON))

    findings = brakeman.run(tmp_path, "org/repo")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SQL Injection"
    assert f.severity == "medium"  # confidence "Medium" -> medium
    assert f.remediation == "https://brakemanscanner.org/docs/warning_types/sql_injection/"


def test_brakeman_empty_warnings_list(tmp_path, monkeypatch):
    monkeypatch.setattr(brakeman, "require", lambda binary: "/usr/bin/brakeman")
    monkeypatch.setattr(brakeman, "run_capture", lambda *a, **k: json.dumps({"warnings": [], "errors": []}))
    assert brakeman.run(tmp_path, "org/repo") == []


def test_brakeman_raises_on_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(brakeman, "require", lambda binary: "/usr/bin/brakeman")
    monkeypatch.setattr(brakeman, "run_capture", lambda *a, **k: "not json")
    with pytest.raises(ScannerExecutionError):
        brakeman.run(tmp_path, "org/repo")
