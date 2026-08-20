"""Shape captured from a real ESLint 8.57.1 + eslint-plugin-security run;
see scanners/eslint_security.py's docstring for the ESLint-10-incompatibility
finding that led to pinning 8.x.
"""

import json

import pytest

from app.orgscan.scanners import eslint_security
from app.orgscan.scanners.base import ScannerUnavailable

_REAL_ESLINT_JSON = [
    {
        "filePath": "/repo/bad.js",
        "messages": [
            {
                "ruleId": "security/detect-eval-with-expression",
                "severity": 1,
                "message": "eval with argument of type Identifier",
                "line": 6,
            },
        ],
    }
]


def test_eslint_security_parses_real_output(tmp_path, monkeypatch):
    tools_dir = tmp_path / "tools"
    eslint_bin = tools_dir / "node_modules" / ".bin" / "eslint"
    eslint_bin.parent.mkdir(parents=True)
    eslint_bin.write_text("#!/bin/sh\n")
    eslint_bin.chmod(0o755)
    monkeypatch.setenv("ORGSCAN_ESLINT_TOOLS_DIR", str(tools_dir))

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    fixed_json = json.dumps([{**_REAL_ESLINT_JSON[0], "filePath": str(repo_dir / "bad.js")}])
    monkeypatch.setattr(eslint_security, "run_capture", lambda *a, **k: fixed_json)

    findings = eslint_security.run(repo_dir, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "security/detect-eval-with-expression"
    assert findings[0].file == "bad.js"
    assert findings[0].severity == "medium"  # eslint severity 1 -> medium


def test_eslint_security_raises_when_tools_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("ORGSCAN_ESLINT_TOOLS_DIR", str(tmp_path / "does-not-exist"))
    with pytest.raises(ScannerUnavailable):
        eslint_security.run(tmp_path, "org/repo")
