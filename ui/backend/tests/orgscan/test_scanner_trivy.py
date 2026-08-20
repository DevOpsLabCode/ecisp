"""Shape captured from a real trivy 0.74.0 `fs --scanners vuln,secret
--format sarif` run; see scanners/trivy_sca_secrets.py's docstring,
including the real discovery that trivy allowlists well-known
documentation example secrets (AWS's own "AKIAIOSFODNN7EXAMPLE") -- a
fixture using that literal value won't be flagged.
"""

import json
from pathlib import Path

import pytest

from app.orgscan.scanners import trivy_sca_secrets
from app.orgscan.scanners.base import ScannerExecutionError

_REAL_TRIVY_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Trivy",
                    "rules": [
                        {
                            "id": "CVE-2019-14234",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {
                                "security-severity": "9.8",
                                "tags": ["vulnerability", "security", "CRITICAL"],
                            },
                        },
                        {
                            "id": "aws-secret-access-key",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {"security-severity": "9.5", "tags": ["secret", "security", "CRITICAL"]},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CVE-2019-14234",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "Package: django\nInstalled Version: 2.2.0\nVulnerability CVE-2019-14234"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "requirements.txt"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "aws-secret-access-key",
                    "ruleIndex": 1,
                    "level": "error",
                    "message": {"text": "Artifact: config.py\nSecret AWS Secret Access Key"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "config.py"}, "region": {"startLine": 2}}}
                    ],
                },
            ],
        }
    ],
}


def test_trivy_categorizes_vuln_vs_secret_findings(tmp_path, monkeypatch):
    def fake_run_capture(args, cwd, ok_exit_codes=(0,), timeout=600):
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_TRIVY_SARIF))
        return ""

    monkeypatch.setattr(trivy_sca_secrets, "require", lambda binary: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_sca_secrets, "run_capture", fake_run_capture)

    findings = trivy_sca_secrets.run(tmp_path, "org/repo")
    assert len(findings) == 2

    by_category = {f.category: f for f in findings}
    assert by_category["sca"].rule_id == "CVE-2019-14234"
    assert by_category["sca"].severity == "critical"
    assert by_category["secrets"].rule_id == "aws-secret-access-key"
    assert by_category["secrets"].severity == "critical"


def test_trivy_raises_execution_error_when_binary_missing(tmp_path, monkeypatch):
    from app.orgscan.scanners.base import ScannerUnavailable

    def fake_require(binary):
        raise ScannerUnavailable(f"'{binary}' is not installed")

    monkeypatch.setattr(trivy_sca_secrets, "require", fake_require)
    with pytest.raises(ScannerUnavailable):
        trivy_sca_secrets.run(tmp_path, "org/repo")


def test_trivy_raises_on_malformed_sarif(tmp_path, monkeypatch):
    monkeypatch.setattr(trivy_sca_secrets, "require", lambda binary: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_sca_secrets, "run_capture", lambda *a, **k: "")
    with pytest.raises(ScannerExecutionError):
        trivy_sca_secrets.run(tmp_path, "org/repo")
