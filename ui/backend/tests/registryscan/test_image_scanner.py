"""Shape captured from a real `trivy image --scanners vuln,secret --format
sarif` run against real images (alpine:3.18 -- clean; node:14.0.0 -- 3231
real findings); see image_scanner.py's docstring. Reuses the same SARIF
shape trivy's filesystem scan produces (same tool, same categorization
rule), captured once in test_scanner_trivy.py.
"""

import json
from pathlib import Path

import pytest

from app.orgscan.scanners.base import ScannerExecutionError, ScannerUnavailable
from app.registryscan import image_scanner

_REAL_TRIVY_IMAGE_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Trivy",
                    "rules": [
                        {
                            "id": "CVE-2020-27350",
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {"security-severity": "5.7", "tags": ["vulnerability", "MEDIUM"]},
                        },
                        {
                            "id": "aws-secret-access-key",
                            "defaultConfiguration": {"level": "error"},
                            "properties": {"security-severity": "9.5", "tags": ["secret", "CRITICAL"]},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CVE-2020-27350",
                    "ruleIndex": 0,
                    "level": "warning",
                    "message": {"text": "Package: apt\nInstalled Version: 1.4.9\nVulnerability CVE-2020-27350"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "node:14.0.0"}, "region": {"startLine": 1}}}
                    ],
                },
                {
                    "ruleId": "aws-secret-access-key",
                    "ruleIndex": 1,
                    "level": "error",
                    "message": {"text": "Artifact: /app/.env\nSecret AWS Secret Access Key"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "/app/.env"}, "region": {"startLine": 1}}}
                    ],
                },
            ],
        }
    ],
}


def _fake_proc(returncode=0, stdout="", stderr=""):
    return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


def test_run_registry_scan_categorizes_vuln_vs_secret(monkeypatch):
    captured_env = {}

    def fake_run(args, env, capture_output, text, timeout, check):
        captured_env.update(env)
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_TRIVY_IMAGE_SARIF))
        assert args[-1] == "node:14.0.0"
        return _fake_proc()

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    findings = image_scanner.run_registry_scan("node:14.0.0", username="me", password="hunter2", registry_token=None)
    assert len(findings) == 2
    by_category = {f.category: f for f in findings}
    assert by_category["sca"].rule_id == "CVE-2020-27350"
    assert by_category["sca"].severity == "medium"
    assert by_category["secrets"].rule_id == "aws-secret-access-key"
    assert by_category["secrets"].severity == "critical"

    # Credentials went through as env vars, never as CLI args (not visible via `ps`).
    assert captured_env["TRIVY_USERNAME"] == "me"
    assert captured_env["TRIVY_PASSWORD"] == "hunter2"
    assert "TRIVY_REGISTRY_TOKEN" not in captured_env


def test_run_registry_scan_omits_unset_credential_env_vars(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        assert "TRIVY_USERNAME" not in env
        assert "TRIVY_PASSWORD" not in env
        assert "TRIVY_REGISTRY_TOKEN" not in env
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_TRIVY_IMAGE_SARIF))
        return _fake_proc()

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    findings = image_scanner.run_registry_scan("alpine:3.18")
    assert len(findings) == 2


def test_run_registry_scan_passes_registry_token(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        assert env["TRIVY_REGISTRY_TOKEN"] == "tok_abc"
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_TRIVY_IMAGE_SARIF))
        return _fake_proc()

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    image_scanner.run_registry_scan("myregistry.jfrog.io/docker-local/app:1.0", registry_token="tok_abc")


def test_run_registry_scan_passes_insecure_flag(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        assert "--insecure" in args
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_TRIVY_IMAGE_SARIF))
        return _fake_proc()

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    image_scanner.run_registry_scan("registry.internal/app:1.0", insecure=True)


def test_run_registry_scan_raises_unavailable_when_trivy_missing(monkeypatch):
    def fake_require(binary):
        raise ScannerUnavailable(f"'{binary}' is not installed")

    monkeypatch.setattr(image_scanner, "require", fake_require)
    with pytest.raises(ScannerUnavailable):
        image_scanner.run_registry_scan("alpine:3.18")


def test_run_registry_scan_raises_execution_error_on_nonzero_exit(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        return _fake_proc(returncode=1, stderr="FATAL Fatal error: DENIED: denied")

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    with pytest.raises(ScannerExecutionError, match="DENIED"):
        image_scanner.run_registry_scan("private.example/secret:1.0", username="bad", password="wrong")


def test_run_registry_scan_raises_execution_error_when_no_output_produced(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        return _fake_proc(returncode=0)  # no file written

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    with pytest.raises(ScannerExecutionError):
        image_scanner.run_registry_scan("alpine:3.18")


def test_run_registry_scan_raises_execution_error_on_timeout(monkeypatch):
    import subprocess

    def fake_run(args, env, capture_output, text, timeout, check):
        raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    with pytest.raises(ScannerExecutionError, match="timed out"):
        image_scanner.run_registry_scan("alpine:3.18", timeout=1)


def test_run_registry_scan_raises_unavailable_on_file_not_found(monkeypatch):
    def fake_run(args, env, capture_output, text, timeout, check):
        raise FileNotFoundError("trivy binary vanished")

    monkeypatch.setattr(image_scanner, "require", lambda binary: "/usr/local/bin/trivy")
    monkeypatch.setattr(image_scanner.subprocess, "run", fake_run)

    with pytest.raises(ScannerUnavailable):
        image_scanner.run_registry_scan("alpine:3.18")
