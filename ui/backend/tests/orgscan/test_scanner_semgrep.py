"""Shape captured from a real semgrep install using this project's bundled
ruleset; see scanners/semgrep.py's docstring.
"""

import json
from pathlib import Path

from app.orgscan.scanners import semgrep

_REAL_SEMGREP_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "rules": [{"id": "hardcoded-secret-assignment", "defaultConfiguration": {"level": "error"}}],
                }
            },
            "results": [
                {
                    "ruleId": "hardcoded-secret-assignment",
                    "message": {"text": "Possible hardcoded secret/credential assigned to a variable."},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "bad.py"}, "region": {"startLine": 3}}}
                    ],
                }
            ],
        }
    ],
}


def test_semgrep_parses_output_written_to_output_flag(tmp_path, monkeypatch):
    def fake_run_capture(args, cwd, ok_exit_codes, timeout=600):
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_SEMGREP_SARIF))
        return ""

    monkeypatch.setattr(semgrep, "require", lambda binary: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep, "run_capture", fake_run_capture)

    findings = semgrep.run(tmp_path, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "hardcoded-secret-assignment"
    assert findings[0].severity == "high"  # falls back to rule's defaultConfiguration.level


def test_semgrep_respects_semgrep_config_env_var(tmp_path, monkeypatch):
    captured = {}

    def fake_run_capture(args, cwd, ok_exit_codes, timeout=600):
        captured["config"] = args[args.index("--config") + 1]
        out_path = args[args.index("--output") + 1]
        Path(out_path).write_text(json.dumps(_REAL_SEMGREP_SARIF))
        return ""

    monkeypatch.setattr(semgrep, "require", lambda binary: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep, "run_capture", fake_run_capture)
    monkeypatch.setenv("SEMGREP_CONFIG", "p/security-audit")

    semgrep.run(tmp_path, "org/repo")
    assert captured["config"] == "p/security-audit"
