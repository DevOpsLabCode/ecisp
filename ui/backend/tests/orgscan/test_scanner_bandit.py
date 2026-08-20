"""Shape captured from a real bandit + bandit-sarif-formatter install; see
scanners/bandit.py's docstring, including the real "Working..." progress-bar
preamble bug this test also guards against.
"""

import json

import pytest

from app.orgscan.scanners import bandit
from app.orgscan.scanners.base import ScannerExecutionError

_REAL_BANDIT_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Bandit", "rules": [{"id": "B105"}]}},
            "results": [
                {
                    "ruleId": "B105",
                    "level": "note",
                    "properties": {"issue_confidence": "HIGH", "issue_severity": "LOW"},
                    "message": {"text": "Possible hardcoded password: 'x'"},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "bad.py"}, "region": {"startLine": 3}}}
                    ],
                }
            ],
        }
    ],
}


def test_bandit_parses_normal_output(tmp_path, monkeypatch):
    monkeypatch.setattr(bandit, "require", lambda binary: "/usr/bin/bandit")
    monkeypatch.setattr(bandit, "run_capture", lambda *a, **k: json.dumps(_REAL_BANDIT_SARIF))

    findings = bandit.run(tmp_path, "org/repo")
    assert len(findings) == 1
    assert findings[0].rule_id == "B105"
    assert findings[0].severity == "low"  # from properties.issue_severity, not the "note" level


def test_bandit_strips_progress_bar_preamble(tmp_path, monkeypatch):
    # Reproduced against this project's own repo: bandit prints a `rich`
    # progress bar to stdout ahead of the JSON on a large enough tree.
    preamble = "Working... ━━━ 100% 0:00:04\n"
    monkeypatch.setattr(bandit, "require", lambda binary: "/usr/bin/bandit")
    monkeypatch.setattr(bandit, "run_capture", lambda *a, **k: preamble + json.dumps(_REAL_BANDIT_SARIF))

    findings = bandit.run(tmp_path, "org/repo")
    assert len(findings) == 1


def test_bandit_raises_when_no_json_present(tmp_path, monkeypatch):
    monkeypatch.setattr(bandit, "require", lambda binary: "/usr/bin/bandit")
    monkeypatch.setattr(bandit, "run_capture", lambda *a, **k: "no json here at all")
    with pytest.raises(ScannerExecutionError):
        bandit.run(tmp_path, "org/repo")
