"""Brakeman -- Rails SAST. Verified against a real brakeman install:
`-f json -q` prints `{"warnings": [...], "errors": [...], ...}` to stdout,
and the CLI exits 3 when warnings are present (0 when clean) -- no native
SARIF output, so this is a bespoke JSON parser rather than going through
`normalize.parse_sarif`.

Only runs when tech_detect found a Gemfile / config/application.rb --
brakeman itself will simply report "not a Rails application" against
anything else, which isn't useful to surface as a finding.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from ..severity import brakeman as brakeman_severity
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "brakeman"


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("brakeman")
    stdout = run_capture(
        ["brakeman", "-f", "json", "-q", "."],
        cwd=repo_dir,
        ok_exit_codes=(0, 3),
    )
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError(f"brakeman produced invalid JSON: {exc}") from exc

    findings: list[Finding] = []
    for w in data.get("warnings", []):
        findings.append(
            Finding(
                repository=repository,
                file=w.get("file", "unknown"),
                line=w.get("line"),
                scanner=SCANNER_ID,
                rule_id=w.get("warning_type", w.get("check_name", "unknown")),
                severity=brakeman_severity(w.get("confidence", "")),
                category="sast",
                message=w.get("message", "Brakeman warning"),
                remediation=w.get("link"),
            )
        )
    return findings
