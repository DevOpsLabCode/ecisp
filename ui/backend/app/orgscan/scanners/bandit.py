"""Bandit -- Python SAST. Verified against a real bandit install:
`-f sarif` (via the bandit-sarif-formatter plugin) prints valid SARIF 2.1.0
to stdout, exits 1 when findings are present (0 when clean), and preserves
bandit's own LOW/MEDIUM/HIGH severity in `properties.issue_severity`, which
`normalize.parse_sarif` prefers over the generic SARIF `level`.

On a large enough tree, bandit also prints a `rich`-rendered "Working..."
progress bar to stdout ahead of the JSON (reproduced against this
project's own ~150-file repo -- it doesn't show up on a two-file fixture,
which is why this wasn't caught until a real-repo scan). `-q` didn't
suppress it, so this strips anything before the first `{` defensively
rather than depending on a bandit version/flag to stop doing that.
"""
from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "bandit"


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("bandit")
    stdout = run_capture(
        ["bandit", "-r", ".", "-f", "sarif"],
        cwd=repo_dir,
        ok_exit_codes=(0, 1),
    )
    brace = stdout.find("{")
    if brace == -1:
        raise ScannerExecutionError(f"bandit produced no JSON on stdout: {stdout[-500:]!r}")
    return parse_sarif(
        stdout[brace:],
        repository=repository,
        scanner=SCANNER_ID,
        category="sast",
        remediation_hint="See the Bandit rule's documentation (bandit.readthedocs.io) for the specific fix pattern.",
    )
