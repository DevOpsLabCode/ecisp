"""Checkov -- IaC scanner (Terraform, CloudFormation, Kubernetes manifests,
Dockerfiles). Verified against a real checkov install: `-o sarif
--output-file-path <dir>` writes `results_sarif.sarif` into that directory
(it does not print SARIF to stdout), and checkov's own exit code is 0 even
when checks fail unless `--hard-fail-on` is set, so we don't gate on it --
the SARIF file's presence is what matters.

Checkov's free/OSS edition has no severity ranking of its own (that's a
Bridgecrew-platform feature) -- every failed check comes through SARIF as
`level: error`, which `normalize.parse_sarif` maps to "high". That's a
known, documented limitation of the OSS tool, not a bug in this adapter.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "checkov"


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("checkov")
    with tempfile.TemporaryDirectory() as out_dir:
        run_capture(
            ["checkov", "-d", str(repo_dir), "-o", "sarif", "--compact", "--output-file-path", out_dir],
            cwd=repo_dir,
            ok_exit_codes=(0, 1),
        )
        sarif_path = Path(out_dir) / "results_sarif.sarif"
        if not sarif_path.exists():
            raise ScannerExecutionError("checkov did not produce results_sarif.sarif")
        sarif_text = sarif_path.read_text()

    return parse_sarif(
        sarif_text,
        repository=repository,
        scanner=SCANNER_ID,
        category="iac",
        remediation_hint="Review the failed policy's guidance; checkov failures usually map 1:1 to a config change.",
    )
