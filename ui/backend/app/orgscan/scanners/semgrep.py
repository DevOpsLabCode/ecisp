"""Semgrep -- multi-language SAST. Verified against a real semgrep install:
`--sarif --output <path>` writes valid SARIF 2.1.0, and semgrep exits 1
when findings are present (0 when clean).

Runs against a small ruleset bundled in this repo
(`rulesets/semgrep-default.yml`) rather than `--config auto`, which pulls
rules from the Semgrep Registry over the network on every run -- that
makes CI and offline/air-gapped scans non-deterministic and a hard
dependency on an external service staying up. Set the `SEMGREP_CONFIG` env
var to point at a registry config (e.g. `p/security-audit`) or a larger
local ruleset instead.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import require, run_capture

SCANNER_ID = "semgrep"

_DEFAULT_RULESET = str(Path(__file__).resolve().parent.parent / "rulesets" / "semgrep-default.yml")


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("semgrep")
    config = os.environ.get("SEMGREP_CONFIG", _DEFAULT_RULESET)

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out_path = tmp.name
    try:
        run_capture(
            ["semgrep", "--config", config, "--sarif", "--output", out_path, "--metrics=off", "."],
            cwd=repo_dir,
            ok_exit_codes=(0, 1),
            timeout=900,
        )
        sarif_text = Path(out_path).read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)

    return parse_sarif(
        sarif_text,
        repository=repository,
        scanner=SCANNER_ID,
        category="sast",
        remediation_hint="Review the matched pattern; Semgrep findings usually point directly at the vulnerable line.",
    )
