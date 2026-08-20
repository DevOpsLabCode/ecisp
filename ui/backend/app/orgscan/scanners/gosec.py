"""Gosec -- Go SAST. Verified against a real gosec install (Docker image
build): `-fmt=sarif -out=<file>` produces valid SARIF 2.1.0, exits 0
regardless of findings.

gosec's own binary is only half of the story -- it shells out to the `go`
toolchain itself to load and type-check the target package, so the
Dockerfile installs the full Go toolchain alongside the compiled gosec
binary, not just the binary (verified: without `go` on PATH, gosec fails
with "go command required, not found" and silently produces no SARIF
output rather than a clear error).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "gosec"


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("gosec")
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out_path = tmp.name
    try:
        run_capture(
            ["gosec", "-fmt=sarif", f"-out={out_path}", "-quiet", "./..."],
            cwd=repo_dir,
            ok_exit_codes=(0, 1),
        )
        sarif_path = Path(out_path)
        if not sarif_path.exists() or sarif_path.stat().st_size == 0:
            raise ScannerExecutionError("gosec did not produce SARIF output")
        sarif_text = sarif_path.read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)

    return parse_sarif(
        sarif_text,
        repository=repository,
        scanner=SCANNER_ID,
        category="sast",
        remediation_hint="See the Gosec rule ID's documentation (github.com/securego/gosec) for the fix pattern.",
    )
