"""Trivy filesystem scan -- SCA (dependency vulnerabilities) and secret
detection in one pass. Verified against a real trivy 0.74.0 install:
`trivy fs --scanners vuln,secret --format sarif` produces valid SARIF
2.1.0, exits 0 regardless of findings (no `--exit-code` flag passed), and
mixes both finding kinds into one `results` array -- distinguished only by
whether the matched rule's `properties.tags` includes "secret" (SCA
findings carry a CVE/GHSA-style `ruleId` and no such tag).

Deliberately restricted to `vuln,secret` -- misconfig scanning is covered
by checkov.py already, and running it here too would just duplicate
findings under a different scanner name.

One real gotcha found while verifying this: trivy's secret rules
allowlist several well-known *documentation* example values (e.g. AWS's
own "AKIAIOSFODNN7EXAMPLE" from their public docs) to cut false-positive
noise -- a fixture using that literal value won't be flagged, which isn't
a bug in this adapter, just something to know before assuming a test
fixture "should" have matched.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ..models import Finding
from ..normalize import parse_sarif
from .base import ScannerExecutionError, require, run_capture

SCANNER_ID = "trivy"


def _category_for(result: dict, rule: dict) -> str:
    tags = rule.get("properties", {}).get("tags", [])
    return "secrets" if "secret" in tags else "sca"


def run(repo_dir: Path, repository: str) -> list[Finding]:
    require("trivy")
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        out_path = tmp.name
    try:
        run_capture(
            ["trivy", "fs", "--scanners", "vuln,secret", "--format", "sarif", "--output", out_path, "."],
            cwd=repo_dir,
            ok_exit_codes=(0,),
            timeout=900,
        )
        sarif_path = Path(out_path)
        if not sarif_path.exists() or sarif_path.stat().st_size == 0:
            raise ScannerExecutionError("trivy did not produce SARIF output")
        sarif_text = sarif_path.read_text()
    finally:
        Path(out_path).unlink(missing_ok=True)

    return parse_sarif(
        sarif_text,
        repository=repository,
        scanner=SCANNER_ID,
        category="sca",  # overridden per-result by category_fn below
        remediation_hint="For SCA findings, upgrade to the fixed version named in the message. For secrets, "
        "rotate the credential immediately and remove it from source (git history included).",
        category_fn=_category_for,
    )
