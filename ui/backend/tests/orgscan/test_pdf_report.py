"""Needs weasyprint's native pango/cairo libraries -- installed via apt in
CI (see .github/workflows/ui-ci.yml) and via brew locally. Skips cleanly
if they're not present rather than failing the whole suite over an
environment gap unrelated to this code.
"""

import pytest

pytest.importorskip("weasyprint", reason="weasyprint needs native pango/cairo libraries")

from app.orgscan.models import Finding, RepoScanResult  # noqa: E402
from app.orgscan.reporting.pdf_report import to_pdf  # noqa: E402


def test_to_pdf_produces_valid_pdf_bytes():
    findings = [
        Finding(
            repository="org/repo",
            file="a.py",
            line=3,
            scanner="bandit",
            rule_id="B105",
            severity="high",
            category="sast",
            message="hardcoded password",
        )
    ]
    result = RepoScanResult(
        repository="org/repo", technologies=["bandit"], scanners_run=["bandit"], scanners_skipped={}, findings=findings
    )

    pdf_bytes = to_pdf("my-org", [result])
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500
