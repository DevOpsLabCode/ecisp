"""Renders the same HTML report to PDF via WeasyPrint (pure-Python, no
headless browser dependency) so the HTML and PDF outputs never drift.
"""
from __future__ import annotations

from ..models import RepoScanResult
from .html_report import to_html


def to_pdf(org: str, repo_results: list[RepoScanResult]) -> bytes:
    from weasyprint import HTML  # imported lazily -- weasyprint pulls in native

    # cairo/pango libs, which shouldn't be a hard import-time dependency for
    # callers that only need SARIF/JSON/CSV/HTML.
    return HTML(string=to_html(org, repo_results)).write_pdf()
