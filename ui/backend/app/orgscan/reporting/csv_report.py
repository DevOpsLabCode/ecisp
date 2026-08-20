"""Flat, one-row-per-finding CSV -- the format most easily dropped into a
spreadsheet for triage assignment or ad hoc filtering.
"""
from __future__ import annotations

import csv
import io

from ..models import RepoScanResult

_COLUMNS = [
    "repository",
    "severity",
    "scanner",
    "rule_id",
    "category",
    "file",
    "line",
    "message",
    "remediation",
    "fingerprint",
]


def to_csv(repo_results: list[RepoScanResult]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_COLUMNS)
    writer.writeheader()
    for r in repo_results:
        for f in r.findings:
            writer.writerow(f.to_dict())
    return buf.getvalue()
