"""Common finding model every scanner adapter normalizes into.

This is the single shape the rest of the pipeline (dedup, reporting, issue
creation, email) operates on -- individual scanners never leak their own
output format past `normalize.py`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    repository: str
    file: str
    scanner: str
    rule_id: str
    severity: str  # one of SEVERITIES
    category: str
    message: str
    line: int | None = None
    remediation: str | None = None
    fingerprint: str = field(default="")

    def __post_init__(self):
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity {self.severity!r}, expected one of {SEVERITIES}")
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        # Same (repo, file, rule, line) reported twice -- by the same
        # scanner on a re-scan, or coincidentally by two scanners -- should
        # collapse to one finding rather than double-counting severity.
        key = f"{self.repository}|{self.file}|{self.rule_id}|{self.line}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "repository": self.repository,
            "file": self.file,
            "line": self.line,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
        }


@dataclass
class RepoScanResult:
    repository: str
    technologies: list[str]
    scanners_run: list[str]
    scanners_skipped: dict[str, str]  # scanner id -> reason skipped
    findings: list[Finding]
    error: str | None = None

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            counts[f.severity] += 1
        return counts
