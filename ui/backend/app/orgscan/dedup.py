"""Collapses findings that fingerprint identically -- the same (repo, file,
rule, line) reported more than once, whether that's two scanners agreeing
on the same line (e.g. Bandit and Semgrep both flagging a `shell=True`
call) or the same scanner run twice. Keeps the most severe instance and
records which scanners actually caught it.
"""
from __future__ import annotations

from .models import SEVERITY_RANK, Finding


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_fingerprint: dict[str, Finding] = {}
    scanners_by_fingerprint: dict[str, set[str]] = {}

    for f in findings:
        scanners_by_fingerprint.setdefault(f.fingerprint, set()).add(f.scanner)
        existing = by_fingerprint.get(f.fingerprint)
        if existing is None or SEVERITY_RANK[f.severity] < SEVERITY_RANK[existing.severity]:
            by_fingerprint[f.fingerprint] = f

    deduped = []
    for fingerprint, finding in by_fingerprint.items():
        scanners = sorted(scanners_by_fingerprint[fingerprint])
        if len(scanners) > 1:
            finding.scanner = "+".join(scanners)
        deduped.append(finding)

    return sorted(deduped, key=lambda f: (SEVERITY_RANK[f.severity], f.repository, f.file, f.line or 0))
