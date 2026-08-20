"""Full-fidelity JSON report -- every finding, every field, per repo."""
from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import RepoScanResult


def to_json(org: str, repo_results: list[RepoScanResult]) -> str:
    doc = {
        "organization": org,
        "generated_at": datetime.now(UTC).isoformat(),
        "repositories_scanned": len(repo_results),
        "repositories": [
            {
                "repository": r.repository,
                "technologies": r.technologies,
                "scanners_run": r.scanners_run,
                "scanners_skipped": r.scanners_skipped,
                "severity_counts": r.severity_counts(),
                "error": r.error,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in repo_results
        ],
    }
    return json.dumps(doc, indent=2)
