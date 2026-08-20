"""Aggregates every repo's findings into one org-wide SARIF 2.1.0 log --
the standardized, tool-agnostic format GitHub's own code-scanning UI (and
any other SARIF consumer) understands, regardless of which of the eight
scanners actually produced a given finding.
"""
from __future__ import annotations

import json

from ..models import RepoScanResult

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(repo_results: list[RepoScanResult]) -> str:
    rules: dict[str, dict] = {}
    results = []

    for repo_result in repo_results:
        for f in repo_result.findings:
            rule_key = f"{f.scanner}:{f.rule_id}"
            if rule_key not in rules:
                rules[rule_key] = {
                    "id": rule_key,
                    "name": f.rule_id,
                    "shortDescription": {"text": f.rule_id},
                    "properties": {"scanner": f.scanner, "category": f.category},
                }
            results.append(
                {
                    "ruleId": rule_key,
                    "level": _LEVEL.get(f.severity, "warning"),
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file},
                                "region": {"startLine": f.line or 1},
                            }
                        }
                    ],
                    "properties": {"severity": f.severity, "repository": f.repository, "fingerprint": f.fingerprint},
                }
            )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "golem-scan",
                        "informationUri": "https://devopslabinc.com",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
