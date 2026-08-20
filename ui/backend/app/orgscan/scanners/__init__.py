"""Pluggable scanner registry. Adding a ninth tool later means writing one
adapter module (SCANNER_ID + run(repo_dir, repository) -> list[Finding])
and adding one line here -- nothing else in the pipeline needs to change.
"""
from __future__ import annotations

from . import (
    bandit,
    brakeman,
    checkov,
    eslint_security,
    gosec,
    security_code_scan,
    semgrep,
    spotbugs,
    trivy_sca_secrets,
)

REGISTRY = {
    m.SCANNER_ID: m
    for m in (
        checkov,
        bandit,
        semgrep,
        gosec,
        spotbugs,
        eslint_security,
        brakeman,
        security_code_scan,
        trivy_sca_secrets,
    )
}
