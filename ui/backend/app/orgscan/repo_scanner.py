"""Runs the applicable scanners against a single cloned repository and
returns a normalized, deduplicated RepoScanResult.

A single scanner failing (tool not installed, or a build-dependent scanner
like SpotBugs/Security Code Scan whose build step fails) is recorded as a
skip with the reason, not a fatal error for the whole repo -- one broken
tool shouldn't take down results from the other seven.
"""
from __future__ import annotations

from pathlib import Path

from . import tech_detect
from .dedup import dedupe
from .models import Finding, RepoScanResult
from .scanners import REGISTRY
from .scanners.base import ScannerExecutionError, ScannerUnavailable


def scan_repo(
    repo_dir: Path,
    repository: str,
    only_scanners: set[str] | None = None,
    exclude_scanners: dict[str, str] | None = None,
) -> RepoScanResult:
    # See github_client.clone()'s comment -- scanner subprocesses report
    # physical paths, so relative-path computation needs to start from a
    # symlink-resolved base too, not just here for /var on macOS.
    repo_dir = repo_dir.resolve()
    technologies = tech_detect.detect(repo_dir)
    applicable = [s for s in technologies if s in REGISTRY]
    if only_scanners is not None:
        applicable = [s for s in applicable if s in only_scanners]

    all_findings: list[Finding] = []
    scanners_run: list[str] = []
    # `exclude_scanners` maps scanner id -> the reason it's excluded (e.g.
    # code_scan_job.py disables SpotBugs/Security Code Scan for uploaded
    # archives specifically, since both compile the target -- running
    # untrusted build tooling -- which a cloned repo's scan doesn't need to
    # rule out). Recorded as a skip with that reason rather than silently
    # dropped, same as any other skip.
    scanners_skipped: dict[str, str] = dict(exclude_scanners or {})
    applicable = [s for s in applicable if s not in scanners_skipped]

    for scanner_id in applicable:
        module = REGISTRY[scanner_id]
        try:
            findings = module.run(repo_dir, repository)
        except ScannerUnavailable as exc:
            scanners_skipped[scanner_id] = f"not installed: {exc}"
            continue
        except ScannerExecutionError as exc:
            scanners_skipped[scanner_id] = str(exc)[:500]
            continue
        except Exception as exc:  # noqa: BLE001 -- a single misbehaving scanner must not abort the repo scan
            scanners_skipped[scanner_id] = f"unexpected error: {exc}"[:500]
            continue
        scanners_run.append(scanner_id)
        all_findings.extend(findings)

    return RepoScanResult(
        repository=repository,
        technologies=technologies,
        scanners_run=scanners_run,
        scanners_skipped=scanners_skipped,
        findings=dedupe(all_findings),
    )
