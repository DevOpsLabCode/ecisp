"""Groups a repo's findings into one GitHub Issue per repo per scan,
rather than one issue per finding -- an org with a few thousand findings
across a hundred repos would otherwise flood every repo's issue tracker.

Only Critical/High findings trigger issue creation (the threshold chosen
when this feature was scoped); Medium/Low/Info still show up in every
report format, just not as GitHub Issues.
"""
from __future__ import annotations

from datetime import UTC, datetime

from .github_client import GitHubClient
from .models import RepoScanResult

ISSUE_THRESHOLD_SEVERITIES = ("critical", "high")
ISSUE_LABELS = ["security", "sast", "automated"]


def issue_title(repository: str, scan_date: str) -> str:
    repo_name = repository.split("/", 1)[-1]
    return f"[Security] SAST findings - {repo_name} - {scan_date}"


def issue_body(result: RepoScanResult, scan_date: str) -> str:
    counts = result.severity_counts()
    lines = [
        f"**Repository:** {result.repository}",
        f"**Security Scan:** {scan_date}",
        "",
        f"- Critical: {counts['critical']}",
        f"- High: {counts['high']}",
        f"- Medium: {counts['medium']}",
        f"- Low: {counts['low']}",
        "",
        "**Issues:**",
        "",
    ]
    qualifying = [f for f in result.findings if f.severity in ISSUE_THRESHOLD_SEVERITIES]
    for i, f in enumerate(qualifying, start=1):
        location = f"{f.file}" + (f":{f.line}" if f.line else "")
        lines.append(f"{i}. **{f.message}** ({f.severity.upper()}, `{f.rule_id}` via {f.scanner})")
        lines.append(f"   - `{location}`")
        if f.remediation:
            lines.append(f"   - Remediation: {f.remediation}")
    lines.append("")
    lines.append(f"<!-- ecisp-org-scan fingerprint-set: {','.join(sorted(f.fingerprint for f in qualifying))} -->")
    return "\n".join(lines)


def create_issues_for_scan(
    gh: GitHubClient, repo_results: list[RepoScanResult], scan_date: str | None = None
) -> dict[str, dict]:
    """Creates (or reuses an existing) grouped issue per repo with at least
    one Critical/High finding. Returns {repository: {"action": ..., "issue_url": ...}}.
    """
    scan_date = scan_date or datetime.now(UTC).strftime("%Y-%m-%d")
    outcomes: dict[str, dict] = {}

    for result in repo_results:
        qualifying = [f for f in result.findings if f.severity in ISSUE_THRESHOLD_SEVERITIES]
        if not qualifying:
            continue

        owner, repo = result.repository.split("/", 1)
        title = issue_title(result.repository, scan_date)

        existing = gh.find_open_issue_by_title(owner, repo, title)
        if existing:
            outcomes[result.repository] = {"action": "skipped_existing", "issue_url": existing["html_url"]}
            continue

        try:
            issue = gh.create_issue(owner, repo, title, issue_body(result, scan_date), ISSUE_LABELS)
            outcomes[result.repository] = {"action": "created", "issue_url": issue["html_url"]}
        except Exception as exc:  # noqa: BLE001 -- one repo's issue-creation failure (e.g. issues disabled) shouldn't abort the rest
            outcomes[result.repository] = {"action": "failed", "error": str(exc)[:300]}

    return outcomes
