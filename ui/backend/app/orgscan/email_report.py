"""Sends the scan summary + attached reports by email, using stdlib
`smtplib` against a configurable SMTP relay. Sent for every completed
scan regardless of whether anything was found, per the design this
implements -- a clean scan is still a result worth confirming landed.

SMTP settings come from environment variables so no credentials are ever
hardcoded or passed through the API:
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USERNAME, SMTP_PASSWORD,
  SMTP_FROM, SMTP_USE_TLS (default "true")

If SMTP_HOST isn't set, `send_report` is a documented no-op (returns
False) rather than raising -- org scanning is still fully usable without
email configured; the recipient just won't get anything.
"""
from __future__ import annotations

import os
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage

from .models import RepoScanResult


def is_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST"))


def _summary_text(org: str, repo_results: list[RepoScanResult], status: str) -> str:
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    with_findings = 0
    for r in repo_results:
        counts = r.severity_counts()
        for sev in totals:
            totals[sev] += counts[sev]
        if r.findings:
            with_findings += 1

    return (
        f"Organization: {org}\n"
        f"Repositories scanned: {len(repo_results)}\n"
        f"Repositories with findings: {with_findings}\n"
        f"Critical: {totals['critical']}\n"
        f"High: {totals['high']}\n"
        f"Medium: {totals['medium']}\n"
        f"Low: {totals['low']}\n"
        f"Scan status: {status}\n"
    )


def send_report(
    to_address: str,
    org: str,
    repo_results: list[RepoScanResult],
    status: str,
    attachments: dict[str, tuple[bytes, str]],
) -> bool:
    """`attachments` maps filename -> (content_bytes, mime_subtype), e.g.
    {"security-report.html": (b"...", "html")}. Returns True if a send was
    attempted (doesn't guarantee delivery -- SMTP accepted the message)."""
    if not is_configured():
        return False

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    from_addr = os.environ.get("SMTP_FROM", username or "golem-scanner@localhost")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() != "false"

    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    msg = EmailMessage()
    msg["Subject"] = f"GitHub Security Scan Report - {org} - {date_str}"
    msg["From"] = from_addr
    msg["To"] = to_address
    msg.set_content(_summary_text(org, repo_results, status))

    for filename, (content, subtype) in attachments.items():
        maintype = "application" if subtype in ("json", "pdf", "sarif") else "text"
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)

    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)
    return True
