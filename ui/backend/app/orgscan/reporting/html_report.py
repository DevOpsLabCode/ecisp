"""Self-contained HTML report (inline CSS, no external assets) -- readable
directly, and also the source `pdf_report.py` renders to PDF via
WeasyPrint, so both formats stay visually consistent by construction.
"""
from __future__ import annotations

import html
from datetime import UTC, datetime

from ..models import SEVERITIES, RepoScanResult

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def to_html(org: str, repo_results: list[RepoScanResult]) -> str:
    totals = dict.fromkeys(SEVERITIES, 0)
    for r in repo_results:
        for sev, count in r.severity_counts().items():
            totals[sev] += count

    repos_with_findings = sum(1 for r in repo_results if r.findings)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    summary_tiles = "".join(
        f'<div class="tile"><div class="tile-value" style="color:{_SEVERITY_COLOR[s]}">{totals[s]}</div>'
        f'<div class="tile-label">{s.capitalize()}</div></div>'
        for s in SEVERITIES
    )

    repo_sections = []
    for r in repo_results:
        if not r.findings and not r.error:
            continue
        rows = "".join(
            f"<tr>"
            f'<td><span class="badge" style="background:{_SEVERITY_COLOR[f.severity]}">{_esc(f.severity)}</span></td>'
            f"<td>{_esc(f.scanner)}</td>"
            f"<td><code>{_esc(f.rule_id)}</code></td>"
            f"<td>{_esc(f.file)}{f':{f.line}' if f.line else ''}</td>"
            f"<td>{_esc(f.message)}</td>"
            f"</tr>"
            for f in r.findings
        )
        error_note = f'<p class="error-note">Scan error: {_esc(r.error)}</p>' if r.error else ""
        skipped_note = (
            f'<p class="skip-note">Skipped: {_esc(", ".join(f"{k} ({v})" for k, v in r.scanners_skipped.items()))}</p>'
            if r.scanners_skipped
            else ""
        )
        repo_sections.append(
            f"""
            <section class="repo">
              <h2>{_esc(r.repository)}</h2>
              <p class="meta">Technologies: {_esc(", ".join(r.technologies) or "none detected")}
                 &middot; Scanners run: {_esc(", ".join(r.scanners_run) or "none")}</p>
              {error_note}
              {skipped_note}
              <table>
                <thead><tr><th>Severity</th><th>Scanner</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead>
                <tbody>{rows}</tbody>
              </table>
            </section>
            """
        )

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Scan Report - {_esc(org)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #0f172a; }}
  body {{ color: #e2e8f0; margin: 0; padding: 32px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .subtitle {{ color: #94a3b8; margin-top: 0; margin-bottom: 24px; }}
  .tiles {{ display: flex; gap: 12px; margin-bottom: 32px; flex-wrap: wrap; }}
  .tile {{ background: #1e293b; border-radius: 8px; padding: 16px 20px; min-width: 100px; }}
  .tile-value {{ font-size: 28px; font-weight: 700; }}
  .tile-label {{ color: #94a3b8; font-size: 13px; margin-top: 4px; }}
  .repo {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .repo h2 {{ margin: 0 0 4px 0; font-size: 16px; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-top: 0; }}
  .error-note {{ color: #f87171; font-size: 13px; }}
  .skip-note {{ color: #fbbf24; font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th {{ text-align: left; color: #94a3b8; border-bottom: 1px solid #334155; padding: 8px; }}
  td {{ padding: 8px; border-bottom: 1px solid #334155; vertical-align: top; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase; }}
  footer {{ color: #64748b; font-size: 12px; margin-top: 32px; }}
</style>
</head>
<body>
  <h1>Security Scan Report &mdash; {_esc(org)}</h1>
  <p class="subtitle">Generated {generated_at} &middot; {len(repo_results)} repositories scanned
     &middot; {repos_with_findings} with findings</p>
  <div class="tiles">{summary_tiles}</div>
  {"".join(repo_sections) or '<p>No findings.</p>'}
  <footer>A DevOps Lab product. Author: Stan Zvenigorodskiy.</footer>
</body>
</html>
"""
