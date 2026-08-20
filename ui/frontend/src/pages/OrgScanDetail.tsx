import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import SeverityLevelBadge from "../components/SeverityLevelBadge";
import StatusBadge from "../components/StatusBadge";
import type { OrgScanDetail as OrgScanDetailType, Severity } from "../types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const STAT_TILE_CLASS: Record<Severity, string> = {
  critical: "critical",
  high: "danger",
  medium: "warning",
  low: "",
  info: "",
};

const REPORT_FORMATS: { fmt: "html" | "pdf" | "sarif" | "json" | "csv"; label: string }[] = [
  { fmt: "html", label: "HTML" },
  { fmt: "pdf", label: "PDF" },
  { fmt: "sarif", label: "SARIF" },
  { fmt: "json", label: "JSON" },
  { fmt: "csv", label: "CSV" },
];

export default function OrgScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<OrgScanDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const load = () => {
      api
        .getOrgScan(id)
        .then((s) => {
          if (stop) return;
          setScan(s);
          if (s.status === "queued" || s.status === "running") {
            timer = setTimeout(load, 3000);
          }
        })
        .catch((e) => !stop && setError(e.message ?? String(e)));
    };
    load();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [id]);

  if (error) {
    return <div className="banner error">{error}</div>;
  }
  if (!scan) {
    return <p>Loading…</p>;
  }

  const inProgress = scan.status === "queued" || scan.status === "running";

  return (
    <>
      <div className="page-header">
        <h1>{scan.org}</h1>
        <p>
          Started {new Date(scan.created_at).toLocaleString()} · <StatusBadge status={scan.status} />
        </p>
      </div>

      {scan.error && <div className="banner error">{scan.error}</div>}
      {inProgress && (
        <div className="banner warning">
          Scanning {scan.completed_repos} of {scan.total_repos || "…"} repositories.
        </div>
      )}

      <div className="stat-row">
        {SEVERITIES.map((sev) => (
          <div key={sev} className={`stat-tile ${STAT_TILE_CLASS[sev]}`}>
            <div className="num">{scan.severity_totals[sev]}</div>
            <div className="label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</div>
          </div>
        ))}
      </div>

      <div className="stat-row">
        <div className="stat-tile">
          <div className="num">
            {scan.completed_repos}/{scan.total_repos}
          </div>
          <div className="label">Repositories scanned</div>
        </div>
        <div className="stat-tile">
          <div className="num">{scan.repos_with_findings}</div>
          <div className="label">With findings</div>
        </div>
        <div className="stat-tile">
          <div className="num">{scan.issues_created}</div>
          <div className="label">Issues created</div>
        </div>
        <div className="stat-tile">
          <div className="num">{scan.email_sent ? "Sent" : "—"}</div>
          <div className="label">Email report</div>
        </div>
      </div>

      {scan.status === "completed" && (
        <div className="card">
          <h2>Reports</h2>
          <div className="toolbar">
            {REPORT_FORMATS.map(({ fmt, label }) => (
              <a key={fmt} className="btn" href={api.orgScanReportUrl(scan.id, fmt)} target="_blank" rel="noreferrer">
                Download {label}
              </a>
            ))}
          </div>
        </div>
      )}

      {scan.repositories.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            {inProgress ? "Waiting for the first repository to finish…" : "No repositories found."}
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Technologies</th>
                <th>Findings</th>
                <th>Highest severity</th>
                <th>Issue</th>
              </tr>
            </thead>
            <tbody>
              {scan.repositories.map((repo) => {
                const highest = SEVERITIES.find((sev) => repo.severity_counts[sev] > 0);
                return (
                  <tr key={repo.repository}>
                    <td>
                      <a href={`https://github.com/${repo.repository}`} target="_blank" rel="noreferrer">
                        {repo.repository}
                      </a>
                      {repo.error && <div className="help">Error: {repo.error}</div>}
                      {Object.keys(repo.scanners_skipped).length > 0 && (
                        <div className="help">
                          Skipped: {Object.entries(repo.scanners_skipped).map(([s, why]) => `${s} (${why})`).join(", ")}
                        </div>
                      )}
                    </td>
                    <td>{repo.technologies.join(", ") || "—"}</td>
                    <td>{repo.finding_count}</td>
                    <td>{highest ? <SeverityLevelBadge severity={highest} /> : "—"}</td>
                    <td>
                      {repo.issue?.issue_url ? (
                        <a href={repo.issue.issue_url} target="_blank" rel="noreferrer">
                          {repo.issue.action === "created" ? "Created" : "Existing"}
                        </a>
                      ) : repo.issue?.action === "failed" ? (
                        <span className="badge danger">Failed</span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
