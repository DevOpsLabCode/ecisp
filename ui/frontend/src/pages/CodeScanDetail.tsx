import { Fragment, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import SeverityLevelBadge from "../components/SeverityLevelBadge";
import StatusBadge from "../components/StatusBadge";
import type { CodeScanDetail as CodeScanDetailType, Severity } from "../types";

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

const ZERO_COUNTS: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

export default function CodeScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<CodeScanDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const [dastTargetUrl, setDastTargetUrl] = useState("");
  const [dastSubmitting, setDastSubmitting] = useState(false);
  const [dastFormError, setDastFormError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const load = () => {
      api
        .getCodeScan(id)
        .then((s) => {
          if (stop) return;
          setScan(s);
          if (s.status === "queued" || s.status === "running" || s.dast_status === "running") {
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

  const filteredFindings = useMemo(() => {
    if (!scan) return [];
    const q = search.trim().toLowerCase();
    return scan.findings
      .filter((f) => severityFilter.has(f.severity))
      .filter((f) => !q || `${f.file} ${f.rule_id} ${f.message}`.toLowerCase().includes(q))
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [scan, severityFilter, search]);

  const toggleSeverity = (sev: Severity) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  const handleRunDast = async () => {
    if (!id || !dastTargetUrl.trim()) return;
    setDastFormError(null);
    setDastSubmitting(true);
    try {
      const updated = await api.runCodeScanDast(id, { target_url: dastTargetUrl.trim() });
      setScan((prev) => (prev ? { ...prev, ...updated } : prev));
    } catch (e) {
      setDastFormError(e instanceof Error ? e.message : String(e));
    } finally {
      setDastSubmitting(false);
    }
  };

  if (error) {
    return <div className="banner error">{error}</div>;
  }
  if (!scan) {
    return <p>Loading…</p>;
  }

  const inProgress = scan.status === "queued" || scan.status === "running";
  const counts = scan.severity_counts ?? ZERO_COUNTS;

  return (
    <>
      <div className="page-header">
        <h1>{scan.source_label}</h1>
        <p>
          {scan.source_type === "upload" ? "Uploaded archive" : "GitHub repository"}
          {scan.branch && <> · branch <code>{scan.branch}</code></>}
          {scan.commit_sha && <> · <code>{scan.commit_sha.slice(0, 12)}</code></>}
          {" · "}
          Started {new Date(scan.created_at).toLocaleString()} · <StatusBadge status={scan.status} />
        </p>
      </div>

      {scan.error && <div className="banner error">{scan.error}</div>}
      {inProgress && <div className="banner warning">Scan in progress…</div>}

      {scan.status === "completed" && (
        <>
          <div className="stat-row">
            {SEVERITIES.map((sev) => (
              <div key={sev} className={`stat-tile ${STAT_TILE_CLASS[sev]}`}>
                <div className="num">{counts[sev]}</div>
                <div className="label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</div>
              </div>
            ))}
          </div>

          <div className="card">
            <h2>Scan details</h2>
            <p className="help">
              Technologies detected: {scan.technologies.join(", ") || "—"}
            </p>
            <p className="help">Scanners run: {scan.scanners_run.join(", ") || "—"}</p>
            {Object.keys(scan.scanners_skipped).length > 0 && (
              <p className="help">
                Skipped: {Object.entries(scan.scanners_skipped).map(([s, why]) => `${s} (${why})`).join(", ")}
              </p>
            )}
          </div>

          <div className="card">
            <h2>Reports</h2>
            <div className="toolbar">
              {REPORT_FORMATS.map(({ fmt, label }) => (
                <a
                  key={fmt}
                  className="btn"
                  href={api.codeScanReportUrl(scan.id, fmt)}
                  target="_blank"
                  rel="noreferrer"
                >
                  Download {label}
                </a>
              ))}
            </div>
          </div>

          <div className="card">
            <h2>DAST (dynamic scan)</h2>
            {scan.dast_status === "not_run" && (
              <>
                <p className="help" style={{ marginBottom: 14 }}>
                  Run OWASP ZAP against a running, authorized instance of this application. Findings
                  merge into the same report as the source scan above.
                </p>
                {dastFormError && <div className="banner error">{dastFormError}</div>}
                <div className="field">
                  <label htmlFor="dast-target-url">Application URL</label>
                  <input
                    id="dast-target-url"
                    type="text"
                    placeholder="https://staging.my-app.example"
                    value={dastTargetUrl}
                    onChange={(e) => setDastTargetUrl(e.target.value)}
                  />
                  <div className="help">Only scan applications you're authorized to test.</div>
                </div>
                <button
                  className="btn primary"
                  onClick={handleRunDast}
                  disabled={!dastTargetUrl.trim() || dastSubmitting}
                >
                  {dastSubmitting ? "Starting…" : "Run DAST"}
                </button>
              </>
            )}
            {scan.dast_status === "running" && (
              <div className="banner warning">Scanning {scan.dast_target_url}…</div>
            )}
            {scan.dast_status === "completed" && (
              <div className="banner success">
                DAST completed against {scan.dast_target_url}. Findings are included above and in
                the reports.
              </div>
            )}
            {scan.dast_status === "failed" && (
              <div className="banner error">{scan.dast_error ?? "DAST scan failed."}</div>
            )}
          </div>

          <div className="card">
            <h2>Findings</h2>
            <div className="toolbar">
              {SEVERITIES.map((sev) => (
                <button
                  key={sev}
                  type="button"
                  className={`method-tab${severityFilter.has(sev) ? " active" : ""}`}
                  onClick={() => toggleSeverity(sev)}
                >
                  {sev}
                </button>
              ))}
              <input
                type="text"
                placeholder="Search findings…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ flex: 1, minWidth: 200 }}
              />
            </div>

            {filteredFindings.length === 0 ? (
              <div className="empty-state">No findings match the current filters.</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 90 }}>Severity</th>
                    <th>File</th>
                    <th style={{ width: 130 }}>Scanner</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f) => (
                    <Fragment key={f.fingerprint}>
                      <tr className="clickable" onClick={() => setExpanded(expanded === f.fingerprint ? null : f.fingerprint)}>
                        <td>
                          <SeverityLevelBadge severity={f.severity} />
                        </td>
                        <td>
                          {f.file}
                          {f.line ? `:${f.line}` : ""}
                        </td>
                        <td>
                          {f.scanner} <span className="help">({f.category})</span>
                        </td>
                        <td>{f.message}</td>
                      </tr>
                      {expanded === f.fingerprint && (
                        <tr>
                          <td colSpan={4} style={{ borderBottom: "1px solid var(--border)" }}>
                            <dl className="finding-detail">
                              <dt>Rule</dt>
                              <dd>{f.rule_id}</dd>
                              {f.remediation && (
                                <>
                                  <dt>Remediation</dt>
                                  <dd>{f.remediation}</dd>
                                </>
                              )}
                            </dl>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </>
  );
}
