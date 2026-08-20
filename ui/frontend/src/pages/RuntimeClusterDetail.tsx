import { Fragment, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import SeverityLevelBadge from "../components/SeverityLevelBadge";
import type { RuntimeClusterDetail as RuntimeClusterDetailType, Severity } from "../types";

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

export default function RuntimeClusterDetail() {
  const { id } = useParams<{ id: string }>();
  const [cluster, setCluster] = useState<RuntimeClusterDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    const load = () => {
      api
        .getRuntimeCluster(id)
        .then((c) => {
          if (!stop) setCluster(c);
        })
        .catch((e) => !stop && setError(e.message ?? String(e)));
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      stop = true;
      clearInterval(interval);
    };
  }, [id]);

  const filteredFindings = useMemo(() => {
    if (!cluster) return [];
    const q = search.trim().toLowerCase();
    return cluster.findings
      .filter((f) => severityFilter.has(f.severity))
      .filter((f) => !q || `${f.file} ${f.rule_id} ${f.message}`.toLowerCase().includes(q))
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [cluster, severityFilter, search]);

  const toggleSeverity = (sev: Severity) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  if (error) {
    return <div className="banner error">{error}</div>;
  }
  if (!cluster) {
    return <p>Loading…</p>;
  }

  return (
    <>
      <div className="page-header">
        <h1>{cluster.name}</h1>
        <p>
          Registered {new Date(cluster.created_at).toLocaleString()}
          {cluster.last_event_at
            ? ` · Last event ${new Date(cluster.last_event_at).toLocaleString()}`
            : " · No events received yet"}
        </p>
      </div>

      {cluster.finding_count === 0 ? (
        <div className="banner warning">
          Waiting for events from the sensor. If you just ran the install script, it can take a
          minute for the DaemonSet to become Ready on every node.
        </div>
      ) : (
        <>
          <div className="stat-row">
            {SEVERITIES.map((sev) => (
              <div key={sev} className={`stat-tile ${STAT_TILE_CLASS[sev]}`}>
                <div className="num">{cluster.severity_counts[sev]}</div>
                <div className="label">{sev.charAt(0).toUpperCase() + sev.slice(1)}</div>
              </div>
            ))}
          </div>

          <div className="card">
            <h2>Reports</h2>
            <div className="toolbar">
              {REPORT_FORMATS.map(({ fmt, label }) => (
                <a
                  key={fmt}
                  className="btn"
                  href={api.runtimeClusterReportUrl(cluster.id, fmt)}
                  target="_blank"
                  rel="noreferrer"
                >
                  Download {label}
                </a>
              ))}
            </div>
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
                    <th>Pod / namespace</th>
                    <th style={{ width: 130 }}>Category</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f) => (
                    <Fragment key={f.fingerprint}>
                      <tr
                        className="clickable"
                        onClick={() => setExpanded(expanded === f.fingerprint ? null : f.fingerprint)}
                      >
                        <td>
                          <SeverityLevelBadge severity={f.severity} />
                        </td>
                        <td>{f.file}</td>
                        <td>{f.category}</td>
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
