import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { OrgScanSummary } from "../types";

export default function OrgScans() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<OrgScanSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api
        .listOrgScans()
        .then((list) => {
          if (!stop) setScans(list);
        })
        .catch((e) => !stop && setError(e.message ?? String(e)));
    };
    load();
    const interval = setInterval(load, 3000);
    return () => {
      stop = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <>
      <div className="page-header">
        <h1>GitHub Org Scan History</h1>
        <p>Every GitHub org/account scan, most recent first.</p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {scans.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            No org scans yet. <Link to="/org-scans/new">Start one</Link>.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Organization</th>
                <th>Started</th>
                <th>Status</th>
                <th style={{ width: 70 }}>Repos</th>
                <th style={{ width: 90 }}>Findings</th>
                <th style={{ width: 90 }}>Issues</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const totals = scan.severity_totals;
                const findingCount = totals.critical + totals.high + totals.medium + totals.low + totals.info;
                return (
                  <tr key={scan.id} className="clickable" onClick={() => navigate(`/org-scans/${scan.id}`)}>
                    <td>
                      <Link to={`/org-scans/${scan.id}`}>{scan.org}</Link>
                    </td>
                    <td>{new Date(scan.created_at).toLocaleString()}</td>
                    <td>
                      <StatusBadge status={scan.status} />
                    </td>
                    <td>
                      {scan.completed_repos}/{scan.total_repos}
                    </td>
                    <td>{findingCount}</td>
                    <td>{scan.issues_created}</td>
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
