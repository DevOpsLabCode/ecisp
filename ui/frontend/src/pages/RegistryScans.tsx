import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { RegistryScanSummary } from "../types";

export default function RegistryScans() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<RegistryScanSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api
        .listRegistryScans()
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
        <h1>Container Image Findings</h1>
        <p>Every container image scan, most recent first.</p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {scans.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            No registry scans yet. <Link to="/registry-scan">Start one</Link>.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Image</th>
                <th>Started</th>
                <th>Status</th>
                <th style={{ width: 90 }}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} className="clickable" onClick={() => navigate(`/registry-scans/${scan.id}`)}>
                  <td>
                    <Link to={`/registry-scans/${scan.id}`}>{scan.image_ref}</Link>
                  </td>
                  <td>{new Date(scan.created_at).toLocaleString()}</td>
                  <td>
                    <StatusBadge status={scan.status} />
                  </td>
                  <td>{scan.finding_count ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
