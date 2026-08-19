import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { BatchSummary } from "../types";

export default function Batches() {
  const navigate = useNavigate();
  const [batches, setBatches] = useState<BatchSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api
        .listBatches()
        .then((list) => {
          if (!stop) setBatches(list);
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
        <h1>Bulk imports</h1>
        <p>Every CSV/XLSX/JSON import, most recent first.</p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {batches.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            No imports yet. <Link to="/bulk-import">Import a file</Link>.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Imported</th>
                <th style={{ width: 90 }}>Queued</th>
                <th style={{ width: 90 }}>Completed</th>
                <th style={{ width: 90 }}>Failed</th>
                <th style={{ width: 90 }}>Skipped</th>
              </tr>
            </thead>
            <tbody>
              {batches.map((batch) => (
                <tr key={batch.id} className="clickable" onClick={() => navigate(`/batches/${batch.id}`)}>
                  <td>
                    <Link to={`/batches/${batch.id}`}>{batch.filename}</Link>
                  </td>
                  <td>{new Date(batch.created_at).toLocaleString()}</td>
                  <td>{batch.queued_jobs}</td>
                  <td>{batch.status_counts.completed}</td>
                  <td>{batch.status_counts.failed}</td>
                  <td>{batch.skipped_rows}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
