import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { BatchDetail as BatchDetailType } from "../types";

export default function BatchDetail() {
  const { id } = useParams<{ id: string }>();
  const [batch, setBatch] = useState<BatchDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const load = () => {
      api
        .getBatch(id)
        .then((b) => {
          if (stop) return;
          setBatch(b);
          const counts = b.status_counts;
          const stillRunning = counts.queued > 0 || counts.running > 0;
          if (stillRunning) {
            timer = setTimeout(load, 2000);
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
  if (!batch) {
    return <p>Loading…</p>;
  }

  const counts = batch.status_counts;
  const total = batch.queued_jobs + batch.skipped_rows;

  return (
    <>
      <div className="page-header">
        <h1>{batch.filename}</h1>
        <p>Imported {new Date(batch.created_at).toLocaleString()}</p>
      </div>

      <div className="stat-row">
        <div className="stat-tile">
          <div className="num">{total}</div>
          <div className="label">Rows in file</div>
        </div>
        <div className="stat-tile success">
          <div className="num">{counts.completed}</div>
          <div className="label">Completed</div>
        </div>
        <div className="stat-tile danger">
          <div className="num">{counts.failed}</div>
          <div className="label">Failed</div>
        </div>
        <div className="stat-tile warning">
          <div className="num">{batch.skipped_rows}</div>
          <div className="label">Skipped rows</div>
        </div>
      </div>

      {batch.errors.length > 0 && (
        <div className="card">
          <h2>Skipped rows</h2>
          <table>
            <thead>
              <tr>
                <th style={{ width: 90 }}>Row</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {batch.errors.map((e) => (
                <tr key={e.row_number}>
                  <td>{e.row_number}</td>
                  <td>{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {batch.jobs.length === 0 ? (
        <div className="card">
          <div className="empty-state">No rows in this file produced a valid scan.</div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Report</th>
                <th>Status</th>
                <th>Exit code</th>
              </tr>
            </thead>
            <tbody>
              {batch.jobs.map((job) => (
                <tr key={job.id}>
                  <td>{job.provider}</td>
                  <td>
                    <Link to={`/jobs/${job.id}`}>{job.report_name}</Link>
                  </td>
                  <td>
                    <StatusBadge status={job.status} />
                  </td>
                  <td>{job.exit_code ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
