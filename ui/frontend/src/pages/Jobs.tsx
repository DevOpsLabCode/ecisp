import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { JobSummary } from "../types";

export default function Jobs() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api
        .listScans()
        .then((list) => {
          if (!stop) setJobs(list);
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
        <h1>CSPM Findings</h1>
        <p>All scans launched from this UI, most recent first.</p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {jobs.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            No scans yet. <Link to="/">Launch one</Link>.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Provider</th>
                <th>Report</th>
                <th>Status</th>
                <th>Created</th>
                <th>Exit code</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id} className="clickable" onClick={() => navigate(`/jobs/${job.id}`)}>
                  <td>{job.provider}</td>
                  <td>
                    <Link to={`/jobs/${job.id}`}>{job.report_name}</Link>
                  </td>
                  <td>
                    <StatusBadge status={job.status} />
                  </td>
                  <td>{new Date(job.created_at).toLocaleString()}</td>
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
