import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import FindingsView from "../components/FindingsView";
import StatusBadge from "../components/StatusBadge";
import type { JobDetail as JobDetailType, ScanResults } from "../types";

export default function JobDetail() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<JobDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [resultsError, setResultsError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let stop = false;
    const load = () => {
      api
        .getScan(id)
        .then((j) => {
          if (stop) return;
          setJob(j);
          if (j.status === "queued" || j.status === "running") {
            timer = setTimeout(load, 2000);
          }
        })
        .catch((e) => !stop && setError(e.message ?? String(e)));
    };
    let timer: ReturnType<typeof setTimeout>;
    load();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [id]);

  useEffect(() => {
    if (job?.status === "completed" && id) {
      api
        .getScanResults(id)
        .then(setResults)
        .catch((e) => setResultsError(e.message ?? String(e)));
    }
  }, [job?.status, id]);

  if (error) {
    return <div className="banner error">{error}</div>;
  }
  if (!job) {
    return <p>Loading…</p>;
  }

  return (
    <>
      <div className="page-header">
        <h1>
          {job.report_name} <StatusBadge status={job.status} />
        </h1>
        <p>
          {job.provider} &middot; created {new Date(job.created_at).toLocaleString()}
          {job.finished_at && <> &middot; finished {new Date(job.finished_at).toLocaleString()}</>}
        </p>
      </div>

      {job.error && <div className="banner error">{job.error}</div>}

      {(job.status === "queued" || job.status === "running") && (
        <div className="card">
          <div className="empty-state">
            {job.status === "queued" ? "Waiting in queue…" : "Scan is running — this page updates automatically."}
          </div>
        </div>
      )}

      {job.log && (
        <div className="card">
          <h2>Engine log</h2>
          <div className="log-output">{job.log}</div>
        </div>
      )}

      {job.status === "completed" && (
        <>
          {resultsError && <div className="banner error">{resultsError}</div>}
          {results && <FindingsView results={results} />}
        </>
      )}
    </>
  );
}
