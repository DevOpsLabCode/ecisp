import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { RuntimeClusterSummary } from "../types";

export default function RuntimeClusters() {
  const navigate = useNavigate();
  const [clusters, setClusters] = useState<RuntimeClusterSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const load = () => {
      api
        .listRuntimeClusters()
        .then((list) => {
          if (!stop) setClusters(list);
        })
        .catch((e) => !stop && setError(e.message ?? String(e)));
    };
    load();
    const interval = setInterval(load, 5000);
    return () => {
      stop = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <>
      <div className="page-header">
        <h1>Protected Clusters</h1>
        <p>Every registered cluster, with live findings from its eBPF sensor.</p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {clusters.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            No clusters registered yet. <Link to="/runtime-defender/new">Install Golem Defender</Link>.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Cluster</th>
                <th>Registered</th>
                <th>Last event</th>
                <th style={{ width: 90 }}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {clusters.map((cluster) => (
                <tr
                  key={cluster.id}
                  className="clickable"
                  onClick={() => navigate(`/runtime-clusters/${cluster.id}`)}
                >
                  <td>
                    <Link to={`/runtime-clusters/${cluster.id}`}>{cluster.name}</Link>
                  </td>
                  <td>{new Date(cluster.created_at).toLocaleString()}</td>
                  <td>{cluster.last_event_at ? new Date(cluster.last_event_at).toLocaleString() : "—"}</td>
                  <td>{cluster.finding_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
