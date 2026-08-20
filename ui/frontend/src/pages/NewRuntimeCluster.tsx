import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { RuntimeClusterDetail } from "../types";

export default function NewRuntimeCluster() {
  const [name, setName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cluster, setCluster] = useState<RuntimeClusterDetail | null>(null);
  const [copied, setCopied] = useState(false);

  const handleSubmit = async () => {
    if (!name.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const created = await api.createRuntimeCluster({ name: name.trim() });
      setCluster(created);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const installCommand = cluster
    ? `curl -fsSL ${api.runtimeClusterInstallScriptUrl(cluster.id)} | bash`
    : "";

  const handleCopy = async () => {
    await navigator.clipboard.writeText(installCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <div className="page-header">
        <h1>Install Golem Defender</h1>
        <p>
          Runtime protection for EKS, AKS, GKE, OpenShift, or any standard Kubernetes cluster — an
          eBPF sensor that watches every node for suspicious process activity, file access, and
          network behavior, and reports what it finds here. Detect and report only: nothing is ever
          blocked or killed automatically.
        </p>
      </div>

      {error && <div className="banner error">{error}</div>}

      {!cluster ? (
        <div className="card">
          <h2>Name this cluster</h2>
          <div className="field">
            <label htmlFor="runtime-cluster-name">Cluster name</label>
            <input
              id="runtime-cluster-name"
              type="text"
              placeholder="prod-eks"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <div className="help">
              Just a label to tell this cluster apart from others — it doesn't need to match your
              real Kubernetes context name.
            </div>
          </div>
          <button className="btn primary" onClick={handleSubmit} disabled={!name.trim() || submitting}>
            {submitting ? "Registering…" : "Register cluster"}
          </button>
        </div>
      ) : (
        <>
          <div className="banner success">
            Cluster "{cluster.name}" registered. Run the command below against whichever cluster your
            current <code>kubectl</code> context points at.
          </div>

          <div className="card">
            <h2>Run this on the cluster</h2>
            <div className="code-block">
              <code>{installCommand}</code>
              <button className="btn" onClick={handleCopy}>
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="help" style={{ marginTop: 10 }}>
              This installs Falco (an open-source eBPF sensor) as a DaemonSet via Helm, one pod per
              node, and points it at this cluster's unique reporting endpoint. Requires{" "}
              <code>helm</code> and <code>kubectl</code> pointed at the target cluster. Read-only
              host-level monitoring — it does not modify or stop anything running in your cluster.
            </div>
          </div>

          <Link className="btn primary" to={`/runtime-clusters/${cluster.id}`}>
            View cluster
          </Link>
        </>
      )}
    </>
  );
}
