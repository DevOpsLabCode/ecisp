import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

export default function BulkImport() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!file) return;
    setError(null);
    setSubmitting(true);
    try {
      const batch = await api.createBatch(file);
      navigate(`/batches/${batch.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>Import Cloud Accounts</h1>
        <p>
          Scan many accounts at once. Each row in the file is one account's full scan
          configuration — provider, auth, and scope — so a single import can mix providers
          (e.g. some AWS rows, some Azure rows) in one file.
        </p>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <h2>Upload</h2>
        <p className="help" style={{ marginBottom: 14 }}>
          Accepts .csv, .xlsx, or .json.{" "}
          <a href={api.batchTemplateUrl()} download>
            Download a CSV template
          </a>{" "}
          with every column and two example rows.
        </p>

        <div className="field">
          <label htmlFor="bulk-import-file">Choose file</label>
          <input
            id="bulk-import-file"
            type="file"
            accept=".csv,.xlsx,.json"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file && (
            <div className="help">
              {file.name} ({Math.ceil(file.size / 1024)} KB)
            </div>
          )}
        </div>

        <button className="btn primary" onClick={handleSubmit} disabled={!file || submitting}>
          {submitting ? "Importing…" : "Import and queue scans"}
        </button>
      </div>

      <div className="card">
        <h2>How each row maps to a scan</h2>
        <p className="help">
          Required columns: <code>provider</code> and <code>auth_method</code> (matching the codes
          shown on the New scan page — e.g. <code>aws</code> / <code>profile</code>). Every other
          auth or scope field (e.g. <code>profile</code>, <code>tenant_id</code>,{" "}
          <code>client_secret</code>, <code>regions</code>) is a column too; only the ones relevant
          to that row's provider are used, so one file's columns can cover every provider at once.
          List fields like <code>regions</code> accept comma- or semicolon-separated values. Rows
          that fail validation are skipped individually and reported — they don't block the rest of
          the import.
        </p>
        <p className="help" style={{ marginTop: 10 }}>
          For AWS specifically: to scan every account in an AWS Organization with one set of
          credentials, configure per-account profiles in the backend's AWS config using standard
          cross-account role assumption (<code>role_arn</code> + <code>source_profile</code> in{" "}
          <code>~/.aws/config</code>) — then list each profile name in its own row here. This
          reuses the AWS SDK's own credential resolution rather than anything custom.
        </p>
      </div>
    </>
  );
}
