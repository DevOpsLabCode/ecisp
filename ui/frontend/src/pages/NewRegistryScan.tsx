import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

export default function NewRegistryScan() {
  const navigate = useNavigate();

  const [imageRef, setImageRef] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [registryToken, setRegistryToken] = useState("");
  const [insecure, setInsecure] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!imageRef.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const scan = await api.createRegistryScan({
        image_ref: imageRef.trim(),
        username: username.trim() || null,
        password: password || null,
        registry_token: registryToken.trim() || null,
        insecure,
      });
      navigate(`/registry-scans/${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>New Artifact Registry Scan</h1>
        <p>
          Scan one container image for known vulnerabilities and baked-in secrets — pull it straight
          from JFrog Artifactory, Docker Hub, GitHub Container Registry, AWS ECR, Google Artifact
          Registry, Azure ACR, Harbor, Quay.io, or any other registry that speaks the standard
          Docker Registry / OCI Distribution API.
        </p>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <h2>Image</h2>
        <div className="field">
          <label htmlFor="registry-scan-image-ref">Image reference</label>
          <input
            id="registry-scan-image-ref"
            type="text"
            placeholder="myregistry.jfrog.io/docker-local/my-app:1.2.3"
            value={imageRef}
            onChange={(e) => setImageRef(e.target.value)}
          />
          <div className="help">
            Registry host + repository + tag (or digest). Public images need nothing else below —
            the pull happens anonymously.
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Authentication (optional)</h2>
        <p className="help" style={{ marginBottom: 14 }}>
          Only needed for private images. Credentials are used once for this scan, passed to the
          scanner as environment variables (never as a command-line argument), and never stored.
        </p>
        <div className="field">
          <label htmlFor="registry-scan-username">Username</label>
          <input
            id="registry-scan-username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="registry-scan-password">Password</label>
          <input
            id="registry-scan-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="registry-scan-token">Registry token (instead of username/password)</label>
          <input
            id="registry-scan-token"
            type="password"
            value={registryToken}
            onChange={(e) => setRegistryToken(e.target.value)}
          />
        </div>
        <div className="checkbox-field">
          <input
            id="registry-scan-insecure"
            type="checkbox"
            checked={insecure}
            onChange={(e) => setInsecure(e.target.checked)}
          />
          <label htmlFor="registry-scan-insecure">Allow insecure connection (self-signed certificate)</label>
        </div>
      </div>

      <button className="btn primary" onClick={handleSubmit} disabled={!imageRef.trim() || submitting}>
        {submitting ? "Starting…" : "Start scan"}
      </button>
    </>
  );
}
