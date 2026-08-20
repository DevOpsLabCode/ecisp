import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { GitHubOAuthStatus, RepoBranchesResponse } from "../types";

type SourceMode = "upload" | "repo";

export default function NewCodeScan() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [mode, setMode] = useState<SourceMode>("upload");
  const [file, setFile] = useState<File | null>(null);

  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [branches, setBranches] = useState<RepoBranchesResponse | null>(null);
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [branchesError, setBranchesError] = useState<string | null>(null);

  const [oauth, setOauth] = useState<GitHubOAuthStatus | null>(null);
  // Captured once from the initial URL, not derived live from searchParams
  // below -- the banner should stay up even after the effect strips the
  // query param that triggered it.
  const [justConnected] = useState(() => searchParams.get("github_connected") === "1");

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.githubOAuthStatus().then(setOauth).catch(() => setOauth({ connected: false, configured: false }));
  }, []);

  // Runs once on mount to strip the redirect flag from the visible URL (so
  // a refresh doesn't re-show the banner). Deliberately an empty deps array
  // (oxlint's exhaustive-deps warns on this, but it's a false positive here):
  // adding searchParams/setSearchParams would retrigger this effect on the
  // very navigation it performs, and since setSearchParams({replace: true})
  // still produces a new location object even when the resulting URL is
  // unchanged, that would either loop or double-fire, not just "run more."
  useEffect(() => {
    if (justConnected) {
      const next = new URLSearchParams(searchParams);
      next.delete("github_connected");
      setSearchParams(next, { replace: true });
    }
  }, []);

  const lookupBranches = async () => {
    if (!repoUrl.trim()) return;
    setBranchesError(null);
    setBranches(null);
    setBranchesLoading(true);
    try {
      const info = await api.listCodeScanBranches(repoUrl.trim());
      setBranches(info);
      setBranch(info.default_branch ?? "");
    } catch (e) {
      setBranchesError(e instanceof Error ? e.message : String(e));
    } finally {
      setBranchesLoading(false);
    }
  };

  const needsGithubConnection = mode === "repo" && branches?.private === true && oauth?.connected === false;

  const handleUpload = async () => {
    if (!file) return;
    setError(null);
    setSubmitting(true);
    try {
      const scan = await api.uploadCodeScan(file);
      navigate(`/code-scans/${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRepoScan = async () => {
    if (!repoUrl.trim() || needsGithubConnection) return;
    setError(null);
    setSubmitting(true);
    try {
      const scan = await api.createCodeScanFromRepo({ repo_url: repoUrl.trim(), branch: branch || null });
      navigate(`/code-scans/${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>New Code Scan</h1>
        <p>
          Scan a single codebase — upload an archive or point at a GitHub repository — through the
          same SAST/SCA/Secrets/IaC pipeline as org-wide scanning, with an optional DAST follow-up
          against a running instance of the app.
        </p>
      </div>

      {justConnected && <div className="banner success">GitHub connected.</div>}
      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <div className="method-tabs">
          <button
            type="button"
            className={`method-tab${mode === "upload" ? " active" : ""}`}
            onClick={() => setMode("upload")}
          >
            Upload archive
          </button>
          <button
            type="button"
            className={`method-tab${mode === "repo" ? " active" : ""}`}
            onClick={() => setMode("repo")}
          >
            GitHub repo URL
          </button>
        </div>

        {mode === "upload" ? (
          <>
            <p className="help" style={{ marginBottom: 14 }}>
              Accepts <code>.zip</code>, <code>.tar</code>, <code>.tar.gz</code>, or{" "}
              <code>.tgz</code>. Extracted under strict path-traversal and symlink checks, and the
              contents are never executed — only read by the scanners.
            </p>
            <div className="field">
              <label htmlFor="code-scan-file">Choose file</label>
              <input
                id="code-scan-file"
                type="file"
                accept=".zip,.tar,.tar.gz,.tgz"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
              {file && (
                <div className="help">
                  {file.name} ({Math.ceil(file.size / 1024)} KB)
                </div>
              )}
            </div>
            <button className="btn primary" onClick={handleUpload} disabled={!file || submitting}>
              {submitting ? "Uploading…" : "Start scan"}
            </button>
          </>
        ) : (
          <>
            <div className="field">
              <label htmlFor="code-scan-repo-url">Repository URL</label>
              <input
                id="code-scan-repo-url"
                type="text"
                placeholder="https://github.com/my-org/my-repo"
                value={repoUrl}
                onChange={(e) => {
                  setRepoUrl(e.target.value);
                  setBranches(null);
                  setBranchesError(null);
                }}
              />
              <div className="help">
                Public repositories scan with no authentication. Private repositories need a
                connected GitHub account (below).
              </div>
            </div>

            <button
              type="button"
              className="btn"
              onClick={lookupBranches}
              disabled={!repoUrl.trim() || branchesLoading}
            >
              {branchesLoading ? "Looking up…" : "Look up branches"}
            </button>

            {branchesError && <div className="banner error" style={{ marginTop: 14 }}>{branchesError}</div>}

            {branches && (
              <div style={{ marginTop: 14 }}>
                {branches.private && (
                  <div className="banner warning">
                    This repository is private.{" "}
                    {oauth?.connected
                      ? "Using your connected GitHub account to scan it."
                      : "Connect GitHub to scan it."}
                  </div>
                )}

                {needsGithubConnection ? (
                  oauth?.configured ? (
                    <a className="btn primary" href={api.githubOAuthLoginUrl()}>
                      Connect GitHub
                    </a>
                  ) : (
                    <div className="banner error">
                      GitHub OAuth isn't configured on this backend — private-repo scanning is
                      unavailable until GITHUB_OAUTH_CLIENT_ID/SECRET are set.
                    </div>
                  )
                ) : (
                  <>
                    <div className="field">
                      <label htmlFor="code-scan-branch">Branch</label>
                      <select
                        id="code-scan-branch"
                        value={branch}
                        onChange={(e) => setBranch(e.target.value)}
                      >
                        {branches.branches.map((b) => (
                          <option key={b} value={b}>
                            {b}
                          </option>
                        ))}
                      </select>
                    </div>
                    <button className="btn primary" onClick={handleRepoScan} disabled={submitting}>
                      {submitting ? "Starting…" : "Start scan"}
                    </button>
                  </>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
