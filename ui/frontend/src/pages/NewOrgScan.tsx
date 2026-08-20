import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";

export default function NewOrgScan() {
  const navigate = useNavigate();

  const [org, setOrg] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [notifyEmail, setNotifyEmail] = useState("");
  const [createIssues, setCreateIssues] = useState(true);
  const [includeArchived, setIncludeArchived] = useState(false);
  const [maxWorkers, setMaxWorkers] = useState(4);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!org.trim() || !githubToken.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const scan = await api.createOrgScan({
        org: org.trim(),
        github_token: githubToken.trim(),
        notify_email: notifyEmail.trim() || null,
        create_issues: createIssues,
        include_archived: includeArchived,
        max_workers: maxWorkers,
      });
      navigate(`/org-scans/${scan.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <h1>New org security scan</h1>
        <p>
          Discovers every repository in a GitHub organization (or personal account), clones each
          one, and runs the SAST scanners relevant to what it finds — Checkov, Bandit, Semgrep,
          Gosec, SpotBugs, ESLint security rules, Brakeman, and Security Code Scan.
        </p>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="card">
        <h2>Target</h2>
        <div className="field">
          <label htmlFor="org-scan-org">Organization or account</label>
          <input
            id="org-scan-org"
            type="text"
            placeholder="my-org"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
          />
          <div className="help">
            The GitHub org or username to scan. Works for real GitHub Organizations and personal
            accounts alike — every repository the token can see gets discovered and scanned.
          </div>
        </div>

        <div className="field">
          <label htmlFor="org-scan-token">GitHub personal access token</label>
          <input
            id="org-scan-token"
            type="password"
            placeholder="ghp_…"
            value={githubToken}
            onChange={(e) => setGithubToken(e.target.value)}
          />
          <div className="help">
            Needs <code>repo</code> (or <code>public_repo</code> for public-only) scope to clone,
            plus <code>read:org</code> for organization discovery. If issue creation is enabled
            below, the token also needs write access to open issues. The token is used once to run
            this scan and is never stored.
          </div>
        </div>

        <div className="checkbox-field">
          <input
            id="org-scan-archived"
            type="checkbox"
            checked={includeArchived}
            onChange={(e) => setIncludeArchived(e.target.checked)}
          />
          <label htmlFor="org-scan-archived">Include archived repositories</label>
        </div>
      </div>

      <div className="card">
        <h2>Findings handling</h2>
        <div className="checkbox-field">
          <input
            id="org-scan-issues"
            type="checkbox"
            checked={createIssues}
            onChange={(e) => setCreateIssues(e.target.checked)}
          />
          <label htmlFor="org-scan-issues">Create GitHub Issues for Critical/High findings</label>
        </div>
        <div className="help" style={{ marginTop: 4, marginLeft: 24 }}>
          One grouped issue per repository, labeled <code>security</code>/<code>sast</code>/
          <code>automated</code>. Re-running a scan on the same day reuses the existing open issue
          instead of creating a duplicate. Medium/Low/Info findings still appear in every report
          format, just not as issues.
        </div>

        <div className="field" style={{ marginTop: 14 }}>
          <label htmlFor="org-scan-email">Notify email (optional)</label>
          <input
            id="org-scan-email"
            type="text"
            placeholder="security-team@example.com"
            value={notifyEmail}
            onChange={(e) => setNotifyEmail(e.target.value)}
          />
          <div className="help">
            Sent when the scan finishes, with a summary and every report format attached — SARIF,
            JSON, CSV, HTML, and PDF. Sent regardless of whether anything was found. Requires the
            backend's SMTP_* environment variables to be configured; the scan still runs and its
            reports are still downloadable from this UI either way.
          </div>
        </div>

        <div className="field">
          <label htmlFor="org-scan-workers">Repos scanned in parallel</label>
          <input
            id="org-scan-workers"
            type="number"
            min={1}
            max={16}
            value={maxWorkers}
            onChange={(e) => setMaxWorkers(Number(e.target.value))}
            style={{ width: 100 }}
          />
        </div>
      </div>

      <button
        className="btn primary"
        onClick={handleSubmit}
        disabled={!org.trim() || !githubToken.trim() || submitting}
      >
        {submitting ? "Starting…" : "Start scan"}
      </button>
    </>
  );
}
