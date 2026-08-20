import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { OrgScanDetail as OrgScanDetailType } from "../types";
import OrgScanDetail from "./OrgScanDetail";

vi.mock("../api/client", () => ({
  api: {
    getOrgScan: vi.fn(),
    orgScanReportUrl: vi.fn((id: string, fmt: string) => `http://localhost:8000/api/org-scans/${id}/report.${fmt}`),
  },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/org-scans/:id" element={<OrgScanDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeScan(overrides: Partial<OrgScanDetailType> = {}): OrgScanDetailType {
  return {
    id: "scan-1",
    org: "my-org",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    error: null,
    total_repos: 1,
    completed_repos: 1,
    repos_with_findings: 1,
    severity_totals: { critical: 0, high: 1, medium: 2, low: 0, info: 0 },
    issues_created: 1,
    email_sent: false,
    repositories: [
      {
        repository: "my-org/payments-api",
        technologies: ["bandit", "semgrep"],
        scanners_run: ["bandit", "semgrep"],
        scanners_skipped: {},
        severity_counts: { critical: 0, high: 1, medium: 2, low: 0, info: 0 },
        finding_count: 3,
        error: null,
        issue: { action: "created", issue_url: "https://github.com/my-org/payments-api/issues/5" },
      },
    ],
    ...overrides,
  };
}

describe("OrgScanDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the scan loads", () => {
    vi.mocked(api.getOrgScan).mockReturnValue(new Promise(() => {}));
    renderAt("/org-scans/scan-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows an error banner when the fetch fails", async () => {
    vi.mocked(api.getOrgScan).mockRejectedValue(new Error("scan fetch failed"));
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("scan fetch failed")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.getOrgScan).mockRejectedValue("network exploded");
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("renders severity tiles and the repository table for a completed scan", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(makeScan());
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("my-org/payments-api")).toBeInTheDocument();
    expect(screen.getByText("bandit, semgrep")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument(); // highest severity badge
    expect(screen.getByRole("link", { name: "Created" })).toHaveAttribute(
      "href",
      "https://github.com/my-org/payments-api/issues/5",
    );
  });

  it("shows report download links only once the scan has completed", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(makeScan({ status: "running" }));
    renderAt("/org-scans/scan-1");
    await screen.findByText("my-org");
    expect(screen.queryByText("Download HTML")).not.toBeInTheDocument();
  });

  it("shows the report downloads once completed", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(makeScan());
    renderAt("/org-scans/scan-1");
    const link = await screen.findByText("Download SARIF");
    expect(link).toHaveAttribute("href", "http://localhost:8000/api/org-scans/scan-1/report.sarif");
  });

  it("shows a progress banner while running", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({ status: "running", total_repos: 5, completed_repos: 2, repositories: [] }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText(/Scanning 2 of 5 repositories/)).toBeInTheDocument();
    expect(screen.getByText(/Waiting for the first repository/)).toBeInTheDocument();
  });

  it("shows an ellipsis for total_repos before discovery has completed", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({ status: "running", total_repos: 0, completed_repos: 0, repositories: [] }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText(/Scanning 0 of … repositories/)).toBeInTheDocument();
  });

  it("shows Sent for the email report tile once an email went out", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(makeScan({ email_sent: true }));
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("Sent")).toBeInTheDocument();
  });

  it("links to the existing issue when a repo's issue was reused rather than created", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({
        repositories: [
          {
            repository: "my-org/payments-api",
            technologies: ["bandit"],
            scanners_run: ["bandit"],
            scanners_skipped: {},
            severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
            finding_count: 1,
            error: null,
            issue: { action: "skipped_existing", issue_url: "https://github.com/my-org/payments-api/issues/4" },
          },
        ],
      }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByRole("link", { name: "Existing" })).toHaveAttribute(
      "href",
      "https://github.com/my-org/payments-api/issues/4",
    );
  });

  it("shows the top-level scan error when present", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({ status: "failed", error: "GitHub rejected this token", repositories: [] }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("GitHub rejected this token")).toBeInTheDocument();
  });

  it("shows a skipped-scanner note and a repo-level error on the row", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({
        repositories: [
          {
            repository: "my-org/broken-repo",
            technologies: [],
            scanners_run: [],
            scanners_skipped: { gosec: "not installed" },
            severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            finding_count: 0,
            error: "git clone failed",
            issue: null,
          },
        ],
      }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("Error: git clone failed")).toBeInTheDocument();
    expect(screen.getByText(/Skipped: gosec \(not installed\)/)).toBeInTheDocument();
  });

  it("shows a failed badge when issue creation failed for a repo", async () => {
    vi.mocked(api.getOrgScan).mockResolvedValue(
      makeScan({
        repositories: [
          {
            repository: "my-org/no-issues-repo",
            technologies: ["bandit"],
            scanners_run: ["bandit"],
            scanners_skipped: {},
            severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
            finding_count: 1,
            error: null,
            issue: { action: "failed", error: "Issues are disabled for this repo" },
          },
        ],
      }),
    );
    renderAt("/org-scans/scan-1");
    expect(await screen.findByText("Failed")).toBeInTheDocument();
  });

  it("polls again while queued/running and stops once terminal", async () => {
    vi.mocked(api.getOrgScan)
      .mockResolvedValueOnce(makeScan({ status: "running" }))
      .mockResolvedValueOnce(makeScan({ status: "completed" }));

    renderAt("/org-scans/scan-1");
    await screen.findByText("my-org");
    expect(api.getOrgScan).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.getOrgScan).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(5000);
    expect(api.getOrgScan).toHaveBeenCalledTimes(2);
  });

  it("ignores a getOrgScan response that resolves after unmount", async () => {
    let resolveScan: (v: OrgScanDetailType) => void = () => {};
    vi.mocked(api.getOrgScan).mockReturnValue(new Promise((resolve) => (resolveScan = resolve)));
    const { unmount } = renderAt("/org-scans/scan-1");
    unmount();
    resolveScan(makeScan());
    await new Promise((r) => setTimeout(r, 0));
  });
});
