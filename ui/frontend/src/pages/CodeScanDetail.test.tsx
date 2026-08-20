import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { CodeScanDetail as CodeScanDetailType } from "../types";
import CodeScanDetail from "./CodeScanDetail";

vi.mock("../api/client", () => ({
  api: {
    getCodeScan: vi.fn(),
    runCodeScanDast: vi.fn(),
    codeScanReportUrl: vi.fn((id: string, fmt: string) => `http://localhost:8000/api/code-scans/${id}/report.${fmt}`),
  },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/code-scans/:id" element={<CodeScanDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeScan(overrides: Partial<CodeScanDetailType> = {}): CodeScanDetailType {
  return {
    id: "scan-1",
    source_type: "repo_url",
    source_label: "my-org/payments-api",
    branch: "main",
    commit_sha: "abc123def4567890",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    error: null,
    severity_counts: { critical: 0, high: 1, medium: 2, low: 0, info: 0 },
    finding_count: 3,
    dast_status: "not_run",
    dast_target_url: null,
    dast_error: null,
    technologies: ["python", "trivy"],
    scanners_run: ["bandit", "trivy"],
    scanners_skipped: {},
    findings: [
      {
        repository: "my-org/payments-api",
        file: "app/auth.py",
        line: 42,
        scanner: "bandit",
        rule_id: "B105",
        severity: "high",
        category: "sast",
        message: "Hardcoded password string",
        remediation: "Use a secrets manager instead.",
        fingerprint: "fp-1",
      },
    ],
    ...overrides,
  };
}

describe("CodeScanDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the scan loads", () => {
    vi.mocked(api.getCodeScan).mockReturnValue(new Promise(() => {}));
    renderAt("/code-scans/scan-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows an error banner when the fetch fails", async () => {
    vi.mocked(api.getCodeScan).mockRejectedValue(new Error("scan fetch failed"));
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("scan fetch failed")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.getCodeScan).mockRejectedValue("network exploded");
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("renders the header, severity tiles, and scan details for a completed scan", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    renderAt("/code-scans/scan-1");
    expect(await screen.findByRole("heading", { name: "my-org/payments-api" })).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
    expect(screen.getByText("abc123def456")).toBeInTheDocument();
    expect(screen.getByText(/python, trivy/)).toBeInTheDocument();
    expect(screen.getByText(/bandit, trivy/)).toBeInTheDocument();
    expect(screen.getByText(/GitHub repository/)).toBeInTheDocument();
  });

  it("labels an uploaded-archive scan as such, with no branch or commit shown", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(
      makeScan({ source_type: "upload", source_label: "myproj.zip", branch: null, commit_sha: null }),
    );
    renderAt("/code-scans/scan-1");
    expect(await screen.findByRole("heading", { name: "myproj.zip" })).toBeInTheDocument();
    expect(screen.getByText(/Uploaded archive/)).toBeInTheDocument();
  });

  it("shows a progress banner and no stats while running", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan({ status: "running", severity_counts: null, findings: [] }));
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("Scan in progress…")).toBeInTheDocument();
    expect(screen.queryByText("Findings")).not.toBeInTheDocument();
  });

  it("shows the top-level scan error when present", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan({ status: "failed", error: "Archive rejected: zip-slip detected" }));
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("Archive rejected: zip-slip detected")).toBeInTheDocument();
  });

  it("expands a row to show remediation, and collapses it again on a second click", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    renderAt("/code-scans/scan-1");

    const row = await screen.findByText("Hardcoded password string");
    expect(screen.getByText("app/auth.py:42")).toBeInTheDocument();
    expect(screen.queryByText("Use a secrets manager instead.")).not.toBeInTheDocument();

    await user.click(row);
    expect(screen.getByText("Use a secrets manager instead.")).toBeInTheDocument();

    await user.click(row);
    expect(screen.queryByText("Use a secrets manager instead.")).not.toBeInTheDocument();
  });

  it("shows an em dash placeholder when no technologies or scanners ran", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(
      makeScan({ technologies: [], scanners_run: [], findings: [] }),
    );
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("Technologies detected: —")).toBeInTheDocument();
    expect(screen.getByText("Scanners run: —")).toBeInTheDocument();
  });

  it("falls back to a generic DAST failure message when no error detail is given", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan({ dast_status: "failed", dast_error: null }));
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("DAST scan failed.")).toBeInTheDocument();
  });

  it("filters findings by severity, and re-adding a severity brings its findings back", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    renderAt("/code-scans/scan-1");
    await screen.findByText("Hardcoded password string");

    const highTab = screen.getByRole("button", { name: "high" });
    await user.click(highTab);
    expect(screen.queryByText("Hardcoded password string")).not.toBeInTheDocument();
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();

    await user.click(highTab);
    expect(screen.getByText("Hardcoded password string")).toBeInTheDocument();
  });

  it("sorts findings by severity, most severe first", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(
      makeScan({
        findings: [
          {
            repository: "my-org/payments-api",
            file: "infra/main.tf",
            line: null,
            scanner: "checkov",
            rule_id: "CKV_AWS_1",
            severity: "low",
            category: "iac",
            message: "Low severity IaC finding",
            remediation: null,
            fingerprint: "fp-low",
          },
          {
            repository: "my-org/payments-api",
            file: "app/auth.py",
            line: 42,
            scanner: "bandit",
            rule_id: "B105",
            severity: "critical",
            category: "sast",
            message: "Critical severity finding",
            remediation: null,
            fingerprint: "fp-critical",
          },
        ],
      }),
    );
    renderAt("/code-scans/scan-1");
    await screen.findByText("Critical severity finding");

    const criticalRow = screen.getByText("Critical severity finding").closest("tr");
    const lowRow = screen.getByText("Low severity IaC finding").closest("tr");
    expect(criticalRow!.compareDocumentPosition(lowRow!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("filters findings by search text", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    renderAt("/code-scans/scan-1");
    await screen.findByText("Hardcoded password string");

    await user.type(screen.getByPlaceholderText("Search findings…"), "nonexistent");
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();
  });

  it("shows a skipped-scanner note when scanners were skipped", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(
      makeScan({ scanners_skipped: { spotbugs: "disabled for uploaded archives" } }),
    );
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText(/Skipped: spotbugs \(disabled for uploaded archives\)/)).toBeInTheDocument();
  });

  it("shows report download links for a completed scan", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    renderAt("/code-scans/scan-1");
    const link = await screen.findByText("Download SARIF");
    expect(link).toHaveAttribute("href", "http://localhost:8000/api/code-scans/scan-1/report.sarif");
  });

  it("starts a DAST scan and reflects the running state", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    vi.mocked(api.runCodeScanDast).mockResolvedValue(makeScan({ dast_status: "running", dast_target_url: "https://staging.example" }));
    renderAt("/code-scans/scan-1");

    await user.type(await screen.findByLabelText("Application URL"), "https://staging.example");
    await user.click(screen.getByRole("button", { name: "Run DAST" }));

    expect(api.runCodeScanDast).toHaveBeenCalledWith("scan-1", { target_url: "https://staging.example" });
    expect(await screen.findByText(/Scanning https:\/\/staging\.example/)).toBeInTheDocument();
  });

  it("shows an error banner when starting DAST fails", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan());
    vi.mocked(api.runCodeScanDast).mockRejectedValue(new Error("Source scan is not completed yet"));
    renderAt("/code-scans/scan-1");

    await user.type(await screen.findByLabelText("Application URL"), "https://staging.example");
    await user.click(screen.getByRole("button", { name: "Run DAST" }));

    expect(await screen.findByText("Source scan is not completed yet")).toBeInTheDocument();
  });

  it("shows a completed DAST banner", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(
      makeScan({ dast_status: "completed", dast_target_url: "https://staging.example" }),
    );
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText(/DAST completed against https:\/\/staging\.example/)).toBeInTheDocument();
  });

  it("shows a failed DAST banner with the error", async () => {
    vi.mocked(api.getCodeScan).mockResolvedValue(makeScan({ dast_status: "failed", dast_error: "ZAP is not installed" }));
    renderAt("/code-scans/scan-1");
    expect(await screen.findByText("ZAP is not installed")).toBeInTheDocument();
  });

  it("polls while queued/running or while DAST is running, and stops once both are terminal", async () => {
    vi.mocked(api.getCodeScan)
      .mockResolvedValueOnce(makeScan({ status: "running", severity_counts: null, findings: [] }))
      .mockResolvedValueOnce(makeScan({ status: "completed", dast_status: "running" }))
      .mockResolvedValueOnce(makeScan({ status: "completed", dast_status: "completed" }));

    renderAt("/code-scans/scan-1");
    await screen.findByRole("heading", { name: "my-org/payments-api" });
    expect(api.getCodeScan).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.getCodeScan).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.getCodeScan).toHaveBeenCalledTimes(3);

    await vi.advanceTimersByTimeAsync(5000);
    expect(api.getCodeScan).toHaveBeenCalledTimes(3);
  });

  it("ignores a getCodeScan response that resolves after unmount", async () => {
    let resolveScan: (v: CodeScanDetailType) => void = () => {};
    vi.mocked(api.getCodeScan).mockReturnValue(new Promise((resolve) => (resolveScan = resolve)));
    const { unmount } = renderAt("/code-scans/scan-1");
    unmount();
    resolveScan(makeScan());
    await new Promise((r) => setTimeout(r, 0));
  });

  it("ignores a getCodeScan rejection that resolves after unmount", async () => {
    let rejectScan: (e: Error) => void = () => {};
    vi.mocked(api.getCodeScan).mockReturnValue(new Promise((_resolve, reject) => (rejectScan = reject)));
    const { unmount } = renderAt("/code-scans/scan-1");
    unmount();
    rejectScan(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });
});
