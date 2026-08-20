import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RegistryScanDetail as RegistryScanDetailType } from "../types";
import RegistryScanDetail from "./RegistryScanDetail";

vi.mock("../api/client", () => ({
  api: {
    getRegistryScan: vi.fn(),
    registryScanReportUrl: vi.fn(
      (id: string, fmt: string) => `http://localhost:8000/api/registry-scans/${id}/report.${fmt}`,
    ),
  },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/registry-scans/:id" element={<RegistryScanDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeScan(overrides: Partial<RegistryScanDetailType> = {}): RegistryScanDetailType {
  return {
    id: "scan-1",
    image_ref: "node:14.0.0",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    error: null,
    severity_counts: { critical: 1, high: 2, medium: 3, low: 4, info: 0 },
    finding_count: 10,
    scanners_run: ["trivy"],
    findings: [
      {
        repository: "node:14.0.0",
        file: "node:14.0.0",
        line: null,
        scanner: "trivy",
        rule_id: "CVE-2020-27350",
        severity: "high",
        category: "sca",
        message: "Package: apt\nInstalled Version: 1.4.9",
        remediation: "Upgrade to the fixed version named in the message.",
        fingerprint: "fp-1",
      },
    ],
    ...overrides,
  };
}

describe("RegistryScanDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the scan loads", () => {
    vi.mocked(api.getRegistryScan).mockReturnValue(new Promise(() => {}));
    renderAt("/registry-scans/scan-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows an error banner when the fetch fails", async () => {
    vi.mocked(api.getRegistryScan).mockRejectedValue(new Error("scan fetch failed"));
    renderAt("/registry-scans/scan-1");
    expect(await screen.findByText("scan fetch failed")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.getRegistryScan).mockRejectedValue("network exploded");
    renderAt("/registry-scans/scan-1");
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("renders the header and severity tiles for a completed scan", async () => {
    vi.mocked(api.getRegistryScan).mockResolvedValue(makeScan());
    renderAt("/registry-scans/scan-1");
    expect(await screen.findByRole("heading", { name: "node:14.0.0" })).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument(); // critical tile
  });

  it("shows a progress banner and no findings section while running", async () => {
    vi.mocked(api.getRegistryScan).mockResolvedValue(
      makeScan({ status: "running", severity_counts: null, findings: [] }),
    );
    renderAt("/registry-scans/scan-1");
    expect(await screen.findByText("Pulling and scanning the image…")).toBeInTheDocument();
    expect(screen.queryByText("Findings")).not.toBeInTheDocument();
  });

  it("shows the top-level scan error when present", async () => {
    vi.mocked(api.getRegistryScan).mockResolvedValue(
      makeScan({ status: "failed", error: "could not scan 'x': DENIED: denied" }),
    );
    renderAt("/registry-scans/scan-1");
    expect(await screen.findByText("could not scan 'x': DENIED: denied")).toBeInTheDocument();
  });

  it("expands a finding row to show its rule and remediation, and collapses on a second click", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRegistryScan).mockResolvedValue(makeScan());
    renderAt("/registry-scans/scan-1");

    const row = await screen.findByText(/Installed Version: 1.4.9/);
    expect(screen.queryByText("Upgrade to the fixed version named in the message.")).not.toBeInTheDocument();

    await user.click(row);
    expect(screen.getByText("Upgrade to the fixed version named in the message.")).toBeInTheDocument();
    expect(screen.getByText("CVE-2020-27350")).toBeInTheDocument();

    await user.click(row);
    expect(screen.queryByText("Upgrade to the fixed version named in the message.")).not.toBeInTheDocument();
  });

  it("filters findings by severity, and re-adding a severity brings its findings back", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRegistryScan).mockResolvedValue(makeScan());
    renderAt("/registry-scans/scan-1");
    await screen.findByText(/Installed Version: 1.4.9/);

    const highTab = screen.getByRole("button", { name: "high" });
    await user.click(highTab);
    expect(screen.queryByText(/Installed Version: 1.4.9/)).not.toBeInTheDocument();
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();

    await user.click(highTab);
    expect(screen.getByText(/Installed Version: 1.4.9/)).toBeInTheDocument();
  });

  it("sorts findings by severity, most severe first", async () => {
    vi.mocked(api.getRegistryScan).mockResolvedValue(
      makeScan({
        findings: [
          {
            repository: "node:14.0.0",
            file: "node:14.0.0",
            line: null,
            scanner: "trivy",
            rule_id: "CVE-LOW",
            severity: "low",
            category: "sca",
            message: "Low severity finding",
            remediation: null,
            fingerprint: "fp-low",
          },
          {
            repository: "node:14.0.0",
            file: "node:14.0.0",
            line: null,
            scanner: "trivy",
            rule_id: "CVE-CRITICAL",
            severity: "critical",
            category: "sca",
            message: "Critical severity finding",
            remediation: null,
            fingerprint: "fp-critical",
          },
        ],
      }),
    );
    renderAt("/registry-scans/scan-1");
    await screen.findByText("Critical severity finding");

    const criticalRow = screen.getByText("Critical severity finding").closest("tr");
    const lowRow = screen.getByText("Low severity finding").closest("tr");
    expect(criticalRow!.compareDocumentPosition(lowRow!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("filters findings by search text", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRegistryScan).mockResolvedValue(makeScan());
    renderAt("/registry-scans/scan-1");
    await screen.findByText(/Installed Version: 1.4.9/);

    await user.type(screen.getByPlaceholderText("Search findings…"), "nonexistent");
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();
  });

  it("shows report download links for a completed scan", async () => {
    vi.mocked(api.getRegistryScan).mockResolvedValue(makeScan());
    renderAt("/registry-scans/scan-1");
    const link = await screen.findByText("Download SARIF");
    expect(link).toHaveAttribute("href", "http://localhost:8000/api/registry-scans/scan-1/report.sarif");
  });

  it("polls while queued/running and stops once completed", async () => {
    vi.mocked(api.getRegistryScan)
      .mockResolvedValueOnce(makeScan({ status: "running", severity_counts: null, findings: [] }))
      .mockResolvedValueOnce(makeScan({ status: "completed" }));

    renderAt("/registry-scans/scan-1");
    await screen.findByRole("heading", { name: "node:14.0.0" });
    expect(api.getRegistryScan).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.getRegistryScan).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(5000);
    expect(api.getRegistryScan).toHaveBeenCalledTimes(2);
  });

  it("ignores a getRegistryScan response that resolves after unmount", async () => {
    let resolveScan: (v: RegistryScanDetailType) => void = () => {};
    vi.mocked(api.getRegistryScan).mockReturnValue(new Promise((resolve) => (resolveScan = resolve)));
    const { unmount } = renderAt("/registry-scans/scan-1");
    unmount();
    resolveScan(makeScan());
    await new Promise((r) => setTimeout(r, 0));
  });
});
