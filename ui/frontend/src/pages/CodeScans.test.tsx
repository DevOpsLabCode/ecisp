import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { CodeScanSummary } from "../types";
import CodeScans from "./CodeScans";

vi.mock("../api/client", () => ({
  api: { listCodeScans: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const scans: CodeScanSummary[] = [
  {
    id: "scan-1",
    source_type: "repo_url",
    source_label: "my-org/payments-api",
    branch: "main",
    commit_sha: "abc123def456",
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
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <CodeScans />
    </MemoryRouter>,
  );
}

describe("CodeScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("shows an empty state with a link to start a scan when there are none", async () => {
    vi.mocked(api.listCodeScans).mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText(/No code scans yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Start one" })).toHaveAttribute("href", "/code-scan");
  });

  it("renders a row per scan with source, branch, status, and findings", async () => {
    vi.mocked(api.listCodeScans).mockResolvedValue(scans);
    renderPage();
    expect(await screen.findByText("my-org/payments-api")).toBeInTheDocument();
    expect(screen.getByText("Repo URL")).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("shows an em dash for DAST when it hasn't been run", async () => {
    vi.mocked(api.listCodeScans).mockResolvedValue(scans);
    renderPage();
    await screen.findByText("my-org/payments-api");
    const row = screen.getByText("my-org/payments-api").closest("tr");
    expect(row).toHaveTextContent("—");
  });

  it("shows Upload, an em dash for branch, and an em dash for findings for an in-progress upload scan", async () => {
    vi.mocked(api.listCodeScans).mockResolvedValue([
      {
        ...scans[0],
        source_type: "upload",
        source_label: "myproj.zip",
        branch: null,
        commit_sha: null,
        status: "running",
        severity_counts: null,
        finding_count: null,
      },
    ]);
    renderPage();
    await screen.findByText("myproj.zip");
    expect(screen.getByText("Upload")).toBeInTheDocument();
    const row = screen.getByText("myproj.zip").closest("tr");
    expect(row).toHaveTextContent("—");
  });

  it("shows a DAST status badge once DAST has run", async () => {
    vi.mocked(api.listCodeScans).mockResolvedValue([{ ...scans[0], dast_status: "running" }]);
    renderPage();
    await screen.findByText("my-org/payments-api");
    expect(screen.getByText("running")).toBeInTheDocument();
  });

  it("navigates to the scan detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScans).mockResolvedValue(scans);
    renderPage();
    const row = await screen.findByText("my-org/payments-api");
    await user.click(row);
    expect(navigateMock).toHaveBeenCalledWith("/code-scans/scan-1");
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listCodeScans).mockRejectedValue(new Error("backend unreachable"));
    renderPage();
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.listCodeScans).mockRejectedValue("network exploded");
    renderPage();
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("ignores a listCodeScans rejection that resolves after unmount", async () => {
    let rejectScans: (e: Error) => void = () => {};
    vi.mocked(api.listCodeScans).mockReturnValue(new Promise((_resolve, reject) => (rejectScans = reject)));
    const { unmount } = renderPage();
    unmount();
    rejectScans(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listCodeScans).mockResolvedValue(scans);
    renderPage();
    await screen.findByText("my-org/payments-api");
    expect(api.listCodeScans).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.listCodeScans).toHaveBeenCalledTimes(2);
  });

  it("ignores a listCodeScans response that resolves after unmount", async () => {
    let resolveScans: (v: CodeScanSummary[]) => void = () => {};
    vi.mocked(api.listCodeScans).mockReturnValue(new Promise((resolve) => (resolveScans = resolve)));
    const { unmount } = renderPage();
    unmount();
    resolveScans(scans);
    await new Promise((r) => setTimeout(r, 0));
  });
});
