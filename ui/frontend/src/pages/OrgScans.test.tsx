import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { OrgScanSummary } from "../types";
import OrgScans from "./OrgScans";

vi.mock("../api/client", () => ({
  api: { listOrgScans: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const scans: OrgScanSummary[] = [
  {
    id: "scan-1",
    org: "my-org",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    error: null,
    total_repos: 10,
    completed_repos: 10,
    repos_with_findings: 3,
    severity_totals: { critical: 1, high: 2, medium: 4, low: 0, info: 0 },
    issues_created: 2,
    email_sent: true,
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <OrgScans />
    </MemoryRouter>,
  );
}

describe("OrgScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("shows an empty state with a link to start a scan when there are none", async () => {
    vi.mocked(api.listOrgScans).mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText(/No org scans yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Start one" })).toHaveAttribute("href", "/org-scans/new");
  });

  it("renders a row per scan with aggregate counts", async () => {
    vi.mocked(api.listOrgScans).mockResolvedValue(scans);
    renderPage();
    expect(await screen.findByText("my-org")).toBeInTheDocument();
    expect(screen.getByText("10/10")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument(); // 1+2+4 severity total
    expect(screen.getByText("2")).toBeInTheDocument(); // issues_created
  });

  it("navigates to the scan detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listOrgScans).mockResolvedValue(scans);
    renderPage();
    const row = await screen.findByText("my-org");
    await user.click(row);
    expect(navigateMock).toHaveBeenCalledWith("/org-scans/scan-1");
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listOrgScans).mockRejectedValue(new Error("backend unreachable"));
    renderPage();
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.listOrgScans).mockRejectedValue("network exploded");
    renderPage();
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("ignores a listOrgScans rejection that resolves after unmount", async () => {
    let rejectScans: (e: Error) => void = () => {};
    vi.mocked(api.listOrgScans).mockReturnValue(new Promise((_resolve, reject) => (rejectScans = reject)));
    const { unmount } = renderPage();
    unmount();
    rejectScans(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listOrgScans).mockResolvedValue(scans);
    renderPage();
    await screen.findByText("my-org");
    expect(api.listOrgScans).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.listOrgScans).toHaveBeenCalledTimes(2);
  });

  it("ignores a listOrgScans response that resolves after unmount", async () => {
    let resolveScans: (v: OrgScanSummary[]) => void = () => {};
    vi.mocked(api.listOrgScans).mockReturnValue(new Promise((resolve) => (resolveScans = resolve)));
    const { unmount } = renderPage();
    unmount();
    resolveScans(scans);
    await new Promise((r) => setTimeout(r, 0));
  });
});
