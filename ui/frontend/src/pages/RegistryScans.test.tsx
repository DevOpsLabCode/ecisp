import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RegistryScanSummary } from "../types";
import RegistryScans from "./RegistryScans";

vi.mock("../api/client", () => ({
  api: { listRegistryScans: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const scans: RegistryScanSummary[] = [
  {
    id: "scan-1",
    image_ref: "node:14.0.0",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    error: null,
    severity_counts: { critical: 221, high: 1105, medium: 1382, low: 523, info: 0 },
    finding_count: 3231,
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <RegistryScans />
    </MemoryRouter>,
  );
}

describe("RegistryScans", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("shows an empty state with a link to start a scan when there are none", async () => {
    vi.mocked(api.listRegistryScans).mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText(/No registry scans yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Start one" })).toHaveAttribute("href", "/registry-scan");
  });

  it("renders a row per scan with image, status, and finding count", async () => {
    vi.mocked(api.listRegistryScans).mockResolvedValue(scans);
    renderPage();
    expect(await screen.findByText("node:14.0.0")).toBeInTheDocument();
    expect(screen.getByText("3231")).toBeInTheDocument();
  });

  it("shows an em dash for findings before a scan completes", async () => {
    vi.mocked(api.listRegistryScans).mockResolvedValue([
      { ...scans[0], status: "running", severity_counts: null, finding_count: null },
    ]);
    renderPage();
    await screen.findByText("node:14.0.0");
    const row = screen.getByText("node:14.0.0").closest("tr");
    expect(row).toHaveTextContent("—");
  });

  it("navigates to the scan detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listRegistryScans).mockResolvedValue(scans);
    renderPage();
    const row = await screen.findByText("node:14.0.0");
    await user.click(row);
    expect(navigateMock).toHaveBeenCalledWith("/registry-scans/scan-1");
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listRegistryScans).mockRejectedValue(new Error("backend unreachable"));
    renderPage();
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.listRegistryScans).mockRejectedValue("network exploded");
    renderPage();
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("ignores a listRegistryScans rejection that resolves after unmount", async () => {
    let rejectScans: (e: Error) => void = () => {};
    vi.mocked(api.listRegistryScans).mockReturnValue(new Promise((_resolve, reject) => (rejectScans = reject)));
    const { unmount } = renderPage();
    unmount();
    rejectScans(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listRegistryScans).mockResolvedValue(scans);
    renderPage();
    await screen.findByText("node:14.0.0");
    expect(api.listRegistryScans).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.listRegistryScans).toHaveBeenCalledTimes(2);
  });

  it("ignores a listRegistryScans response that resolves after unmount", async () => {
    let resolveScans: (v: RegistryScanSummary[]) => void = () => {};
    vi.mocked(api.listRegistryScans).mockReturnValue(new Promise((resolve) => (resolveScans = resolve)));
    const { unmount } = renderPage();
    unmount();
    resolveScans(scans);
    await new Promise((r) => setTimeout(r, 0));
  });
});
