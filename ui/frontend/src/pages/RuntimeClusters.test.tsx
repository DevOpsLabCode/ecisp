import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RuntimeClusterSummary } from "../types";
import RuntimeClusters from "./RuntimeClusters";

vi.mock("../api/client", () => ({
  api: { listRuntimeClusters: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const clusters: RuntimeClusterSummary[] = [
  {
    id: "cluster-1",
    name: "prod-eks",
    created_at: "2026-01-01T00:00:00Z",
    last_event_at: "2026-01-01T00:05:00Z",
    severity_counts: { critical: 1, high: 2, medium: 3, low: 4, info: 0 },
    finding_count: 10,
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <RuntimeClusters />
    </MemoryRouter>,
  );
}

describe("RuntimeClusters", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("shows an empty state with a link to install when there are none", async () => {
    vi.mocked(api.listRuntimeClusters).mockResolvedValue([]);
    renderPage();
    expect(await screen.findByText(/No clusters registered yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Install Golem Defender" })).toHaveAttribute(
      "href",
      "/runtime-defender/new",
    );
  });

  it("renders a row per cluster with name, last event, and finding count", async () => {
    vi.mocked(api.listRuntimeClusters).mockResolvedValue(clusters);
    renderPage();
    expect(await screen.findByText("prod-eks")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });

  it("shows an em dash when a cluster has no events yet", async () => {
    vi.mocked(api.listRuntimeClusters).mockResolvedValue([{ ...clusters[0], last_event_at: null }]);
    renderPage();
    await screen.findByText("prod-eks");
    const row = screen.getByText("prod-eks").closest("tr");
    expect(row).toHaveTextContent("—");
  });

  it("navigates to the cluster detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listRuntimeClusters).mockResolvedValue(clusters);
    renderPage();
    const row = await screen.findByText("prod-eks");
    await user.click(row);
    expect(navigateMock).toHaveBeenCalledWith("/runtime-clusters/cluster-1");
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listRuntimeClusters).mockRejectedValue(new Error("backend unreachable"));
    renderPage();
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.listRuntimeClusters).mockRejectedValue("network exploded");
    renderPage();
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("ignores a listRuntimeClusters rejection that resolves after unmount", async () => {
    let rejectClusters: (e: Error) => void = () => {};
    vi.mocked(api.listRuntimeClusters).mockReturnValue(new Promise((_resolve, reject) => (rejectClusters = reject)));
    const { unmount } = renderPage();
    unmount();
    rejectClusters(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listRuntimeClusters).mockResolvedValue(clusters);
    renderPage();
    await screen.findByText("prod-eks");
    expect(api.listRuntimeClusters).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(5100);
    expect(api.listRuntimeClusters).toHaveBeenCalledTimes(2);
  });

  it("ignores a listRuntimeClusters response that resolves after unmount", async () => {
    let resolveClusters: (v: RuntimeClusterSummary[]) => void = () => {};
    vi.mocked(api.listRuntimeClusters).mockReturnValue(new Promise((resolve) => (resolveClusters = resolve)));
    const { unmount } = renderPage();
    unmount();
    resolveClusters(clusters);
    await new Promise((r) => setTimeout(r, 0));
  });
});
