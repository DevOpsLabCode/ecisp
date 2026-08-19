import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { BatchSummary } from "../types";
import Batches from "./Batches";

vi.mock("../api/client", () => ({
  api: { listBatches: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const batches: BatchSummary[] = [
  {
    id: "batch-1",
    filename: "accounts.csv",
    created_at: "2026-01-01T00:00:00Z",
    queued_jobs: 3,
    skipped_rows: 1,
    status_counts: { queued: 0, running: 0, completed: 2, failed: 1 },
  },
];

describe("Batches", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("shows an empty state with a link to bulk import when there are no batches", async () => {
    vi.mocked(api.listBatches).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/No imports yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import a file" })).toHaveAttribute("href", "/bulk-import");
  });

  it("ignores a listBatches response that resolves after unmount", async () => {
    let resolveBatches: (v: BatchSummary[]) => void = () => {};
    vi.mocked(api.listBatches).mockReturnValue(new Promise((resolve) => (resolveBatches = resolve)));
    const { unmount } = render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    unmount();
    resolveBatches(batches);
    await new Promise((r) => setTimeout(r, 0));
    // Reaching here without an "update on an unmounted component" warning is the assertion.
  });

  it("ignores a listBatches rejection that resolves after unmount", async () => {
    let rejectBatches: (e: Error) => void = () => {};
    vi.mocked(api.listBatches).mockReturnValue(new Promise((_resolve, reject) => (rejectBatches = reject)));
    const { unmount } = render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    unmount();
    rejectBatches(new Error("too late"));
    await new Promise((r) => setTimeout(r, 0));
  });

  it("renders a row per batch with aggregate counts", async () => {
    vi.mocked(api.listBatches).mockResolvedValue(batches);
    render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    expect(await screen.findByText("accounts.csv")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument(); // queued_jobs
    expect(screen.getByText("2")).toBeInTheDocument(); // completed
    expect(screen.getAllByText("1")).toHaveLength(2); // failed + skipped
  });

  it("navigates to the batch detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listBatches).mockResolvedValue(batches);
    render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    const row = await screen.findByText("accounts.csv");
    await user.click(row);
    expect(navigateMock).toHaveBeenCalledWith("/batches/batch-1");
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listBatches).mockRejectedValue(new Error("backend unreachable"));
    render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listBatches).mockResolvedValue(batches);
    render(
      <MemoryRouter>
        <Batches />
      </MemoryRouter>,
    );
    await screen.findByText("accounts.csv");
    expect(api.listBatches).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.listBatches).toHaveBeenCalledTimes(2);
  });
});
