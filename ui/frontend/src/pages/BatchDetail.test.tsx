import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { BatchDetail as BatchDetailType } from "../types";
import BatchDetail from "./BatchDetail";

vi.mock("../api/client", () => ({
  api: { getBatch: vi.fn() },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/batches/:id" element={<BatchDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeBatch(overrides: Partial<BatchDetailType>): BatchDetailType {
  return {
    id: "batch-1",
    filename: "accounts.csv",
    created_at: "2026-01-01T00:00:00Z",
    queued_jobs: 1,
    skipped_rows: 0,
    status_counts: { queued: 0, running: 0, completed: 1, failed: 0 },
    jobs: [
      {
        id: "job-1",
        provider: "aws",
        report_name: "acct-1",
        status: "completed",
        created_at: "2026-01-01T00:00:00Z",
        started_at: null,
        finished_at: null,
        exit_code: 0,
        error: null,
      },
    ],
    errors: [],
    ...overrides,
  };
}

describe("BatchDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the batch loads", () => {
    vi.mocked(api.getBatch).mockReturnValue(new Promise(() => {}));
    renderAt("/batches/batch-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows an error banner when the fetch fails", async () => {
    vi.mocked(api.getBatch).mockRejectedValue(new Error("batch fetch failed"));
    renderAt("/batches/batch-1");
    expect(await screen.findByText("batch fetch failed")).toBeInTheDocument();
  });

  it("renders stat tiles and the jobs table", async () => {
    vi.mocked(api.getBatch).mockResolvedValue(makeBatch({}));
    renderAt("/batches/batch-1");
    expect(await screen.findByText("accounts.csv")).toBeInTheDocument();
    expect(screen.getByText("acct-1")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
  });

  it("renders skipped-row errors when present", async () => {
    vi.mocked(api.getBatch).mockResolvedValue(
      makeBatch({
        skipped_rows: 1,
        errors: [{ row_number: 3, message: "Unknown provider: 'bogus'" }],
      }),
    );
    renderAt("/batches/batch-1");
    expect(await screen.findByRole("heading", { name: "Skipped rows" })).toBeInTheDocument();
    expect(screen.getByText("Unknown provider: 'bogus'")).toBeInTheDocument();
  });

  it("shows an empty state when no rows produced a job", async () => {
    vi.mocked(api.getBatch).mockResolvedValue(makeBatch({ jobs: [], queued_jobs: 0 }));
    renderAt("/batches/batch-1");
    expect(await screen.findByText("No rows in this file produced a valid scan.")).toBeInTheDocument();
  });

  it("polls again while jobs are queued/running and stops once terminal", async () => {
    vi.mocked(api.getBatch)
      .mockResolvedValueOnce(
        makeBatch({ status_counts: { queued: 1, running: 0, completed: 0, failed: 0 } }),
      )
      .mockResolvedValueOnce(
        makeBatch({ status_counts: { queued: 0, running: 0, completed: 1, failed: 0 } }),
      );

    renderAt("/batches/batch-1");
    await screen.findByText("accounts.csv");
    expect(api.getBatch).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(2100);
    expect(api.getBatch).toHaveBeenCalledTimes(2);

    await vi.advanceTimersByTimeAsync(5000);
    expect(api.getBatch).toHaveBeenCalledTimes(2);
  });

  it("ignores a getBatch response that resolves after unmount", async () => {
    let resolveBatch: (v: BatchDetailType) => void = () => {};
    vi.mocked(api.getBatch).mockReturnValue(new Promise((resolve) => (resolveBatch = resolve)));
    const { unmount } = renderAt("/batches/batch-1");
    unmount();
    resolveBatch(makeBatch({}));
    await new Promise((r) => setTimeout(r, 0));
  });
});
