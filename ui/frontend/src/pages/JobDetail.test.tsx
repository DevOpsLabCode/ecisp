import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { JobDetail as JobDetailType, ScanResults } from "../types";
import JobDetail from "./JobDetail";

vi.mock("../api/client", () => ({
  api: { getScan: vi.fn(), getScanResults: vi.fn() },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/jobs/:id" element={<JobDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function job(overrides: Partial<JobDetailType>): JobDetailType {
  return {
    id: "job-1",
    provider: "aws",
    report_name: "aws-audit",
    status: "queued",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    exit_code: null,
    error: null,
    request: {},
    log: "",
    ...overrides,
  };
}

describe("JobDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the job loads", () => {
    vi.mocked(api.getScan).mockReturnValue(new Promise(() => {})); // never resolves
    renderAt("/jobs/job-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("ignores a getScan response that resolves after unmount", async () => {
    let resolveJob: (v: JobDetailType) => void = () => {};
    vi.mocked(api.getScan).mockReturnValue(new Promise((resolve) => (resolveJob = resolve)));
    const { unmount } = renderAt("/jobs/job-1");
    unmount();
    resolveJob(job({ status: "completed" }));
    await new Promise((r) => setTimeout(r, 0));
    // Reaching here without an "update on an unmounted component" warning is the assertion.
  });

  it("shows an error banner when the job fetch fails", async () => {
    vi.mocked(api.getScan).mockRejectedValue(new Error("job fetch failed"));
    renderAt("/jobs/job-1");
    expect(await screen.findByText("job fetch failed")).toBeInTheDocument();
  });

  it("shows a queued waiting message", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "queued" }));
    renderAt("/jobs/job-1");
    expect(await screen.findByText("Waiting in queue…")).toBeInTheDocument();
  });

  it("shows a running message and the engine log", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "running", log: "gathering data\n" }));
    renderAt("/jobs/job-1");
    expect(await screen.findByText(/updates automatically/)).toBeInTheDocument();
    expect(screen.getByText(/gathering data/)).toBeInTheDocument();
  });

  it("shows the job.error banner when present", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "failed", error: "auth failed" }));
    renderAt("/jobs/job-1");
    expect(await screen.findByText("auth failed")).toBeInTheDocument();
  });

  it("shows the finished_at timestamp when present", async () => {
    vi.mocked(api.getScan).mockResolvedValue(
      job({ status: "completed", exit_code: 0, finished_at: "2026-01-01T00:05:00Z" }),
    );
    vi.mocked(api.getScanResults).mockResolvedValue({ services: {} });
    renderAt("/jobs/job-1");
    expect(await screen.findByText(/finished/)).toBeInTheDocument();
  });

  it("falls back to a stringified error when the rejection has no message", async () => {
    vi.mocked(api.getScan).mockRejectedValue("network exploded");
    renderAt("/jobs/job-1");
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("loads and renders findings once the job is completed", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "completed", exit_code: 0 }));
    const results: ScanResults = {
      service_list: ["iam"],
      services: {
        iam: {
          findings: {
            "iam-finding": { description: "An IAM finding", level: "danger", items: ["a"], flagged_items: 1 },
          },
        },
      },
    };
    vi.mocked(api.getScanResults).mockResolvedValue(results);
    renderAt("/jobs/job-1");
    expect(await screen.findByText("An IAM finding")).toBeInTheDocument();
    expect(api.getScanResults).toHaveBeenCalledWith("job-1");
  });

  it("shows a results error banner when loading results fails", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "completed", exit_code: 0 }));
    vi.mocked(api.getScanResults).mockRejectedValue(new Error("results parse failed"));
    renderAt("/jobs/job-1");
    expect(await screen.findByText("results parse failed")).toBeInTheDocument();
  });

  it("falls back to a stringified results error when the rejection has no message", async () => {
    vi.mocked(api.getScan).mockResolvedValue(job({ status: "completed", exit_code: 0 }));
    vi.mocked(api.getScanResults).mockRejectedValue("results service down");
    renderAt("/jobs/job-1");
    expect(await screen.findByText("results service down")).toBeInTheDocument();
  });

  it("polls again while queued/running and stops once terminal", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.getScan)
      .mockResolvedValueOnce(job({ status: "running" }))
      .mockResolvedValueOnce(job({ status: "completed", exit_code: 0 }));
    vi.mocked(api.getScanResults).mockResolvedValue({ services: {} });

    renderAt("/jobs/job-1");
    await screen.findByText(/updates automatically/);
    expect(api.getScan).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(2100);
    expect(api.getScan).toHaveBeenCalledTimes(2);
    expect(await screen.findByText("completed")).toBeInTheDocument();

    // no further polling once terminal
    await vi.advanceTimersByTimeAsync(5000);
    expect(api.getScan).toHaveBeenCalledTimes(2);
  });
});
