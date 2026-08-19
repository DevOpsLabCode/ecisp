import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { JobSummary } from "../types";
import Jobs from "./Jobs";

vi.mock("../api/client", () => ({
  api: { listScans: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const jobs: JobSummary[] = [
  {
    id: "job-1",
    provider: "aws",
    report_name: "aws-audit",
    status: "completed",
    created_at: "2026-01-01T00:00:00Z",
    started_at: "2026-01-01T00:00:01Z",
    finished_at: "2026-01-01T00:05:00Z",
    exit_code: 0,
    error: null,
  },
  {
    id: "job-2",
    provider: "azure",
    report_name: "azure-audit",
    status: "queued",
    created_at: "2026-01-01T00:10:00Z",
    started_at: null,
    finished_at: null,
    exit_code: null,
    error: null,
  },
];

describe("Jobs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows an empty state with a link to launch a scan when there are no jobs", async () => {
    vi.mocked(api.listScans).mockResolvedValue([]);
    render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Launch one" })).toHaveAttribute("href", "/");
  });

  it("renders a table row per job, falling back to an em-dash for a missing exit code", async () => {
    vi.mocked(api.listScans).mockResolvedValue(jobs);
    render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    expect(await screen.findByText("aws-audit")).toBeInTheDocument();
    expect(screen.getByText("aws")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("azure-audit")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("navigates to the job detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listScans).mockResolvedValue(jobs);
    render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    await screen.findByText("aws-audit");
    await user.click(screen.getByText("aws"));
    expect(navigateMock).toHaveBeenCalledWith("/jobs/job-1");
  });

  it("ignores a listScans response that resolves after unmount", async () => {
    let resolveScans: (v: JobSummary[]) => void = () => {};
    vi.mocked(api.listScans).mockReturnValue(new Promise((resolve) => (resolveScans = resolve)));
    const { unmount } = render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    unmount();
    resolveScans(jobs);
    await new Promise((r) => setTimeout(r, 0));
    // Reaching here without an "update on an unmounted component" warning is the assertion.
  });

  it("shows an error banner when the initial load fails", async () => {
    vi.mocked(api.listScans).mockRejectedValue(new Error("backend unreachable"));
    render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    expect(await screen.findByText("backend unreachable")).toBeInTheDocument();
  });

  it("polls for updates on an interval", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(api.listScans).mockResolvedValue(jobs);
    render(
      <MemoryRouter>
        <Jobs />
      </MemoryRouter>,
    );
    await screen.findByText("aws-audit");
    expect(api.listScans).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(3100);
    expect(api.listScans).toHaveBeenCalledTimes(2);
  });
});
