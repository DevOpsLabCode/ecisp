import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RuntimeClusterDetail as RuntimeClusterDetailType } from "../types";
import RuntimeClusterDetail from "./RuntimeClusterDetail";

vi.mock("../api/client", () => ({
  api: {
    getRuntimeCluster: vi.fn(),
    runtimeClusterReportUrl: vi.fn(
      (id: string, fmt: string) => `http://localhost:8000/api/runtime-clusters/${id}/report.${fmt}`,
    ),
    runtimeClusterSimulationScriptUrl: vi.fn(
      (id: string) => `http://localhost:8000/api/runtime-clusters/${id}/simulate.sh`,
    ),
  },
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/runtime-clusters/:id" element={<RuntimeClusterDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

function makeCluster(overrides: Partial<RuntimeClusterDetailType> = {}): RuntimeClusterDetailType {
  return {
    id: "cluster-1",
    name: "prod-eks",
    created_at: "2026-01-01T00:00:00Z",
    last_event_at: "2026-01-01T00:05:00Z",
    severity_counts: { critical: 1, high: 2, medium: 3, low: 4, info: 0 },
    finding_count: 10,
    install_token: "secret-token",
    findings: [
      {
        repository: "prod-eks",
        file: "default/test-victim/test-victim",
        line: null,
        scanner: "falco",
        rule_id: "Read sensitive file untrusted",
        severity: "high",
        category: "runtime",
        message: "Warning Sensitive file opened for reading | command=cat /etc/shadow",
        remediation: "Investigate the process/command in the alert message.",
        fingerprint: "fp-1",
      },
    ],
    ...overrides,
  };
}

describe("RuntimeClusterDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("shows a loading state before the cluster loads", () => {
    vi.mocked(api.getRuntimeCluster).mockReturnValue(new Promise(() => {}));
    renderAt("/runtime-clusters/cluster-1");
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  it("shows an error banner when the fetch fails", async () => {
    vi.mocked(api.getRuntimeCluster).mockRejectedValue(new Error("cluster fetch failed"));
    renderAt("/runtime-clusters/cluster-1");
    expect(await screen.findByText("cluster fetch failed")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    vi.mocked(api.getRuntimeCluster).mockRejectedValue("network exploded");
    renderAt("/runtime-clusters/cluster-1");
    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("renders the header and severity tiles when findings exist", async () => {
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    expect(await screen.findByRole("heading", { name: "prod-eks" })).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument(); // high tile
  });

  it("shows a waiting banner and no findings section when nothing has been reported yet", async () => {
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(
      makeCluster({ finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], last_event_at: null }),
    );
    renderAt("/runtime-clusters/cluster-1");
    expect(await screen.findByText(/Waiting for events from the sensor/)).toBeInTheDocument();
    expect(screen.queryByText("Findings")).not.toBeInTheDocument();
  });

  it("expands a finding row to show its rule and remediation, and collapses on a second click", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");

    const row = await screen.findByText(/command=cat \/etc\/shadow/);
    expect(screen.queryByText("Investigate the process/command in the alert message.")).not.toBeInTheDocument();

    await user.click(row);
    expect(screen.getByText("Investigate the process/command in the alert message.")).toBeInTheDocument();
    expect(screen.getByText("Read sensitive file untrusted")).toBeInTheDocument();

    await user.click(row);
    expect(screen.queryByText("Investigate the process/command in the alert message.")).not.toBeInTheDocument();
  });

  it("filters findings by severity, and re-adding a severity brings its findings back", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    await screen.findByText(/command=cat \/etc\/shadow/);

    const highTab = screen.getByRole("button", { name: "high" });
    await user.click(highTab);
    expect(screen.queryByText(/command=cat \/etc\/shadow/)).not.toBeInTheDocument();
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();

    await user.click(highTab);
    expect(screen.getByText(/command=cat \/etc\/shadow/)).toBeInTheDocument();
  });

  it("filters findings by search text", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    await screen.findByText(/command=cat \/etc\/shadow/);

    await user.type(screen.getByPlaceholderText("Search findings…"), "nonexistent");
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();
  });

  it("shows report download links once there are findings", async () => {
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    const link = await screen.findByText("Download SARIF");
    expect(link).toHaveAttribute("href", "http://localhost:8000/api/runtime-clusters/cluster-1/report.sarif");
  });

  it("polls for updates on an interval", async () => {
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    await screen.findByRole("heading", { name: "prod-eks" });
    expect(api.getRuntimeCluster).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(5100);
    expect(api.getRuntimeCluster).toHaveBeenCalledTimes(2);
  });

  it("shows the attack simulation command only after the user asks for it", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    await screen.findByRole("heading", { name: "prod-eks" });

    expect(
      screen.queryByText("curl -fsSL http://localhost:8000/api/runtime-clusters/cluster-1/simulate.sh | bash"),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show simulation command" }));
    expect(
      screen.getByText("curl -fsSL http://localhost:8000/api/runtime-clusters/cluster-1/simulate.sh | bash"),
    ).toBeInTheDocument();
  });

  it("copies the attack simulation command to the clipboard", async () => {
    const user = userEvent.setup();
    vi.mocked(api.getRuntimeCluster).mockResolvedValue(makeCluster());
    renderAt("/runtime-clusters/cluster-1");
    await screen.findByRole("heading", { name: "prod-eks" });

    await user.click(screen.getByRole("button", { name: "Show simulation command" }));
    await user.click(screen.getByRole("button", { name: "Copy" }));

    expect(await navigator.clipboard.readText()).toBe(
      "curl -fsSL http://localhost:8000/api/runtime-clusters/cluster-1/simulate.sh | bash",
    );
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("ignores a getRuntimeCluster response that resolves after unmount", async () => {
    let resolveCluster: (v: RuntimeClusterDetailType) => void = () => {};
    vi.mocked(api.getRuntimeCluster).mockReturnValue(new Promise((resolve) => (resolveCluster = resolve)));
    const { unmount } = renderAt("/runtime-clusters/cluster-1");
    unmount();
    resolveCluster(makeCluster());
    await new Promise((r) => setTimeout(r, 0));
  });
});
