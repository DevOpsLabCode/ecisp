import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RuntimeClusterDetail } from "../types";
import NewRuntimeCluster from "./NewRuntimeCluster";

vi.mock("../api/client", () => ({
  api: {
    createRuntimeCluster: vi.fn(),
    runtimeClusterInstallScriptUrl: vi.fn((id: string) => `http://localhost:8000/api/runtime-clusters/${id}/install.sh`),
  },
}));

function renderPage() {
  return render(
    <MemoryRouter>
      <NewRuntimeCluster />
    </MemoryRouter>,
  );
}

function clusterDetail(overrides: Partial<RuntimeClusterDetail> = {}): RuntimeClusterDetail {
  return {
    id: "cluster-1",
    name: "prod-eks",
    created_at: "2026-01-01T00:00:00Z",
    last_event_at: null,
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    finding_count: 0,
    install_token: "secret-token",
    findings: [],
    ...overrides,
  };
}

describe("NewRuntimeCluster", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("disables the register button until a name is entered", async () => {
    const user = userEvent.setup();
    renderPage();
    const button = screen.getByRole("button", { name: "Register cluster" });
    expect(button).toBeDisabled();

    await user.type(screen.getByLabelText("Cluster name"), "prod-eks");
    expect(button).toBeEnabled();
  });

  it("registers a cluster and shows the install command", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRuntimeCluster).mockResolvedValue(clusterDetail());

    renderPage();
    await user.type(screen.getByLabelText("Cluster name"), "prod-eks");
    await user.click(screen.getByRole("button", { name: "Register cluster" }));

    expect(api.createRuntimeCluster).toHaveBeenCalledWith({ name: "prod-eks" });
    expect(await screen.findByText(/registered/)).toBeInTheDocument();
    expect(
      screen.getByText("curl -fsSL http://localhost:8000/api/runtime-clusters/cluster-1/install.sh | bash"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View cluster" })).toHaveAttribute(
      "href",
      "/runtime-clusters/cluster-1",
    );
  });

  it("copies the install command to the clipboard", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRuntimeCluster).mockResolvedValue(clusterDetail());

    renderPage();
    await user.type(screen.getByLabelText("Cluster name"), "prod-eks");
    await user.click(screen.getByRole("button", { name: "Register cluster" }));
    await screen.findByText(/registered/);

    await user.click(screen.getByRole("button", { name: "Copy" }));
    expect(await navigator.clipboard.readText()).toBe(
      "curl -fsSL http://localhost:8000/api/runtime-clusters/cluster-1/install.sh | bash",
    );
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("shows an error banner when registration fails", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRuntimeCluster).mockRejectedValue(new Error("name is required"));

    renderPage();
    await user.type(screen.getByLabelText("Cluster name"), "prod-eks");
    await user.click(screen.getByRole("button", { name: "Register cluster" }));

    expect(await screen.findByText("name is required")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRuntimeCluster).mockRejectedValue("network exploded");

    renderPage();
    await user.type(screen.getByLabelText("Cluster name"), "prod-eks");
    await user.click(screen.getByRole("button", { name: "Register cluster" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });
});
