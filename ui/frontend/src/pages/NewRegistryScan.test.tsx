import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { RegistryScanSummary } from "../types";
import NewRegistryScan from "./NewRegistryScan";

vi.mock("../api/client", () => ({
  api: { createRegistryScan: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <NewRegistryScan />
    </MemoryRouter>,
  );
}

function scanSummary(overrides: Partial<RegistryScanSummary> = {}): RegistryScanSummary {
  return {
    id: "scan-1",
    image_ref: "alpine:3.18",
    status: "queued",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    error: null,
    severity_counts: null,
    finding_count: null,
    ...overrides,
  };
}

describe("NewRegistryScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("disables the start button until an image reference is entered", async () => {
    const user = userEvent.setup();
    renderPage();
    const button = screen.getByRole("button", { name: "Start scan" });
    expect(button).toBeDisabled();

    await user.type(screen.getByLabelText("Image reference"), "alpine:3.18");
    expect(button).toBeEnabled();
  });

  it("submits with just an image reference and navigates to the detail page", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRegistryScan).mockResolvedValue(scanSummary());

    renderPage();
    await user.type(screen.getByLabelText("Image reference"), "alpine:3.18");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createRegistryScan).toHaveBeenCalledWith({
      image_ref: "alpine:3.18",
      username: null,
      password: null,
      registry_token: null,
      insecure: false,
    });
    expect(navigateMock).toHaveBeenCalledWith("/registry-scans/scan-1");
  });

  it("submits with credentials and the insecure flag", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRegistryScan).mockResolvedValue(scanSummary({ id: "scan-2" }));

    renderPage();
    await user.type(screen.getByLabelText("Image reference"), "myregistry.jfrog.io/docker-local/app:1.0");
    await user.type(screen.getByLabelText("Username"), "deploy");
    await user.type(screen.getByLabelText("Password"), "s3cret");
    await user.click(screen.getByLabelText("Allow insecure connection (self-signed certificate)"));
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createRegistryScan).toHaveBeenCalledWith({
      image_ref: "myregistry.jfrog.io/docker-local/app:1.0",
      username: "deploy",
      password: "s3cret",
      registry_token: null,
      insecure: true,
    });
    expect(navigateMock).toHaveBeenCalledWith("/registry-scans/scan-2");
  });

  it("submits a registry token instead of username/password", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRegistryScan).mockResolvedValue(scanSummary());

    renderPage();
    await user.type(screen.getByLabelText("Image reference"), "ghcr.io/org/app:1.0");
    await user.type(screen.getByLabelText("Registry token (instead of username/password)"), "tok_abc");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createRegistryScan).toHaveBeenCalledWith(
      expect.objectContaining({ registry_token: "tok_abc" }),
    );
  });

  it("shows an error banner when the scan fails to start", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRegistryScan).mockRejectedValue(new Error("could not scan 'bad:ref': DENIED: denied"));

    renderPage();
    await user.type(screen.getByLabelText("Image reference"), "bad:ref");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("could not scan 'bad:ref': DENIED: denied")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createRegistryScan).mockRejectedValue("network exploded");

    renderPage();
    await user.type(screen.getByLabelText("Image reference"), "alpine:3.18");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });
});
