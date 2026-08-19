import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { JobSummary, ProviderMeta } from "../types";
import NewScan from "./NewScan";

vi.mock("../api/client", () => ({
  api: {
    providers: vi.fn(),
    health: vi.fn(),
    createScan: vi.fn(),
  },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const AWS: ProviderMeta = {
  code: "aws",
  label: "Amazon Web Services",
  authMethods: {
    profile: { label: "Named profile", fields: [{ name: "profile", label: "Profile name", type: "text", required: true }] },
    access_keys: {
      label: "Access keys",
      fields: [{ name: "aws_access_key_id", label: "Access Key ID", type: "text", required: true }],
    },
  },
  scopeFields: [{ name: "regions", label: "Regions", type: "multi" }],
};

const AZURE: ProviderMeta = {
  code: "azure",
  label: "Microsoft Azure",
  authMethods: { cli: { label: "Azure CLI", fields: [] } },
  scopeFields: [],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <NewScan />
    </MemoryRouter>,
  );
}

describe("NewScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.providers).mockResolvedValue([AWS, AZURE]);
    vi.mocked(api.health).mockResolvedValue({ status: "ok", engine_available: true, engine_error: null });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads providers and defaults to the first one with its first auth method", async () => {
    renderPage();
    expect(await screen.findByText("Amazon Web Services")).toBeInTheDocument();
    expect(await screen.findByText("Profile name *")).toBeInTheDocument();
  });

  it("shows an error banner when the engine is unavailable", async () => {
    vi.mocked(api.health).mockResolvedValue({
      status: "ok",
      engine_available: false,
      engine_error: "ModuleNotFoundError: no module named foo",
    });
    renderPage();
    expect(await screen.findByText(/Engine not importable/)).toHaveTextContent(
      "ModuleNotFoundError: no module named foo",
    );
  });

  it("treats the engine as unavailable when the health check itself fails", async () => {
    vi.mocked(api.health).mockRejectedValue(new Error("connection refused"));
    renderPage();
    expect(await screen.findByText(/Engine not importable/)).toBeInTheDocument();
  });

  it("defaults to an empty auth method when the first provider has none configured", async () => {
    const noAuthProvider: ProviderMeta = { code: "mystery", label: "Mystery Cloud", authMethods: {}, scopeFields: [] };
    vi.mocked(api.providers).mockResolvedValue([noAuthProvider, AWS]);
    renderPage();
    expect(await screen.findByText("Mystery Cloud")).toBeInTheDocument();
    expect(screen.getByText("Authentication")).toBeInTheDocument();
  });

  it("defaults to an empty auth method when switching to a provider with none configured", async () => {
    const user = userEvent.setup();
    const noAuthProvider: ProviderMeta = { code: "mystery", label: "Mystery Cloud", authMethods: {}, scopeFields: [] };
    vi.mocked(api.providers).mockResolvedValue([AWS, noAuthProvider]);
    renderPage();
    await screen.findByText("Profile name *");
    await user.click(screen.getByText("Mystery Cloud"));
    expect(await screen.findByText("Mystery Cloud")).toHaveClass("active");
    expect(screen.queryByText("Profile name *")).not.toBeInTheDocument();
  });

  it("shows a load error banner when providers() fails", async () => {
    vi.mocked(api.providers).mockRejectedValue(new Error("network down"));
    renderPage();
    expect(await screen.findByText(/Could not reach the backend/)).toHaveTextContent("network down");
  });

  it("switches provider and resets auth method to the new provider's first method", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Profile name *");
    await user.click(screen.getByText("Microsoft Azure"));
    expect(await screen.findByRole("button", { name: "Azure CLI" })).toHaveClass("active");
    expect(screen.getByText(/No credentials required/)).toBeInTheDocument();
  });

  it("switches auth method within a provider", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Profile name *");
    await user.click(screen.getByRole("button", { name: "Access keys" }));
    expect(screen.getByText("Access Key ID *")).toBeInTheDocument();
    expect(screen.queryByText("Profile name *")).not.toBeInTheDocument();
  });

  it("lets the user fill in a scope field", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Scope");
    await user.type(screen.getByLabelText("Regions"), "us-east-1{Enter}");
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
  });

  it("submits the scan and navigates to the job detail page", async () => {
    const user = userEvent.setup();
    const job: JobSummary = {
      id: "job-123",
      provider: "aws",
      report_name: "aws-job-123",
      status: "queued",
      created_at: "2026-01-01T00:00:00Z",
      started_at: null,
      finished_at: null,
      exit_code: null,
      error: null,
    };
    vi.mocked(api.createScan).mockResolvedValue(job);

    renderPage();
    await screen.findByText("Profile name *");
    await user.type(screen.getByLabelText("Profile name *"), "audit");
    await user.click(screen.getByRole("button", { name: "Launch scan" }));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/jobs/job-123"));
    const payload = vi.mocked(api.createScan).mock.calls[0][0];
    expect(payload.provider).toBe("aws");
    expect(payload.auth_method).toBe("profile");
    expect(payload.auth).toEqual({ profile: "audit" });
  });

  it("shows a submit error banner when createScan rejects", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createScan).mockRejectedValue(new Error("Missing required field 'profile'"));

    renderPage();
    await screen.findByText("Profile name *");
    await user.click(screen.getByRole("button", { name: "Launch scan" }));

    expect(await screen.findByText("Missing required field 'profile'")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the submit error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createScan).mockRejectedValue("backend exploded");

    renderPage();
    await screen.findByText("Profile name *");
    await user.click(screen.getByRole("button", { name: "Launch scan" }));

    expect(await screen.findByText("backend exploded")).toBeInTheDocument();
  });

  it("falls back to 10 max workers at submit time when the field was cleared", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createScan).mockResolvedValue({
      id: "job-789",
      provider: "aws",
      report_name: "aws-job-789",
      status: "queued",
      created_at: "2026-01-01T00:00:00Z",
      started_at: null,
      finished_at: null,
      exit_code: null,
      error: null,
    });

    renderPage();
    await screen.findByText("Profile name *");
    await user.type(screen.getByLabelText("Profile name *"), "audit");
    await user.clear(screen.getByLabelText("Max workers"));
    await user.click(screen.getByRole("button", { name: "Launch scan" }));

    await waitFor(() => expect(api.createScan).toHaveBeenCalled());
    expect(vi.mocked(api.createScan).mock.calls[0][0].max_workers).toBe(10);
  });

  it("lets the user configure report name, services, ruleset, workers, and debug", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createScan).mockResolvedValue({
      id: "job-456",
      provider: "aws",
      report_name: "custom-name",
      status: "queued",
      created_at: "2026-01-01T00:00:00Z",
      started_at: null,
      finished_at: null,
      exit_code: null,
      error: null,
    });

    renderPage();
    await screen.findByText("Profile name *");
    await user.type(screen.getByLabelText("Profile name *"), "audit");
    await user.type(screen.getByLabelText("Report name"), "custom-name");
    await user.type(screen.getByLabelText("Ruleset"), "-extra");
    await user.click(screen.getByLabelText("Verbose/debug logging"));
    await user.clear(screen.getByLabelText("Max workers"));
    await user.type(screen.getByLabelText("Max workers"), "3");
    await user.click(screen.getByRole("button", { name: "Launch scan" }));

    await waitFor(() => expect(api.createScan).toHaveBeenCalled());
    const payload = vi.mocked(api.createScan).mock.calls[0][0];
    expect(payload.report_name).toBe("custom-name");
    expect(payload.ruleset).toBe("default.json-extra");
    expect(payload.debug).toBe(true);
    expect(payload.max_workers).toBe(3);
  });
});
