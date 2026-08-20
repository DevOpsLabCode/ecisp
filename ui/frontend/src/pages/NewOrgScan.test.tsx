import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { OrgScanSummary } from "../types";
import NewOrgScan from "./NewOrgScan";

vi.mock("../api/client", () => ({
  api: { createOrgScan: vi.fn() },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <NewOrgScan />
    </MemoryRouter>,
  );
}

function summary(overrides: Partial<OrgScanSummary> = {}): OrgScanSummary {
  return {
    id: "scan-1",
    org: "my-org",
    status: "queued",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    error: null,
    total_repos: 0,
    completed_repos: 0,
    repos_with_findings: 0,
    severity_totals: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    issues_created: 0,
    email_sent: false,
    ...overrides,
  };
}

describe("NewOrgScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("disables the start button until org and token are filled in", async () => {
    const user = userEvent.setup();
    renderPage();
    const button = screen.getByRole("button", { name: "Start scan" });
    expect(button).toBeDisabled();

    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    expect(button).toBeDisabled();

    await user.type(screen.getByLabelText("GitHub personal access token"), "ghp_abc");
    expect(button).toBeEnabled();
  });

  it("submits with defaults (issue creation on, archived off) and navigates to the detail page", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createOrgScan).mockResolvedValue(summary());

    renderPage();
    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    await user.type(screen.getByLabelText("GitHub personal access token"), "ghp_abc");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createOrgScan).toHaveBeenCalledWith({
      org: "my-org",
      github_token: "ghp_abc",
      notify_email: null,
      create_issues: true,
      include_archived: false,
      max_workers: 4,
    });
    expect(navigateMock).toHaveBeenCalledWith("/org-scans/scan-1");
  });

  it("submits unchecked issue-creation and a notify email when provided", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createOrgScan).mockResolvedValue(summary());

    renderPage();
    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    await user.type(screen.getByLabelText("GitHub personal access token"), "ghp_abc");
    await user.click(screen.getByLabelText("Create GitHub Issues for Critical/High findings"));
    await user.click(screen.getByLabelText("Include archived repositories"));
    await user.type(screen.getByLabelText("Notify email (optional)"), "security@example.com");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createOrgScan).toHaveBeenCalledWith({
      org: "my-org",
      github_token: "ghp_abc",
      notify_email: "security@example.com",
      create_issues: false,
      include_archived: true,
      max_workers: 4,
    });
  });

  it("submits a custom max-workers value", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createOrgScan).mockResolvedValue(summary());

    renderPage();
    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    await user.type(screen.getByLabelText("GitHub personal access token"), "ghp_abc");
    const workers = screen.getByLabelText("Repos scanned in parallel");
    await user.clear(workers);
    await user.type(workers, "8");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createOrgScan).toHaveBeenCalledWith(expect.objectContaining({ max_workers: 8 }));
  });

  it("shows an error banner when the scan fails to start", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createOrgScan).mockRejectedValue(new Error("GitHub rejected this token"));

    renderPage();
    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    await user.type(screen.getByLabelText("GitHub personal access token"), "bad-token");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("GitHub rejected this token")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createOrgScan).mockRejectedValue("network exploded");

    renderPage();
    await user.type(screen.getByLabelText("Organization or account"), "my-org");
    await user.type(screen.getByLabelText("GitHub personal access token"), "ghp_abc");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });
});
