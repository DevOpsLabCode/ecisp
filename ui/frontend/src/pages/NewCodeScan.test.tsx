import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { CodeScanSummary, GitHubOAuthStatus, RepoBranchesResponse } from "../types";
import NewCodeScan from "./NewCodeScan";

function LocationProbe({ onSearch, children }: { onSearch: (search: string) => void; children: ReactNode }) {
  const location = useLocation();
  onSearch(location.search);
  return <>{children}</>;
}

vi.mock("../api/client", () => ({
  api: {
    uploadCodeScan: vi.fn(),
    createCodeScanFromRepo: vi.fn(),
    listCodeScanBranches: vi.fn(),
    githubOAuthStatus: vi.fn(),
    githubOAuthLoginUrl: vi.fn(() => "http://localhost:8000/api/github/oauth/login"),
  },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

function renderPage(initialEntries: string[] = ["/code-scan"]) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <NewCodeScan />
    </MemoryRouter>,
  );
}

function scanSummary(overrides: Partial<CodeScanSummary> = {}): CodeScanSummary {
  return {
    id: "scan-1",
    source_type: "upload",
    source_label: "myproj.zip",
    branch: null,
    commit_sha: null,
    status: "queued",
    created_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    error: null,
    severity_counts: null,
    finding_count: null,
    dast_status: "not_run",
    dast_target_url: null,
    dast_error: null,
    ...overrides,
  };
}

function oauthStatus(overrides: Partial<GitHubOAuthStatus> = {}): GitHubOAuthStatus {
  return { connected: false, configured: true, ...overrides };
}

function branches(overrides: Partial<RepoBranchesResponse> = {}): RepoBranchesResponse {
  return { private: false, default_branch: "main", branches: ["main", "develop"], ...overrides };
}

describe("NewCodeScan", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.githubOAuthStatus).mockResolvedValue(oauthStatus());
  });

  it("uploads a file and navigates to the detail page", async () => {
    const user = userEvent.setup();
    vi.mocked(api.uploadCodeScan).mockResolvedValue(scanSummary());
    renderPage();

    const file = new File(["dummy"], "myproj.zip", { type: "application/zip" });
    const input = screen.getByLabelText("Choose file");
    await user.upload(input, file);

    expect(screen.getByText(/myproj\.zip/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.uploadCodeScan).toHaveBeenCalledWith(file);
    expect(navigateMock).toHaveBeenCalledWith("/code-scans/scan-1");
  });

  it("disables the upload start button until a file is chosen", () => {
    renderPage();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
  });

  it("shows an error banner when the upload fails", async () => {
    const user = userEvent.setup();
    vi.mocked(api.uploadCodeScan).mockRejectedValue(new Error("Archive rejected: zip-slip detected"));
    renderPage();

    const file = new File(["dummy"], "evil.zip", { type: "application/zip" });
    await user.upload(screen.getByLabelText("Choose file"), file);
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("Archive rejected: zip-slip detected")).toBeInTheDocument();
  });

  it("stringifies a non-Error upload rejection in the error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.uploadCodeScan).mockRejectedValue("network exploded");
    renderPage();

    const file = new File(["dummy"], "evil.zip", { type: "application/zip" });
    await user.upload(screen.getByLabelText("Choose file"), file);
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("switches to the repo URL mode and looks up branches for a public repo", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches());
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    expect(api.listCodeScanBranches).toHaveBeenCalledWith("https://github.com/octocat/Hello-World");
    expect(await screen.findByLabelText("Branch")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "main" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeEnabled();
  });

  it("starts a repo scan with the selected branch", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches());
    vi.mocked(api.createCodeScanFromRepo).mockResolvedValue(scanSummary({ id: "scan-2", source_type: "repo_url" }));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));
    await screen.findByLabelText("Branch");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createCodeScanFromRepo).toHaveBeenCalledWith({
      repo_url: "https://github.com/octocat/Hello-World",
      branch: "main",
    });
    expect(navigateMock).toHaveBeenCalledWith("/code-scans/scan-2");
  });

  it("switches back to upload mode after visiting repo mode", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    expect(screen.getByLabelText("Repository URL")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Upload archive" }));
    expect(screen.getByLabelText("Choose file")).toBeInTheDocument();
  });

  it("starts a repo scan with a non-default branch once changed", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches());
    vi.mocked(api.createCodeScanFromRepo).mockResolvedValue(scanSummary({ id: "scan-3", source_type: "repo_url" }));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));
    await screen.findByLabelText("Branch");

    await user.selectOptions(screen.getByLabelText("Branch"), "develop");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(api.createCodeScanFromRepo).toHaveBeenCalledWith({
      repo_url: "https://github.com/octocat/Hello-World",
      branch: "develop",
    });
  });

  it("shows an error banner when starting a repo scan fails", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches());
    vi.mocked(api.createCodeScanFromRepo).mockRejectedValue(new Error("GitHub rejected this request"));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));
    await screen.findByLabelText("Branch");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("GitHub rejected this request")).toBeInTheDocument();
  });

  it("stringifies a non-Error repo scan rejection", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches());
    vi.mocked(api.createCodeScanFromRepo).mockRejectedValue("network exploded");
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));
    await screen.findByLabelText("Branch");
    await user.click(screen.getByRole("button", { name: "Start scan" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("shows a branch lookup error", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockRejectedValue(new Error("Not a valid GitHub repository URL"));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "not-a-url");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    expect(await screen.findByText("Not a valid GitHub repository URL")).toBeInTheDocument();
  });

  it("stringifies a non-Error branch lookup rejection", async () => {
    const user = userEvent.setup();
    vi.mocked(api.listCodeScanBranches).mockRejectedValue("network exploded");
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/Hello-World");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });

  it("prompts to connect GitHub for a private repo when not connected", async () => {
    const user = userEvent.setup();
    vi.mocked(api.githubOAuthStatus).mockResolvedValue(oauthStatus({ connected: false, configured: true }));
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches({ private: true }));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/private-repo");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    const connectLink = await screen.findByRole("link", { name: "Connect GitHub" });
    expect(connectLink).toHaveAttribute("href", "http://localhost:8000/api/github/oauth/login");
    expect(screen.queryByLabelText("Branch")).not.toBeInTheDocument();
  });

  it("allows scanning a private repo once GitHub is connected", async () => {
    const user = userEvent.setup();
    vi.mocked(api.githubOAuthStatus).mockResolvedValue(oauthStatus({ connected: true, configured: true }));
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches({ private: true }));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/private-repo");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    expect(await screen.findByLabelText("Branch")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Connect GitHub" })).not.toBeInTheDocument();
  });

  it("shows an unconfigured message instead of a connect link when OAuth isn't set up", async () => {
    const user = userEvent.setup();
    vi.mocked(api.githubOAuthStatus).mockResolvedValue(oauthStatus({ connected: false, configured: false }));
    vi.mocked(api.listCodeScanBranches).mockResolvedValue(branches({ private: true }));
    renderPage();

    await user.click(screen.getByRole("button", { name: "GitHub repo URL" }));
    await user.type(screen.getByLabelText("Repository URL"), "https://github.com/octocat/private-repo");
    await user.click(screen.getByRole("button", { name: "Look up branches" }));

    expect(await screen.findByText(/GitHub OAuth isn't configured/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Connect GitHub" })).not.toBeInTheDocument();
  });

  it("shows a success banner after a GitHub connect redirect, and it stays up once the query param is stripped", async () => {
    let search = "";
    render(
      <MemoryRouter initialEntries={["/code-scan?github_connected=1"]}>
        <Routes>
          <Route
            path="/code-scan"
            element={
              <LocationProbe onSearch={(s) => (search = s)}>
                <NewCodeScan />
              </LocationProbe>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("GitHub connected.")).toBeInTheDocument();
    expect(search).toBe("");
    expect(screen.getByText("GitHub connected.")).toBeInTheDocument();
  });

  it("shows no success banner on a plain visit", () => {
    renderPage(["/code-scan"]);
    expect(screen.queryByText("GitHub connected.")).not.toBeInTheDocument();
  });
});
