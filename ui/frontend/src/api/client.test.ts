import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./client";

function mockFetchOnce(body: unknown, init: { ok: boolean; status?: number } = { ok: true }) {
  return vi.fn().mockResolvedValue({
    ok: init.ok,
    status: init.status ?? (init.ok ? 200 : 500),
    statusText: "Error",
    json: async () => body,
  });
}

describe("api client", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("health() calls /api/health and returns parsed JSON", async () => {
    globalThis.fetch = mockFetchOnce({ status: "ok", engine_available: true, engine_error: null });
    const result = await api.health();
    expect(result.status).toBe("ok");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/health"),
      expect.objectContaining({ headers: { "content-type": "application/json" } }),
    );
  });

  it("providers() calls /api/providers", async () => {
    globalThis.fetch = mockFetchOnce([{ code: "aws" }]);
    const result = await api.providers();
    expect(result).toEqual([{ code: "aws" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/providers"), expect.anything());
  });

  it("createScan() POSTs to /api/scans with the body serialized", async () => {
    globalThis.fetch = mockFetchOnce({ id: "abc", status: "queued" });
    const body = {
      provider: "aws",
      auth_method: "profile",
      auth: { profile: "audit" },
      scope: {},
      services: [],
      skipped_services: [],
      ruleset: "default.json",
      max_workers: 10,
      debug: false,
    };
    const result = await api.createScan(body);
    expect(result.id).toBe("abc");
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("listScans() calls /api/scans", async () => {
    globalThis.fetch = mockFetchOnce([{ id: "abc" }]);
    const result = await api.listScans();
    expect(result).toEqual([{ id: "abc" }]);
  });

  it("getScan() calls /api/scans/:id", async () => {
    globalThis.fetch = mockFetchOnce({ id: "abc" });
    await api.getScan("abc");
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/scans/abc"), expect.anything());
  });

  it("getScanResults() calls /api/scans/:id/results", async () => {
    globalThis.fetch = mockFetchOnce({ provider_code: "aws" });
    const result = await api.getScanResults("abc");
    expect(result.provider_code).toBe("aws");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/scans/abc/results"),
      expect.anything(),
    );
  });

  it("throws the server-provided detail message on a non-ok response", async () => {
    globalThis.fetch = mockFetchOnce({ detail: "Missing required field 'profile'" }, { ok: false, status: 400 });
    await expect(api.getScan("abc")).rejects.toThrow("Missing required field 'profile'");
  });

  it("falls back to statusText when the error body has no detail field", async () => {
    globalThis.fetch = mockFetchOnce({ message: "something else entirely" }, { ok: false, status: 400 });
    await expect(api.getScan("abc")).rejects.toThrow("Error"); // mockFetchOnce's statusText
  });

  it("falls back to statusText when the error body isn't JSON", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => {
        throw new Error("not json");
      },
    });
    await expect(api.getScan("abc")).rejects.toThrow("Internal Server Error");
  });

  it("createBatch() POSTs multipart form data without a content-type header", async () => {
    globalThis.fetch = mockFetchOnce({ id: "batch-1", queued_jobs: 2, skipped_rows: 0 });
    const file = new File(["provider,auth_method\naws,profile\n"], "accounts.csv", { type: "text/csv" });
    const result = await api.createBatch(file);
    expect(result.id).toBe("batch-1");

    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain("/api/batches");
    expect(init.method).toBe("POST");
    expect(init.headers).toBeUndefined();
    expect(init.body).toBeInstanceOf(FormData);
    expect(init.body.get("file")).toBe(file);
  });

  it("createBatch() throws the server detail on failure", async () => {
    globalThis.fetch = mockFetchOnce({ detail: "Unsupported file type" }, { ok: false, status: 400 });
    const file = new File(["x"], "accounts.txt");
    await expect(api.createBatch(file)).rejects.toThrow("Unsupported file type");
  });

  it("listBatches() calls /api/batches", async () => {
    globalThis.fetch = mockFetchOnce([{ id: "batch-1" }]);
    const result = await api.listBatches();
    expect(result).toEqual([{ id: "batch-1" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/batches"), expect.anything());
  });

  it("getBatch() calls /api/batches/:id", async () => {
    globalThis.fetch = mockFetchOnce({ id: "batch-1", jobs: [], errors: [] });
    await api.getBatch("batch-1");
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/batches/batch-1"), expect.anything());
  });

  it("batchTemplateUrl() returns an absolute URL to the CSV template", () => {
    expect(api.batchTemplateUrl()).toContain("/api/batches/template.csv");
  });

  it("createOrgScan() POSTs to /api/org-scans with the body serialized", async () => {
    globalThis.fetch = mockFetchOnce({ id: "scan-1", status: "queued" });
    const body = {
      org: "my-org",
      github_token: "ghp_abc",
      notify_email: null,
      create_issues: true,
      max_workers: 4,
      include_archived: false,
    };
    const result = await api.createOrgScan(body);
    expect(result.id).toBe("scan-1");
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("listOrgScans() calls /api/org-scans", async () => {
    globalThis.fetch = mockFetchOnce([{ id: "scan-1" }]);
    const result = await api.listOrgScans();
    expect(result).toEqual([{ id: "scan-1" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/org-scans"), expect.anything());
  });

  it("getOrgScan() calls /api/org-scans/:id", async () => {
    globalThis.fetch = mockFetchOnce({ id: "scan-1" });
    await api.getOrgScan("scan-1");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/org-scans/scan-1"),
      expect.anything(),
    );
  });

  it("orgScanReportUrl() returns an absolute URL for the given format", () => {
    expect(api.orgScanReportUrl("scan-1", "sarif")).toContain("/api/org-scans/scan-1/report.sarif");
  });

  it("uploadCodeScan() POSTs multipart form data with credentials included", async () => {
    globalThis.fetch = mockFetchOnce({ id: "code-scan-1", status: "queued" });
    const file = new File(["PK"], "myproj.zip", { type: "application/zip" });
    const result = await api.uploadCodeScan(file);
    expect(result.id).toBe("code-scan-1");

    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain("/api/code-scans/upload");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
    expect(init.headers).toBeUndefined();
    expect(init.body).toBeInstanceOf(FormData);
    expect(init.body.get("file")).toBe(file);
  });

  it("uploadCodeScan() throws the server detail on failure", async () => {
    globalThis.fetch = mockFetchOnce({ detail: "Archive rejected: zip-slip detected" }, { ok: false, status: 400 });
    const file = new File(["x"], "evil.zip");
    await expect(api.uploadCodeScan(file)).rejects.toThrow("Archive rejected: zip-slip detected");
  });

  it("createCodeScanFromRepo() POSTs to /api/code-scans/repo with the body serialized", async () => {
    globalThis.fetch = mockFetchOnce({ id: "code-scan-1", status: "queued" });
    const body = { repo_url: "https://github.com/octocat/Hello-World", branch: "main" };
    const result = await api.createCodeScanFromRepo(body);
    expect(result.id).toBe("code-scan-1");
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("listCodeScanBranches() calls /api/code-scans/branches with the URL-encoded repo_url", async () => {
    globalThis.fetch = mockFetchOnce({ private: false, default_branch: "main", branches: ["main"] });
    const result = await api.listCodeScanBranches("https://github.com/octocat/Hello-World");
    expect(result.branches).toEqual(["main"]);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/code-scans/branches?repo_url=https%3A%2F%2Fgithub.com%2Foctocat%2FHello-World"),
      expect.anything(),
    );
  });

  it("listCodeScans() calls /api/code-scans", async () => {
    globalThis.fetch = mockFetchOnce([{ id: "code-scan-1" }]);
    const result = await api.listCodeScans();
    expect(result).toEqual([{ id: "code-scan-1" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/code-scans"), expect.anything());
  });

  it("getCodeScan() calls /api/code-scans/:id", async () => {
    globalThis.fetch = mockFetchOnce({ id: "code-scan-1" });
    await api.getCodeScan("code-scan-1");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/code-scans/code-scan-1"),
      expect.anything(),
    );
  });

  it("runCodeScanDast() POSTs to /api/code-scans/:id/dast with the body serialized", async () => {
    globalThis.fetch = mockFetchOnce({ id: "code-scan-1", dast_status: "running" });
    const result = await api.runCodeScanDast("code-scan-1", { target_url: "https://staging.example" });
    expect(result.dast_status).toBe("running");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain("/api/code-scans/code-scan-1/dast");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ target_url: "https://staging.example" });
  });

  it("codeScanReportUrl() returns an absolute URL for the given format", () => {
    expect(api.codeScanReportUrl("code-scan-1", "sarif")).toContain("/api/code-scans/code-scan-1/report.sarif");
  });

  it("githubOAuthStatus() calls /api/github/oauth/status", async () => {
    globalThis.fetch = mockFetchOnce({ connected: true, configured: true });
    const result = await api.githubOAuthStatus();
    expect(result.connected).toBe(true);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/github/oauth/status"),
      expect.anything(),
    );
  });

  it("githubOAuthLoginUrl() returns an absolute URL to the login redirect", () => {
    expect(api.githubOAuthLoginUrl()).toContain("/api/github/oauth/login");
  });

  it("githubOAuthLogout() POSTs to /api/github/oauth/logout with credentials included", async () => {
    globalThis.fetch = mockFetchOnce({});
    await api.githubOAuthLogout();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain("/api/github/oauth/logout");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("include");
  });

  it("githubOAuthLogout() throws the server detail on failure", async () => {
    globalThis.fetch = mockFetchOnce({ detail: "no active session" }, { ok: false, status: 400 });
    await expect(api.githubOAuthLogout()).rejects.toThrow("no active session");
  });

  it("createRegistryScan() POSTs to /api/registry-scans with the body serialized", async () => {
    globalThis.fetch = mockFetchOnce({ id: "scan-1", status: "queued" });
    const body = { image_ref: "alpine:3.18", username: null, password: null, registry_token: null, insecure: false };
    const result = await api.createRegistryScan(body);
    expect(result.id).toBe("scan-1");
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("listRegistryScans() calls /api/registry-scans", async () => {
    globalThis.fetch = mockFetchOnce([{ id: "scan-1" }]);
    const result = await api.listRegistryScans();
    expect(result).toEqual([{ id: "scan-1" }]);
    expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringContaining("/api/registry-scans"), expect.anything());
  });

  it("getRegistryScan() calls /api/registry-scans/:id", async () => {
    globalThis.fetch = mockFetchOnce({ id: "scan-1" });
    await api.getRegistryScan("scan-1");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/registry-scans/scan-1"),
      expect.anything(),
    );
  });

  it("registryScanReportUrl() returns an absolute URL for the given format", () => {
    expect(api.registryScanReportUrl("scan-1", "sarif")).toContain("/api/registry-scans/scan-1/report.sarif");
  });
});
