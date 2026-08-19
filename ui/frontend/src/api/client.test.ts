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
});
