import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./api/client";
import App from "./App";

vi.mock("./api/client", () => ({
  api: {
    providers: vi.fn().mockResolvedValue([]),
    health: vi.fn().mockResolvedValue({ status: "ok", engine_available: true, engine_error: null }),
    listScans: vi.fn().mockResolvedValue([]),
    getScan: vi.fn(),
    getScanResults: vi.fn(),
    createScan: vi.fn(),
  },
}));

describe("App", () => {
  const originalLocation = window.location.href;

  beforeEach(() => {
    window.history.pushState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
    window.history.pushState({}, "", originalLocation);
  });

  it("renders the New scan page at the root route", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "New CSPM Scan" })).toBeInTheDocument();
    expect(api.providers).toHaveBeenCalled();
  });

  it("renders the Jobs page at /jobs", async () => {
    window.history.pushState({}, "", "/jobs");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "CSPM Findings" })).toBeInTheDocument();
    expect(api.listScans).toHaveBeenCalled();
  });
});
