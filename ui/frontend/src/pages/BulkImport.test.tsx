import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { BatchSummary } from "../types";
import BulkImport from "./BulkImport";

vi.mock("../api/client", () => ({
  api: {
    createBatch: vi.fn(),
    batchTemplateUrl: vi.fn(() => "http://localhost:8000/api/batches/template.csv"),
  },
}));

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <BulkImport />
    </MemoryRouter>,
  );
}

describe("BulkImport", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a template download link", () => {
    renderPage();
    const link = screen.getByRole("link", { name: /Download a CSV template/ });
    expect(link).toHaveAttribute("href", "http://localhost:8000/api/batches/template.csv");
  });

  it("disables the import button until a file is chosen", () => {
    renderPage();
    expect(screen.getByRole("button", { name: "Import and queue scans" })).toBeDisabled();
  });

  it("clearing the file selection resets to no file chosen", () => {
    renderPage();
    const input = screen.getByLabelText("Choose file") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [] } });
    expect(screen.getByRole("button", { name: "Import and queue scans" })).toBeDisabled();
  });

  it("enables the import button and shows the filename once a file is chosen", async () => {
    const user = userEvent.setup();
    renderPage();
    const file = new File(["provider,auth_method\naws,profile\n"], "accounts.csv", { type: "text/csv" });
    const input = screen.getByLabelText("Choose file") as HTMLInputElement;
    await user.upload(input, file);
    expect(screen.getByText(/accounts\.csv/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import and queue scans" })).toBeEnabled();
  });

  it("uploads the file and navigates to the batch detail page", async () => {
    const user = userEvent.setup();
    const summary: BatchSummary = {
      id: "batch-1",
      filename: "accounts.csv",
      created_at: "2026-01-01T00:00:00Z",
      queued_jobs: 2,
      skipped_rows: 0,
      status_counts: { queued: 2, running: 0, completed: 0, failed: 0 },
    };
    vi.mocked(api.createBatch).mockResolvedValue(summary);

    renderPage();
    const file = new File(["provider,auth_method\naws,profile\n"], "accounts.csv", { type: "text/csv" });
    const input = screen.getByLabelText("Choose file") as HTMLInputElement;
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: "Import and queue scans" }));

    expect(api.createBatch).toHaveBeenCalledWith(file);
    expect(navigateMock).toHaveBeenCalledWith("/batches/batch-1");
  });

  it("shows an error banner when the upload fails", async () => {
    const user = userEvent.setup();
    // A row-validation failure surfaced by the backend, not a client-side
    // extension mismatch -- userEvent.upload() respects the input's
    // `accept` attribute, so the file here still needs a matching extension
    // or it's silently never attached.
    vi.mocked(api.createBatch).mockRejectedValue(new Error("Could not parse accounts.csv: bad rows"));

    renderPage();
    const file = new File(["not,valid,csv"], "accounts.csv", { type: "text/csv" });
    const input = screen.getByLabelText("Choose file") as HTMLInputElement;
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: "Import and queue scans" }));

    expect(await screen.findByText("Could not parse accounts.csv: bad rows")).toBeInTheDocument();
  });

  it("stringifies a non-Error rejection in the error banner", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createBatch).mockRejectedValue("network exploded");

    renderPage();
    const file = new File(["provider,auth_method\naws,profile\n"], "accounts.csv", { type: "text/csv" });
    const input = screen.getByLabelText("Choose file") as HTMLInputElement;
    await user.upload(input, file);
    await user.click(screen.getByRole("button", { name: "Import and queue scans" }));

    expect(await screen.findByText("network exploded")).toBeInTheDocument();
  });
});
