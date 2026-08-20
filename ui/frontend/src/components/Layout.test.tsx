import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import Layout from "./Layout";

describe("Layout", () => {
  it("renders the brand, nav links, and children", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>
          <p>page content</p>
        </Layout>
      </MemoryRouter>,
    );
    expect(screen.getByText("ecisp")).toBeInTheDocument();
    expect(screen.getByText("Enterprise Cloud Discovery")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scan history" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import accounts" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import history" })).toBeInTheDocument();
    expect(screen.getByText("page content")).toBeInTheDocument();
  });

  it("marks the New scan link active on the root route", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Scan history" })).not.toHaveClass("active");
  });

  it("marks the Scan history link active on /jobs", () => {
    render(
      <MemoryRouter initialEntries={["/jobs"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Scan history" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "New scan" })).not.toHaveClass("active");
  });

  it("marks the Import accounts link active on /bulk-import", () => {
    render(
      <MemoryRouter initialEntries={["/bulk-import"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Import accounts" })).toHaveClass("active");
  });

  it("marks the Import history link active on /batches", () => {
    render(
      <MemoryRouter initialEntries={["/batches"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Import history" })).toHaveClass("active");
  });

  it("renders the org security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New org scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Org scan history" })).toBeInTheDocument();
  });

  it("marks the New org scan link active on /org-scans/new", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans/new"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New org scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Org scan history" })).not.toHaveClass("active");
  });

  it("marks the Org scan history link active on /org-scans", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Org scan history" })).toHaveClass("active");
  });
});
