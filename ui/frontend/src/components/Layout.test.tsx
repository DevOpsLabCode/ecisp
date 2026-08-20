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
    expect(screen.getByText("Golem")).toBeInTheDocument();
    expect(screen.getByText("Built to defend what you build")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "New CSPM Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Scan history" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import Cloud Accounts" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Cloud Import History" })).toBeInTheDocument();
    expect(screen.getByText("page content")).toBeInTheDocument();
  });

  it("marks the New CSPM Scan link active on the root route", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New CSPM Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Scan history" })).not.toHaveClass("active");
  });

  it("marks the Scan history link active on /jobs", () => {
    render(
      <MemoryRouter initialEntries={["/jobs"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Scan history" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "New CSPM Scan" })).not.toHaveClass("active");
  });

  it("marks the Import Cloud Accounts link active on /bulk-import", () => {
    render(
      <MemoryRouter initialEntries={["/bulk-import"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Import Cloud Accounts" })).toHaveClass("active");
  });

  it("marks the Cloud Import History link active on /batches", () => {
    render(
      <MemoryRouter initialEntries={["/batches"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Cloud Import History" })).toHaveClass("active");
  });

  it("renders the org security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Scan GitHub Organization" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "GitHub Org Scan History" })).toBeInTheDocument();
  });

  it("marks the Scan GitHub Organization link active on /org-scans/new", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans/new"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Scan GitHub Organization" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "GitHub Org Scan History" })).not.toHaveClass("active");
  });

  it("marks the GitHub Org Scan History link active on /org-scans", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "GitHub Org Scan History" })).toHaveClass("active");
  });

  it("renders the code security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New code scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Code scan history" })).toBeInTheDocument();
  });

  it("marks the New code scan link active on /code-scan", () => {
    render(
      <MemoryRouter initialEntries={["/code-scan"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New code scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Code scan history" })).not.toHaveClass("active");
  });

  it("marks the Code scan history link active on /code-scans", () => {
    render(
      <MemoryRouter initialEntries={["/code-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Code scan history" })).toHaveClass("active");
  });

  it("renders the registry security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Artifact Registry Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Artifact Registry Scan History" })).toBeInTheDocument();
  });

  it("marks the New Artifact Registry Scan link active on /registry-scan", () => {
    render(
      <MemoryRouter initialEntries={["/registry-scan"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Artifact Registry Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Artifact Registry Scan History" })).not.toHaveClass("active");
  });

  it("marks the Artifact Registry Scan History link active on /registry-scans", () => {
    render(
      <MemoryRouter initialEntries={["/registry-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Artifact Registry Scan History" })).toHaveClass("active");
  });

  it("renders the runtime defender nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Install Golem Defender" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Kubernetes Clusters" })).toBeInTheDocument();
  });

  it("marks the Kubernetes Clusters link active on /runtime-clusters", () => {
    render(
      <MemoryRouter initialEntries={["/runtime-clusters"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Kubernetes Clusters" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Install Golem Defender" })).not.toHaveClass("active");
  });
});
