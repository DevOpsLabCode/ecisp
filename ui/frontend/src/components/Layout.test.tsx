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
    expect(screen.getByRole("link", { name: "CSPM Findings" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Bulk Account Import" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Import Jobs" })).toBeInTheDocument();
    expect(screen.getByText("page content")).toBeInTheDocument();
  });

  it("marks the New CSPM Scan link active on the root route", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New CSPM Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "CSPM Findings" })).not.toHaveClass("active");
  });

  it("marks the CSPM Findings link active on /jobs", () => {
    render(
      <MemoryRouter initialEntries={["/jobs"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "CSPM Findings" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "New CSPM Scan" })).not.toHaveClass("active");
  });

  it("marks the Bulk Account Import link active on /bulk-import", () => {
    render(
      <MemoryRouter initialEntries={["/bulk-import"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Bulk Account Import" })).toHaveClass("active");
  });

  it("marks the Import Jobs link active on /batches", () => {
    render(
      <MemoryRouter initialEntries={["/batches"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Import Jobs" })).toHaveClass("active");
  });

  it("renders the GitHub org security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New GitHub Org Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "GitHub Org Findings" })).toBeInTheDocument();
  });

  it("marks the New GitHub Org Scan link active on /org-scans/new", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans/new"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New GitHub Org Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "GitHub Org Findings" })).not.toHaveClass("active");
  });

  it("marks the GitHub Org Findings link active on /org-scans", () => {
    render(
      <MemoryRouter initialEntries={["/org-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "GitHub Org Findings" })).toHaveClass("active");
  });

  it("renders the code security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Code Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Code Security Findings" })).toBeInTheDocument();
  });

  it("marks the New Code Scan link active on /code-scan", () => {
    render(
      <MemoryRouter initialEntries={["/code-scan"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Code Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Code Security Findings" })).not.toHaveClass("active");
  });

  it("marks the Code Security Findings link active on /code-scans", () => {
    render(
      <MemoryRouter initialEntries={["/code-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Code Security Findings" })).toHaveClass("active");
  });

  it("renders the container security nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Container Image Scan" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Container Image Findings" })).toBeInTheDocument();
  });

  it("marks the New Container Image Scan link active on /registry-scan", () => {
    render(
      <MemoryRouter initialEntries={["/registry-scan"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "New Container Image Scan" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Container Image Findings" })).not.toHaveClass("active");
  });

  it("marks the Container Image Findings link active on /registry-scans", () => {
    render(
      <MemoryRouter initialEntries={["/registry-scans"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Container Image Findings" })).toHaveClass("active");
  });

  it("renders the runtime protection nav links", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Install Golem Defender" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Protected Clusters" })).toBeInTheDocument();
  });

  it("marks the Protected Clusters link active on /runtime-clusters", () => {
    render(
      <MemoryRouter initialEntries={["/runtime-clusters"]}>
        <Layout>content</Layout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Protected Clusters" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Install Golem Defender" })).not.toHaveClass("active");
  });
});
