import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import DynamicField from "./DynamicField";
import type { FieldMeta } from "../types";

describe("DynamicField", () => {
  it("renders a bool field as a checkbox and reports changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const field: FieldMeta = { name: "debug", label: "Debug", type: "bool" };
    render(<DynamicField field={field} value={false} onChange={onChange} />);
    const checkbox = screen.getByLabelText("Debug");
    await user.click(checkbox);
    expect(onChange).toHaveBeenCalledWith("debug", true);
  });

  it("renders a multi field with TagInput and reports changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const field: FieldMeta = { name: "regions", label: "Regions", type: "multi", help: "pick some" };
    render(<DynamicField field={field} value={["us-east-1"]} onChange={onChange} />);
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
    expect(screen.getByText("pick some")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox"), "us-west-2{Enter}");
    expect(onChange).toHaveBeenCalledWith("regions", ["us-east-1", "us-west-2"]);
  });

  it("renders a multi field with an empty array when value is not an array", () => {
    const field: FieldMeta = { name: "regions", label: "Regions", type: "multi" };
    render(<DynamicField field={field} value={undefined} onChange={vi.fn()} />);
    expect(screen.getByRole("textbox")).toHaveValue("");
  });

  it("renders a select field with options and reports changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const field: FieldMeta = {
      name: "kubernetes_cluster_provider",
      label: "Cluster provider",
      type: "select",
      options: ["", "aks", "eks", "gke"],
      help: "pick a managed provider",
    };
    render(<DynamicField field={field} value="" onChange={onChange} />);
    expect(screen.getByText("— none —")).toBeInTheDocument();
    expect(screen.getByText("pick a managed provider")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Cluster provider"), "eks");
    expect(onChange).toHaveBeenCalledWith("kubernetes_cluster_provider", "eks");
  });

  it("renders a select field with no value and no options without crashing", () => {
    const field: FieldMeta = { name: "kubernetes_cluster_provider", label: "Cluster provider", type: "select" };
    render(<DynamicField field={field} value={undefined} onChange={vi.fn()} />);
    const select = screen.getByLabelText("Cluster provider") as HTMLSelectElement;
    expect(select.value).toBe("");
    expect(select.options).toHaveLength(0);
  });

  it("renders a text field and reports changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const field: FieldMeta = { name: "profile", label: "Profile name", type: "text", required: true };
    render(<DynamicField field={field} value="" onChange={onChange} />);
    expect(screen.getByText("Profile name *")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Profile name *"), "a");
    expect(onChange).toHaveBeenCalledWith("profile", "a");
  });

  it("renders a password field with type=password", () => {
    const field: FieldMeta = { name: "token", label: "Token", type: "password" };
    render(<DynamicField field={field} value="" onChange={vi.fn()} />);
    const input = screen.getByLabelText("Token");
    expect(input).toHaveAttribute("type", "password");
  });

  it("renders text field help text when provided", () => {
    const field: FieldMeta = { name: "profile", label: "Profile", type: "text", help: "e.g. audit" };
    render(<DynamicField field={field} value="" onChange={vi.fn()} />);
    expect(screen.getByText("e.g. audit")).toBeInTheDocument();
  });
});
