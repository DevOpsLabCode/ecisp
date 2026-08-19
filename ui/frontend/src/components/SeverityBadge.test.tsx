import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import SeverityBadge from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("renders Danger for level=danger", () => {
    render(<SeverityBadge level="danger" />);
    expect(screen.getByText("Danger")).toHaveClass("badge", "danger");
  });

  it("renders Warning for level=warning", () => {
    render(<SeverityBadge level="warning" />);
    expect(screen.getByText("Warning")).toHaveClass("badge", "warning");
  });

  it("renders Good for level=good", () => {
    render(<SeverityBadge level="good" />);
    expect(screen.getByText("Good")).toHaveClass("badge", "success");
  });

  it("renders Good for level=success", () => {
    render(<SeverityBadge level="success" />);
    expect(screen.getByText("Good")).toHaveClass("badge", "success");
  });

  it("falls back to the raw level for unknown values", () => {
    render(<SeverityBadge level="mystery" />);
    expect(screen.getByText("mystery")).toHaveClass("badge", "info");
  });

  it("falls back to 'info' label for an empty level", () => {
    render(<SeverityBadge level="" />);
    expect(screen.getByText("info")).toHaveClass("badge", "info");
  });
});
