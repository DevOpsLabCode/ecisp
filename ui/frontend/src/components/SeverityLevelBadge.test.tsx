import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Severity } from "../types";
import SeverityLevelBadge from "./SeverityLevelBadge";

describe("SeverityLevelBadge", () => {
  it.each([
    ["critical", "critical"],
    ["high", "danger"],
    ["medium", "warning"],
    ["low", "info"],
    ["info", "info"],
  ] as const)("renders %s with the %s badge class", (severity, cls) => {
    render(<SeverityLevelBadge severity={severity} />);
    expect(screen.getByText(severity)).toHaveClass(`badge ${cls}`);
  });

  it("falls back to the info class for an unrecognized severity", () => {
    render(<SeverityLevelBadge severity={"unknown" as unknown as Severity} />);
    expect(screen.getByText("unknown")).toHaveClass("badge info");
  });
});
