import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import StatusBadge from "./StatusBadge";
import type { JobStatus } from "../types";

describe("StatusBadge", () => {
  it.each<JobStatus>(["queued", "running", "completed", "failed"])("renders the %s status", (status) => {
    render(<StatusBadge status={status} />);
    const badge = screen.getByText(status);
    expect(badge).toHaveClass("badge", status);
  });
});
