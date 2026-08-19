import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import FindingsView from "./FindingsView";
import type { ScanResults } from "../types";

const sampleResults: ScanResults = {
  provider_code: "aws",
  service_list: ["iam", "s3"],
  services: {
    iam: {
      findings: {
        "iam-no-mfa": {
          description: "IAM users without MFA",
          rationale: "MFA reduces credential-compromise risk.",
          remediation: "Enable MFA for every console user.",
          level: "danger",
          items: ["iam.users.alice", "iam.users.bob"],
          flagged_items: 2,
          checked_items: 10,
        },
        "iam-root-mfa-ok": {
          description: "Root account has MFA enabled",
          level: "good",
          items: [],
          flagged_items: 0,
          checked_items: 1,
        },
      },
    },
    s3: {
      findings: {
        "s3-weak-policy": {
          description: "S3 bucket policy allows wildcard principal",
          level: "info",
          items: ["s3.buckets.a"],
          flagged_items: 1,
          checked_items: 3,
        },
      },
    },
  },
};

describe("FindingsView", () => {
  it("shows stat tile counts, bucketing unrecognized levels under warning", () => {
    render(<FindingsView results={sampleResults} />);
    // danger: 1 (iam-no-mfa), warning: 1 (s3-weak-policy, level="info" falls back to warning bucket), good: 0 flagged
    const tiles = screen.getAllByText(/Danger findings|Warning findings|Good-practice findings/);
    expect(tiles).toHaveLength(3);
    expect(screen.getByText("Danger findings").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Warning findings").previousSibling).toHaveTextContent("1");
    expect(screen.getByText("Good-practice findings").previousSibling).toHaveTextContent("0");
  });

  it("excludes findings with zero flagged items from the table by default", () => {
    render(<FindingsView results={sampleResults} />);
    expect(screen.queryByText("Root account has MFA enabled")).not.toBeInTheDocument();
  });

  it("shows danger and warning findings by default, sorted by severity", () => {
    render(<FindingsView results={sampleResults} />);
    const rows = screen.getAllByRole("row").slice(1); // drop header row
    expect(within(rows[0]).getByText("IAM users without MFA")).toBeInTheDocument();
    expect(within(rows[1]).getByText("S3 bucket policy allows wildcard principal")).toBeInTheDocument();
  });

  it("breaks ties within the same severity by flagged item count, descending", () => {
    const results: ScanResults = {
      services: {
        iam: {
          findings: {
            "few-flagged": { description: "Few flagged", level: "danger", items: ["a"], flagged_items: 1 },
            "many-flagged": {
              description: "Many flagged",
              level: "danger",
              items: ["a", "b", "c"],
              flagged_items: 3,
            },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("Many flagged")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Few flagged")).toBeInTheDocument();
  });

  it("toggling off the danger filter hides danger findings", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    await user.click(screen.getByRole("button", { name: "danger" }));
    expect(screen.queryByText("IAM users without MFA")).not.toBeInTheDocument();
    expect(screen.getByText("S3 bucket policy allows wildcard principal")).toBeInTheDocument();
  });

  it("toggling on the good filter reveals good-practice findings with flagged items", async () => {
    const user = userEvent.setup();
    const results: ScanResults = {
      services: {
        iam: {
          findings: {
            "some-good-finding": {
              description: "Everything looks fine here",
              level: "good",
              items: ["a"],
              flagged_items: 1,
            },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    expect(screen.queryByText("Everything looks fine here")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "good" }));
    expect(screen.getByText("Everything looks fine here")).toBeInTheDocument();
  });

  it("filters by service", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    await user.selectOptions(screen.getByRole("combobox"), "iam");
    expect(screen.getByText("IAM users without MFA")).toBeInTheDocument();
    expect(screen.queryByText("S3 bucket policy allows wildcard principal")).not.toBeInTheDocument();
  });

  it("filters by search text against description and id", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    await user.type(screen.getByPlaceholderText("Search findings…"), "wildcard");
    expect(screen.queryByText("IAM users without MFA")).not.toBeInTheDocument();
    expect(screen.getByText("S3 bucket policy allows wildcard principal")).toBeInTheDocument();
  });

  it("shows an empty state when no findings match the filters", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    await user.type(screen.getByPlaceholderText("Search findings…"), "nothing matches this");
    expect(screen.getByText("No findings match the current filters.")).toBeInTheDocument();
  });

  it("expands a row on click to show rationale, remediation, and affected resources", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    await user.click(screen.getByText("IAM users without MFA"));
    expect(screen.getByText("MFA reduces credential-compromise risk.")).toBeInTheDocument();
    expect(screen.getByText("Enable MFA for every console user.")).toBeInTheDocument();
    expect(screen.getByText("iam.users.alice")).toBeInTheDocument();
    expect(screen.getByText("iam.users.bob")).toBeInTheDocument();
  });

  it("collapses an expanded row on a second click", async () => {
    const user = userEvent.setup();
    render(<FindingsView results={sampleResults} />);
    const row = screen.getByText("IAM users without MFA");
    await user.click(row);
    expect(screen.getByText("iam.users.alice")).toBeInTheDocument();
    await user.click(row);
    expect(screen.queryByText("iam.users.alice")).not.toBeInTheDocument();
  });

  it("truncates a long affected-resources list and shows a remainder count", async () => {
    const user = userEvent.setup();
    const manyItems = Array.from({ length: 60 }, (_, i) => `resource-${i}`);
    const results: ScanResults = {
      services: {
        ec2: {
          findings: {
            "many-findings": {
              description: "Lots of resources",
              level: "danger",
              items: manyItems,
              flagged_items: 60,
            },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    await user.click(screen.getByText("Lots of resources"));
    expect(screen.getByText("Affected resources (60)")).toBeInTheDocument();
    expect(screen.getByText("resource-0")).toBeInTheDocument();
    expect(screen.getByText("resource-49")).toBeInTheDocument();
    expect(screen.queryByText("resource-50")).not.toBeInTheDocument();
    expect(screen.getByText("…and 10 more")).toBeInTheDocument();
  });

  it("treats a finding with neither flagged_items nor items as zero flagged, excluding it", () => {
    const results: ScanResults = {
      services: {
        ec2: {
          findings: {
            "bare-finding": { description: "Nothing counted", level: "danger" },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    expect(screen.queryByText("Nothing counted")).not.toBeInTheDocument();
    expect(screen.getByText("Danger findings").previousSibling).toHaveTextContent("0");
  });

  it("matches search against a finding whose description is empty", async () => {
    const user = userEvent.setup();
    const results: ScanResults = {
      services: {
        ec2: {
          findings: {
            "no-description-finding": { level: "danger", items: ["x"], flagged_items: 1 },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    await user.type(screen.getByPlaceholderText("Search findings…"), "no-description-finding");
    expect(screen.getByText("no-description-finding")).toBeInTheDocument();
  });

  it("falls back to the finding id as flagged count and service list length when data is sparse", () => {
    const results: ScanResults = {
      services: {
        ec2: {
          findings: {
            "sparse-finding": {
              description: "",
              level: "danger",
              items: ["only-one"],
            },
          },
        },
      },
    };
    render(<FindingsView results={results} />);
    // no description -> falls back to rendering the finding id
    expect(screen.getByText("sparse-finding")).toBeInTheDocument();
    // "Services scanned" falls back to derived service list since service_list is absent
    expect(screen.getByText("Services scanned")).toBeInTheDocument();
  });
});
