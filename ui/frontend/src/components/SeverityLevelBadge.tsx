import type { Severity } from "../types";

const CLASS_MAP: Record<Severity, string> = {
  critical: "critical",
  high: "danger",
  medium: "warning",
  low: "info",
  info: "info",
};

export default function SeverityLevelBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${CLASS_MAP[severity] ?? "info"}`}>{severity}</span>;
}
