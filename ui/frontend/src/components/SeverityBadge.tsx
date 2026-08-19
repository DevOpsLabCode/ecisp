const LEVEL_MAP: Record<string, { label: string; cls: string }> = {
  danger: { label: "Danger", cls: "danger" },
  warning: { label: "Warning", cls: "warning" },
  good: { label: "Good", cls: "success" },
  success: { label: "Good", cls: "success" },
};

export default function SeverityBadge({ level }: { level: string }) {
  const meta = LEVEL_MAP[level] ?? { label: level || "info", cls: "info" };
  return <span className={`badge ${meta.cls}`}>{meta.label}</span>;
}
