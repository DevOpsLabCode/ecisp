import type { JobStatus } from "../types";

export default function StatusBadge({ status }: { status: JobStatus }) {
  return <span className={`badge ${status}`}>{status}</span>;
}
