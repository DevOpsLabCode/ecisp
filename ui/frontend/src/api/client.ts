import type {
  JobDetail,
  JobSummary,
  ProviderMeta,
  ScanCreateRequest,
  ScanResults,
} from "../types";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; engine_available: boolean; engine_error: string | null }>("/api/health"),
  providers: () => request<ProviderMeta[]>("/api/providers"),
  createScan: (body: ScanCreateRequest) =>
    request<JobSummary>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  listScans: () => request<JobSummary[]>("/api/scans"),
  getScan: (id: string) => request<JobDetail>(`/api/scans/${id}`),
  getScanResults: (id: string) => request<ScanResults>(`/api/scans/${id}/results`),
};
