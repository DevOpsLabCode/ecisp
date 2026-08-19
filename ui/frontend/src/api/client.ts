import type {
  BatchDetail,
  BatchSummary,
  JobDetail,
  JobSummary,
  ProviderMeta,
  ScanCreateRequest,
  ScanResults,
} from "../types";

const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function handleErrors(res: Response): Promise<Response> {
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
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "content-type": "application/json" },
    ...init,
  });
  await handleErrors(res);
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

  createBatch: async (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    // No content-type header here deliberately: the browser must set its
    // own multipart boundary, which it can't do if we set the header.
    const res = await fetch(`${BASE_URL}/api/batches`, { method: "POST", body: formData });
    await handleErrors(res);
    return res.json() as Promise<BatchSummary>;
  },
  listBatches: () => request<BatchSummary[]>("/api/batches"),
  getBatch: (id: string) => request<BatchDetail>(`/api/batches/${id}`),
  batchTemplateUrl: () => `${BASE_URL}/api/batches/template.csv`,
};
