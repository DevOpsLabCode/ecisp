import type {
  BatchDetail,
  BatchSummary,
  CodeScanDetail,
  CodeScanFromRepoRequest,
  CodeScanSummary,
  DastRequest,
  GitHubOAuthStatus,
  JobDetail,
  JobSummary,
  OrgScanCreateRequest,
  OrgScanDetail,
  OrgScanSummary,
  ProviderMeta,
  RegistryScanCreateRequest,
  RegistryScanDetail,
  RegistryScanSummary,
  RepoBranchesResponse,
  RuntimeClusterCreateRequest,
  RuntimeClusterDetail,
  RuntimeClusterSummary,
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
    // Needed so the browser sends/reads the GitHub OAuth session cookie --
    // this API is on a different origin (port) than the frontend in dev
    // and in docker-compose alike. Harmless for endpoints that don't care.
    credentials: "include",
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

  createOrgScan: (body: OrgScanCreateRequest) =>
    request<OrgScanSummary>("/api/org-scans", { method: "POST", body: JSON.stringify(body) }),
  listOrgScans: () => request<OrgScanSummary[]>("/api/org-scans"),
  getOrgScan: (id: string) => request<OrgScanDetail>(`/api/org-scans/${id}`),
  orgScanReportUrl: (id: string, fmt: "sarif" | "json" | "csv" | "html" | "pdf") =>
    `${BASE_URL}/api/org-scans/${id}/report.${fmt}`,

  uploadCodeScan: async (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    // No content-type header here deliberately, same reason as createBatch
    // above: the browser must set its own multipart boundary.
    const res = await fetch(`${BASE_URL}/api/code-scans/upload`, {
      method: "POST",
      body: formData,
      credentials: "include",
    });
    await handleErrors(res);
    return res.json() as Promise<CodeScanSummary>;
  },
  createCodeScanFromRepo: (body: CodeScanFromRepoRequest) =>
    request<CodeScanSummary>("/api/code-scans/repo", { method: "POST", body: JSON.stringify(body) }),
  listCodeScanBranches: (repoUrl: string) =>
    request<RepoBranchesResponse>(`/api/code-scans/branches?repo_url=${encodeURIComponent(repoUrl)}`),
  listCodeScans: () => request<CodeScanSummary[]>("/api/code-scans"),
  getCodeScan: (id: string) => request<CodeScanDetail>(`/api/code-scans/${id}`),
  runCodeScanDast: (id: string, body: DastRequest) =>
    request<CodeScanSummary>(`/api/code-scans/${id}/dast`, { method: "POST", body: JSON.stringify(body) }),
  codeScanReportUrl: (id: string, fmt: "sarif" | "json" | "csv" | "html" | "pdf") =>
    `${BASE_URL}/api/code-scans/${id}/report.${fmt}`,

  githubOAuthStatus: () => request<GitHubOAuthStatus>("/api/github/oauth/status"),
  githubOAuthLoginUrl: () => `${BASE_URL}/api/github/oauth/login`,
  githubOAuthLogout: () =>
    fetch(`${BASE_URL}/api/github/oauth/logout`, { method: "POST", credentials: "include" }).then(handleErrors),

  createRegistryScan: (body: RegistryScanCreateRequest) =>
    request<RegistryScanSummary>("/api/registry-scans", { method: "POST", body: JSON.stringify(body) }),
  listRegistryScans: () => request<RegistryScanSummary[]>("/api/registry-scans"),
  getRegistryScan: (id: string) => request<RegistryScanDetail>(`/api/registry-scans/${id}`),
  registryScanReportUrl: (id: string, fmt: "sarif" | "json" | "csv" | "html" | "pdf") =>
    `${BASE_URL}/api/registry-scans/${id}/report.${fmt}`,

  createRuntimeCluster: (body: RuntimeClusterCreateRequest) =>
    request<RuntimeClusterDetail>("/api/runtime-clusters", { method: "POST", body: JSON.stringify(body) }),
  listRuntimeClusters: () => request<RuntimeClusterSummary[]>("/api/runtime-clusters"),
  getRuntimeCluster: (id: string) => request<RuntimeClusterDetail>(`/api/runtime-clusters/${id}`),
  runtimeClusterInstallScriptUrl: (id: string) => `${BASE_URL}/api/runtime-clusters/${id}/install.sh`,
  runtimeClusterReportUrl: (id: string, fmt: "sarif" | "json" | "csv" | "html" | "pdf") =>
    `${BASE_URL}/api/runtime-clusters/${id}/report.${fmt}`,
};
