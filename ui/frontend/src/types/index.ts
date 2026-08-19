export type FieldType = "text" | "password" | "bool" | "multi" | "select";

export interface FieldMeta {
  name: string;
  label: string;
  type: FieldType;
  required?: boolean;
  help?: string;
  options?: string[];
}

export interface AuthMethodMeta {
  label: string;
  fields: FieldMeta[];
}

export interface ProviderMeta {
  code: string;
  label: string;
  authMethods: Record<string, AuthMethodMeta>;
  scopeFields: FieldMeta[];
}

export type JobStatus = "queued" | "running" | "completed" | "failed";

export interface JobSummary {
  id: string;
  provider: string;
  report_name: string;
  status: JobStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  error: string | null;
}

export interface JobDetail extends JobSummary {
  request: Record<string, unknown>;
  log: string;
}

export interface ScanCreateRequest {
  provider: string;
  auth_method: string;
  auth: Record<string, unknown>;
  scope: Record<string, unknown>;
  report_name?: string;
  services: string[];
  skipped_services: string[];
  ruleset: string;
  max_workers: number;
  max_rate?: number | null;
  debug: boolean;
}

export type FindingLevel = "danger" | "warning" | "success" | string;

export interface Finding {
  description?: string;
  rationale?: string;
  remediation?: string;
  level: FindingLevel;
  items?: string[];
  flagged_items?: number;
  checked_items?: number;
  service?: string;
  category?: string;
  path?: string;
  references?: string[];
  compliance?: unknown;
  [key: string]: unknown;
}

export interface ServiceData {
  findings?: Record<string, Finding>;
  [key: string]: unknown;
}

export interface ScanResults {
  provider_code?: string;
  provider_name?: string;
  account_id?: string;
  environment?: string;
  last_run?: Record<string, unknown>;
  service_list?: string[];
  services?: Record<string, ServiceData>;
  [key: string]: unknown;
}
