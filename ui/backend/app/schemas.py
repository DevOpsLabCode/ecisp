from typing import Any

from pydantic import BaseModel, Field


class ScanCreateRequest(BaseModel):
    provider: str
    auth_method: str
    auth: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)

    report_name: str | None = None
    services: list[str] = Field(default_factory=list)
    skipped_services: list[str] = Field(default_factory=list)
    ruleset: str = "default.json"
    max_workers: int = 10
    max_rate: int | None = None
    debug: bool = False


class JobSummary(BaseModel):
    id: str
    provider: str
    report_name: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    error: str | None = None


class JobDetail(JobSummary):
    request: dict[str, Any]
    log: str


class RowError(BaseModel):
    row_number: int
    message: str


class BatchSummary(BaseModel):
    id: str
    filename: str
    created_at: str
    queued_jobs: int
    skipped_rows: int
    status_counts: dict[str, int]


class BatchDetail(BatchSummary):
    jobs: list[JobSummary]
    errors: list[RowError]


class OrgScanCreateRequest(BaseModel):
    org: str
    github_token: str
    notify_email: str | None = None
    create_issues: bool = True
    max_workers: int = 4
    include_archived: bool = False


class OrgScanSummary(BaseModel):
    id: str
    org: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    total_repos: int
    completed_repos: int
    repos_with_findings: int
    severity_totals: dict[str, int]
    issues_created: int
    email_sent: bool


class IssueOutcome(BaseModel):
    action: str
    issue_url: str | None = None
    error: str | None = None


class RepoScanSummary(BaseModel):
    repository: str
    technologies: list[str]
    scanners_run: list[str]
    scanners_skipped: dict[str, str]
    severity_counts: dict[str, int]
    finding_count: int
    error: str | None = None
    issue: IssueOutcome | None = None


class OrgScanDetail(OrgScanSummary):
    repositories: list[RepoScanSummary]


class CodeScanFromRepoRequest(BaseModel):
    repo_url: str
    branch: str | None = None


class DastRequest(BaseModel):
    target_url: str
    spider_minutes: int = 2
    active_scan_minutes: int = 5


class CodeScanSummary(BaseModel):
    id: str
    source_type: str
    source_label: str
    branch: str | None = None
    commit_sha: str | None = None
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    severity_counts: dict[str, int] | None = None
    finding_count: int | None = None
    dast_status: str
    dast_target_url: str | None = None
    dast_error: str | None = None


class FindingOut(BaseModel):
    repository: str
    file: str
    line: int | None = None
    scanner: str
    rule_id: str
    severity: str
    category: str
    message: str
    remediation: str | None = None
    fingerprint: str


class CodeScanDetail(CodeScanSummary):
    technologies: list[str]
    scanners_run: list[str]
    scanners_skipped: dict[str, str]
    findings: list[FindingOut]


class RegistryScanCreateRequest(BaseModel):
    image_ref: str
    username: str | None = None
    password: str | None = None
    registry_token: str | None = None
    insecure: bool = False


class RegistryScanSummary(BaseModel):
    id: str
    image_ref: str
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    severity_counts: dict[str, int] | None = None
    finding_count: int | None = None


class RegistryScanDetail(RegistryScanSummary):
    scanners_run: list[str]
    findings: list[FindingOut]


class RuntimeClusterCreateRequest(BaseModel):
    name: str


class RuntimeClusterSummary(BaseModel):
    id: str
    name: str
    created_at: str
    last_event_at: str | None = None
    severity_counts: dict[str, int]
    finding_count: int


class RuntimeClusterDetail(RuntimeClusterSummary):
    install_token: str
    findings: list[FindingOut]


class ResponseRuleUpsertRequest(BaseModel):
    rule_id: str
    action: str
    enabled: bool = True


class ResponseRuleOut(BaseModel):
    rule_id: str
    action: str
    enabled: bool
    created_at: str
    updated_at: str


class ResponseCommandOut(BaseModel):
    id: str
    cluster_id: str
    namespace: str
    pod_name: str
    action: str
    status: str
    attempts: int
    resolved_role_arn: str | None = None
    created_at: str
    updated_at: str


class ResolveIamRoleRequest(BaseModel):
    role_arn: str


class CommandStatusUpdateRequest(BaseModel):
    status: str


class ClusterCoverageOut(BaseModel):
    cluster_id: str
    responder_last_seen_at: str | None = None
    network_policy_enforcement: str
    network_policy_checked_at: str | None = None
    updated_at: str


class NetworkPolicyCoverageReportRequest(BaseModel):
    status: str
