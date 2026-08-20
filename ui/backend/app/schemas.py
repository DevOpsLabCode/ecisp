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
