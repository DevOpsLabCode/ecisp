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
