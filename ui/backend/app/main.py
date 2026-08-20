import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse

from . import engine_runner
from .batch_import import RowParseError, csv_template_text
from .batches import batch_manager
from .jobs import REPORT_DIR, manager
from .orgscan.github_client import GitHubAuthError, GitHubClient
from .orgscan.org_scan_job import manager as org_scan_manager
from .providers_meta import list_providers
from .schemas import (
    BatchDetail,
    BatchSummary,
    JobDetail,
    JobSummary,
    OrgScanCreateRequest,
    OrgScanDetail,
    OrgScanSummary,
    ScanCreateRequest,
)

app = FastAPI(
    title="ecisp-ui",
    description="Web UI for the Enterprise Cloud Discovery engine, a DevOps Lab product.",
    version="0.1.0",
    contact={"name": "Stan Zvenigorodskiy", "url": "https://devopslabinc.com"},
)

# Defaults cover the Vite dev server (`npm run dev`) and the default
# docker-compose port for the built frontend. Override with a comma-
# separated CORS_ORIGINS env var for any other deployment -- the frontend
# origin the browser actually uses must be listed exactly (scheme + host +
# port), or every request will fail CORS preflight with no server-side
# error to point at, same as it did before this was configurable.
DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080"


def parse_cors_origins(raw: str) -> list[str]:
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "engine_available": engine_runner.ENGINE_AVAILABLE,
        "engine_error": engine_runner.ENGINE_IMPORT_ERROR,
    }


@app.get("/api/providers")
def providers():
    return list_providers()


@app.post("/api/scans", response_model=JobSummary)
def create_scan(req: ScanCreateRequest):
    error = manager.validate(req)
    if error:
        raise HTTPException(status_code=400, detail=error)
    job = manager.create(req)
    return job.summary()


@app.get("/api/scans", response_model=list[JobSummary])
def list_scans():
    return [job.summary() for job in manager.list()]


@app.get("/api/scans/{job_id}", response_model=JobDetail)
def get_scan(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.detail()


@app.get("/api/scans/{job_id}/results")
def get_scan_results(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "completed":
        raise HTTPException(status_code=409, detail=f"Job is {job.status}, not completed")
    try:
        return engine_runner.load_results(job.report_name, REPORT_DIR)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load results: {exc}") from exc


# 5MB is generous for a few hundred rows of scan configuration even with
# every possible column populated; this just guards against unbounded
# upload abuse, not a realistic import size.
MAX_BATCH_UPLOAD_BYTES = 5 * 1024 * 1024


@app.get("/api/batches/template.csv")
def batch_template():
    # Must be registered before /api/batches/{batch_id} -- FastAPI matches
    # routes in declaration order, and {batch_id} would otherwise swallow
    # the literal "template.csv" path segment.
    return PlainTextResponse(
        csv_template_text(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ecisp-bulk-import-template.csv"},
    )


@app.post("/api/batches", response_model=BatchSummary)
async def create_batch(file: UploadFile = File(...)):  # noqa: B008 -- required FastAPI pattern, not a real mutable-default bug
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(data) > MAX_BATCH_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the 5MB limit")
    try:
        batch = batch_manager.create_from_file(file.filename or "upload", data)
    except RowParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse {file.filename!r}: {exc}") from exc
    return batch.summary()


@app.get("/api/batches", response_model=list[BatchSummary])
def list_batches():
    return [batch.summary() for batch in batch_manager.list()]


@app.get("/api/batches/{batch_id}", response_model=BatchDetail)
def get_batch(batch_id: str):
    batch = batch_manager.get(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return batch.detail()


# ---------------------------------------------------------------------
# Org-wide GitHub security scanning (SAST across every repo in an org)
# ---------------------------------------------------------------------
@app.post("/api/org-scans", response_model=OrgScanSummary)
def create_org_scan(req: OrgScanCreateRequest):
    # Verified synchronously (not left to the async worker) so a bad/expired
    # token fails the request immediately with a clear 400, instead of
    # silently failing a scan the user has already navigated away from.
    try:
        with GitHubClient(req.github_token) as gh:
            gh.verify()
    except GitHubAuthError as exc:
        # Constructing GitHubClient itself raises GitHubAuthError for a
        # blank token, not just verify() for a rejected one -- both need to
        # land here as a clean 400, not escape the `with` block as an
        # unhandled 500 (reproduced by POSTing an empty github_token).
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = org_scan_manager.create(
        org=req.org,
        token=req.github_token,
        notify_email=req.notify_email,
        create_issues=req.create_issues,
        max_workers=req.max_workers,
        include_archived=req.include_archived,
    )
    return scan.summary()


@app.get("/api/org-scans", response_model=list[OrgScanSummary])
def list_org_scans():
    return [scan.summary() for scan in org_scan_manager.list()]


@app.get("/api/org-scans/{scan_id}", response_model=OrgScanDetail)
def get_org_scan(scan_id: str):
    scan = org_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Org scan not found")
    return scan.detail()


_REPORT_MEDIA_TYPES = {
    "sarif": "application/sarif+json",
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "pdf": "application/pdf",
}
_REPORT_FILENAMES = {
    "sarif": "security-findings.sarif",
    "json": "security-findings.json",
    "csv": "security-findings.csv",
    "html": "security-report.html",
    "pdf": "security-report.pdf",
}


@app.get("/api/org-scans/{scan_id}/report.{fmt}")
def get_org_scan_report(scan_id: str, fmt: str):
    scan = org_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Org scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status}, not completed")
    if fmt not in _REPORT_FILENAMES:
        raise HTTPException(status_code=404, detail=f"Unknown report format '{fmt}'")

    path = scan._report_dir() / _REPORT_FILENAMES[fmt]
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{fmt} report not available for this scan")
    return FileResponse(path, media_type=_REPORT_MEDIA_TYPES[fmt], filename=_REPORT_FILENAMES[fmt])
