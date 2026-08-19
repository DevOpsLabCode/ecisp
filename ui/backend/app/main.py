import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import engine_runner
from .jobs import REPORT_DIR, manager
from .providers_meta import list_providers
from .schemas import JobDetail, JobSummary, ScanCreateRequest

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
