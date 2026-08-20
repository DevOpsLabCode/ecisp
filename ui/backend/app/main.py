import os
import uuid

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, Response

from . import engine_runner
from .batch_import import RowParseError, csv_template_text
from .batches import batch_manager
from .codescan import github_oauth
from .codescan.code_scan_job import UPLOAD_DIR
from .codescan.code_scan_job import manager as code_scan_manager
from .codescan.github_oauth import OAuthError, OAuthNotConfigured
from .jobs import REPORT_DIR, manager
from .orgscan.github_client import GitHubAuthError, GitHubClient, parse_repo_url
from .orgscan.org_scan_job import manager as org_scan_manager
from .orgscan.reporting import csv_report, html_report, json_report
from .orgscan.reporting import sarif as sarif_report
from .providers_meta import list_providers
from .registryscan.registry_scan_job import manager as registry_scan_manager
from .runtimedefender.attack_simulation_script import build_simulation_script
from .runtimedefender.install_script import build_install_script
from .runtimedefender.runtime_defender import ClusterNotFound, InvalidInstallToken, MalformedFalcoAlert
from .runtimedefender.runtime_defender import manager as runtime_defender_manager
from .schemas import (
    BatchDetail,
    BatchSummary,
    CodeScanDetail,
    CodeScanFromRepoRequest,
    CodeScanSummary,
    DastRequest,
    JobDetail,
    JobSummary,
    OrgScanCreateRequest,
    OrgScanDetail,
    OrgScanSummary,
    RegistryScanCreateRequest,
    RegistryScanDetail,
    RegistryScanSummary,
    RuntimeClusterCreateRequest,
    RuntimeClusterDetail,
    RuntimeClusterSummary,
    ScanCreateRequest,
)

app = FastAPI(
    title="Golem",
    description="Golem -- built to defend what you build. A DevOps Lab Inc. product, "
    "on the Enterprise Cloud Discovery engine.",
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

# Where the OAuth callback sends the browser back to, and what redirect_uri
# this backend registers with GitHub -- both need to be reachable exactly
# as configured, matching the OAuth App's own "Authorization callback URL".
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:8080")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")


def parse_cors_origins(raw: str) -> list[str]:
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS)),
    allow_methods=["*"],
    allow_headers=["*"],
    # The code-scan frontend reads/sends the GitHub OAuth session cookie via
    # `fetch(..., credentials: "include")` from a different origin (port) than
    # this API -- without allow_credentials, the browser won't expose those
    # responses to JS regardless of the cookie itself being sent. Safe here
    # because allow_origins above is always an explicit whitelist, never "*".
    allow_credentials=True,
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
        headers={"Content-Disposition": "attachment; filename=golem-bulk-import-template.csv"},
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


# ---------------------------------------------------------------------
# GitHub OAuth ("Connect GitHub" for private repos in the code-scan flow)
# ---------------------------------------------------------------------
_OAUTH_CALLBACK_URL = f"{BACKEND_URL}/api/github/oauth/callback"


@app.get("/api/github/oauth/login")
def github_oauth_login():
    try:
        state = github_oauth.oauth_states.create("pending")
        url = github_oauth.build_authorize_url(_OAUTH_CALLBACK_URL, state)
    except OAuthNotConfigured as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return RedirectResponse(url)


@app.get("/api/github/oauth/callback")
def github_oauth_callback(code: str, state: str):
    if github_oauth.oauth_states.pop(state) is None:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    try:
        token = github_oauth.exchange_code(code, _OAUTH_CALLBACK_URL)
    except (OAuthNotConfigured, OAuthError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    session_id = github_oauth.oauth_sessions.create(token)
    # The redirect target is a plain "it worked" signal for the UI to pick
    # up (e.g. close a popup, flip a connected indicator) -- the token
    # itself never appears in a URL, only in the httponly cookie below.
    response = RedirectResponse(f"{FRONTEND_URL}/code-scan?github_connected=1")
    response.set_cookie(
        github_oauth.SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
        max_age=github_oauth.SESSION_TTL_SECONDS,
    )
    return response


@app.get("/api/github/oauth/status")
def github_oauth_status(request: Request):
    session_id = request.cookies.get(github_oauth.SESSION_COOKIE_NAME)
    token = github_oauth.oauth_sessions.get(session_id) if session_id else None
    return {"connected": token is not None, "configured": github_oauth.is_configured()}


@app.post("/api/github/oauth/logout")
def github_oauth_logout(request: Request):
    session_id = request.cookies.get(github_oauth.SESSION_COOKIE_NAME)
    if session_id:
        github_oauth.oauth_sessions.pop(session_id)
    response = RedirectResponse(f"{FRONTEND_URL}/code-scan")
    response.delete_cookie(github_oauth.SESSION_COOKIE_NAME)
    return response


def _session_github_token(request: Request) -> str | None:
    session_id = request.cookies.get(github_oauth.SESSION_COOKIE_NAME)
    return github_oauth.oauth_sessions.get(session_id) if session_id else None


# ---------------------------------------------------------------------
# Single-source code scanning (upload a .zip/.tar/.tar.gz, or a GitHub
# repo URL) through the same SAST/SCA/Secrets/IaC pipeline as org scans,
# plus an optional DAST follow-up against an authorized running app URL.
# ---------------------------------------------------------------------
# 200MB comfortably covers a real project's source tree (excluding
# dependencies/build output, which a reasonable .gitignore/.dockerignore-
# style upload wouldn't include anyway) without allowing unbounded abuse;
# archive_extract.py enforces its own, separate caps on the *extracted*
# content regardless of what this allows in compressed.
MAX_CODE_UPLOAD_BYTES = 200 * 1024 * 1024


@app.post("/api/code-scans/upload", response_model=CodeScanSummary)
async def create_code_scan_from_upload(file: UploadFile = File(...)):  # noqa: B008
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(data) > MAX_CODE_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413, detail=f"Uploaded file exceeds the {MAX_CODE_UPLOAD_BYTES // (1024 * 1024)}MB limit"
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = UPLOAD_DIR / f"{uuid.uuid4().hex}-{file.filename or 'upload'}"
    archive_path.write_bytes(data)

    scan = code_scan_manager.create_from_upload(archive_path, file.filename or "upload")
    return scan.summary()


@app.get("/api/code-scans/branches")
def list_code_scan_branches(repo_url: str, request: Request):
    try:
        owner, repo = parse_repo_url(repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token = _session_github_token(request)
    with GitHubClient(token) as gh:
        try:
            info = gh.get_repo(owner, repo)
            branches = gh.list_branches(owner, repo)
        except GitHubAuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"private": info.get("private", False), "default_branch": info.get("default_branch"), "branches": branches}


@app.post("/api/code-scans/repo", response_model=CodeScanSummary)
def create_code_scan_from_repo(req: CodeScanFromRepoRequest, request: Request):
    try:
        parse_repo_url(req.repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token = _session_github_token(request)
    scan = code_scan_manager.create_from_repo_url(req.repo_url, req.branch, github_token=token)
    return scan.summary()


@app.get("/api/code-scans", response_model=list[CodeScanSummary])
def list_code_scans():
    return [scan.summary() for scan in code_scan_manager.list()]


@app.get("/api/code-scans/{scan_id}", response_model=CodeScanDetail)
def get_code_scan(scan_id: str):
    scan = code_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Code scan not found")
    return scan.detail()


@app.post("/api/code-scans/{scan_id}/dast", response_model=CodeScanSummary)
def create_code_scan_dast(scan_id: str, req: DastRequest):
    scan = code_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Code scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Source scan is {scan.status}, not completed yet")
    if scan.dast_status == "running":
        raise HTTPException(status_code=409, detail="A DAST scan is already running for this code scan")

    scan = code_scan_manager.add_dast(scan_id, req.target_url, req.spider_minutes, req.active_scan_minutes)
    return scan.summary()


@app.get("/api/code-scans/{scan_id}/report.{fmt}")
def get_code_scan_report(scan_id: str, fmt: str):
    scan = code_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Code scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status}, not completed")
    if fmt not in _REPORT_FILENAMES:
        raise HTTPException(status_code=404, detail=f"Unknown report format '{fmt}'")

    path = scan._report_dir() / _REPORT_FILENAMES[fmt]
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{fmt} report not available for this scan")
    return FileResponse(path, media_type=_REPORT_MEDIA_TYPES[fmt], filename=_REPORT_FILENAMES[fmt])


# ---------------------------------------------------------------------
# Container registry image scanning -- one image reference, pulled and
# scanned via Trivy against JFrog Artifactory, Docker Hub, GHCR, ECR, GCR,
# ACR, Harbor, Quay, or any other OCI/Docker-v2-compliant registry.
# ---------------------------------------------------------------------
@app.post("/api/registry-scans", response_model=RegistryScanSummary)
def create_registry_scan(req: RegistryScanCreateRequest):
    if not req.image_ref.strip():
        raise HTTPException(status_code=400, detail="image_ref is required")
    scan = registry_scan_manager.create(
        req.image_ref.strip(),
        username=req.username or None,
        password=req.password or None,
        registry_token=req.registry_token or None,
        insecure=req.insecure,
    )
    return scan.summary()


@app.get("/api/registry-scans", response_model=list[RegistryScanSummary])
def list_registry_scans():
    return [scan.summary() for scan in registry_scan_manager.list()]


@app.get("/api/registry-scans/{scan_id}", response_model=RegistryScanDetail)
def get_registry_scan(scan_id: str):
    scan = registry_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Registry scan not found")
    return scan.detail()


@app.get("/api/registry-scans/{scan_id}/report.{fmt}")
def get_registry_scan_report(scan_id: str, fmt: str):
    scan = registry_scan_manager.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Registry scan not found")
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status}, not completed")
    if fmt not in _REPORT_FILENAMES:
        raise HTTPException(status_code=404, detail=f"Unknown report format '{fmt}'")

    path = scan._report_dir() / _REPORT_FILENAMES[fmt]
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{fmt} report not available for this scan")
    return FileResponse(path, media_type=_REPORT_MEDIA_TYPES[fmt], filename=_REPORT_FILENAMES[fmt])


# ---------------------------------------------------------------------
# Runtime Defender -- registers a Kubernetes cluster, hands back a one-line
# install script that deploys the real Falco eBPF sensor + falcosidekick
# (works against EKS/AKS/GKE/OpenShift/any standard cluster, since it's
# just Kubernetes), and ingests the alerts that sensor reports back.
# ---------------------------------------------------------------------
@app.post("/api/runtime-clusters", response_model=RuntimeClusterDetail)
def create_runtime_cluster(req: RuntimeClusterCreateRequest):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="name is required")
    cluster = runtime_defender_manager.create_cluster(req.name.strip())
    return cluster.detail()


@app.get("/api/runtime-clusters", response_model=list[RuntimeClusterSummary])
def list_runtime_clusters():
    return [c.summary() for c in runtime_defender_manager.list()]


@app.get("/api/runtime-clusters/{cluster_id}", response_model=RuntimeClusterDetail)
def get_runtime_cluster(cluster_id: str):
    cluster = runtime_defender_manager.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Runtime cluster not found")
    return cluster.detail()


@app.get("/api/runtime-clusters/{cluster_id}/install.sh")
def get_runtime_cluster_install_script(cluster_id: str):
    cluster = runtime_defender_manager.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Runtime cluster not found")
    script = build_install_script(cluster.id, cluster.name, cluster.install_token, BACKEND_URL)
    return PlainTextResponse(script, media_type="text/x-shellscript")


@app.get("/api/runtime-clusters/{cluster_id}/simulate.sh")
def get_runtime_cluster_simulation_script(cluster_id: str):
    cluster = runtime_defender_manager.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Runtime cluster not found")
    script = build_simulation_script(cluster.name)
    return PlainTextResponse(script, media_type="text/x-shellscript")


@app.post("/api/runtime-clusters/{cluster_id}/events", status_code=204)
async def ingest_runtime_cluster_event(cluster_id: str, request: Request, token: str):
    try:
        payload = await request.json()
    except Exception as exc:  # noqa: BLE001 -- any malformed body is the same 400 to the caller
        raise HTTPException(status_code=400, detail="request body is not valid JSON") from exc

    try:
        runtime_defender_manager.ingest_event(cluster_id, token, payload)
    except ClusterNotFound as exc:
        raise HTTPException(status_code=404, detail="Runtime cluster not found") from exc
    except InvalidInstallToken as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except MalformedFalcoAlert as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Response(status_code=204)


@app.get("/api/runtime-clusters/{cluster_id}/report.{fmt}")
def get_runtime_cluster_report(cluster_id: str, fmt: str):
    cluster = runtime_defender_manager.get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Runtime cluster not found")
    if fmt not in _REPORT_FILENAMES:
        raise HTTPException(status_code=404, detail=f"Unknown report format '{fmt}'")

    results = [cluster.as_repo_scan_result()]
    if fmt == "sarif":
        body: str | bytes = sarif_report.to_sarif(results)
    elif fmt == "json":
        body = json_report.to_json(cluster.name, results)
    elif fmt == "csv":
        body = csv_report.to_csv(results)
    elif fmt == "html":
        body = html_report.to_html(cluster.name, results)
    else:
        try:
            from .orgscan.reporting.pdf_report import to_pdf

            body = to_pdf(cluster.name, results)
        except Exception as exc:  # noqa: BLE001 -- PDF needs native libs (pango/cairo); a soft dependency everywhere else too
            raise HTTPException(
                status_code=503, detail="PDF report generation is unavailable in this deployment"
            ) from exc

    return Response(
        content=body,
        media_type=_REPORT_MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="{_REPORT_FILENAMES[fmt]}"'},
    )
