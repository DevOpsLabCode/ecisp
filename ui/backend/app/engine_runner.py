"""
Thin integration layer between the FastAPI job manager and the actual
EnterpriseCloudDiscovery engine (the ecisp package living at the repo root,
two directories up from this file).

Import of the engine is deferred and guarded: the API should still boot and
serve provider metadata / job history even if the engine package (and its
many cloud SDK dependencies) isn't installed in the current interpreter, so
this backend is easy to smoke-test without a full 3.9-3.11 venv set up.
"""
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ENGINE_IMPORT_ERROR: str | None = None

try:
    from EnterpriseCloudDiscovery.__main__ import run as engine_run  # noqa: E402
    from EnterpriseCloudDiscovery.output.result_encoder import JavaScriptEncoder  # noqa: E402
    ENGINE_AVAILABLE = True
except Exception as exc:  # pragma: no cover - depends on local environment
    ENGINE_AVAILABLE = False
    ENGINE_IMPORT_ERROR = (
        f"{type(exc).__name__}: {exc}. The ecisp engine is not importable from this "
        f"interpreter. Install it with `pip install -e {REPO_ROOT}` (or the pinned "
        f"requirements in ui/backend/requirements.txt) under Python 3.9-3.11."
    )

ENGINE_LOGGER_NAME = "enterprise-cloud-discovery"

AZURE_METHOD_FLAG = {
    "cli": "cli",
    "user_account": "user_account",
    "user_account_browser": "user_account_browser",
    "service_principal": "service_principal",
    "msi": "msi",
}


def build_run_kwargs(req, report_dir: str) -> dict:
    """
    Translate a ScanCreateRequest into the keyword arguments expected by
    EnterpriseCloudDiscovery.__main__.run(). Auth and scope field names in
    providers_meta.py are deliberately chosen to match run()'s kwarg names,
    so most of this is a direct merge.
    """
    kwargs = dict(
        provider=req.provider,
        report_name=req.report_name,
        report_dir=report_dir,
        services=list(req.services or []),
        skipped_services=list(req.skipped_services or []),
        ruleset=req.ruleset or "default.json",
        max_workers=req.max_workers or 10,
        max_rate=req.max_rate,
        debug=bool(req.debug),
        quiet=False,
        no_browser=True,
        force_write=True,
        result_format="json",
        programmatic_execution=True,
    )

    for k, v in (req.auth or {}).items():
        if v not in (None, ""):
            kwargs[k] = v

    for k, v in (req.scope or {}).items():
        if v not in (None, "", []):
            kwargs[k] = v

    if req.provider == "azure":
        flag = AZURE_METHOD_FLAG.get(req.auth_method)
        if flag:
            kwargs[flag] = True
    elif req.provider == "gcp" and req.auth_method == "user_account":
        kwargs["user_account"] = True

    return kwargs


class JobLogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        try:
            self.lines.append(self.format(record))
        except Exception:
            # A malformed log record must never crash the scan it's logging for.
            pass  # nosec B110

    def text(self) -> str:
        return "\n".join(self.lines)


def execute(kwargs: dict) -> tuple[int, str, str | None]:
    """
    Run the engine synchronously (blocking). Must only be called from the
    single-worker job thread in jobs.py -- the engine's logger and asyncio
    event loop setup are process-global and not safe to run concurrently.

    Returns (exit_code, captured_log, error_message_or_None).
    """
    if not ENGINE_AVAILABLE:
        return 1, "", ENGINE_IMPORT_ERROR

    capture = JobLogCapture()
    capture.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger = logging.getLogger(ENGINE_LOGGER_NAME)
    logger.addHandler(capture)
    try:
        exit_code = engine_run(**kwargs)
        return exit_code, capture.text(), None
    except Exception as exc:
        return 1, capture.text(), f"{type(exc).__name__}: {exc}"
    finally:
        logger.removeHandler(capture)


def load_results(report_name: str, report_dir: str) -> dict:
    if not ENGINE_AVAILABLE:
        raise RuntimeError(ENGINE_IMPORT_ERROR)
    encoder = JavaScriptEncoder(report_name=report_name, report_dir=report_dir)
    return encoder.load_from_file("RESULTS")
