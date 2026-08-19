"""
In-process job queue for scan runs.

Jobs are executed one at a time on a single background worker thread. This
is a deliberate simplification: the engine configures a process-global
logger (coloredlogs.install on a shared logger name) and spins up its own
asyncio event loop per run, neither of which is safe to do concurrently
from multiple threads. A single-worker queue sidesteps that entirely and
matches how this tool is actually used -- one audit run at a time.
"""
import queue
import threading
import uuid
from datetime import UTC, datetime

from . import engine_runner
from .providers_meta import PROVIDERS

REPORT_DIR = str((engine_runner.REPO_ROOT / "ui" / "backend" / "data" / "reports").resolve())


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Job:
    def __init__(self, job_id: str, request: dict):
        self.id = job_id
        self.request = request
        self.provider = request["provider"]
        self.report_name = request["report_name"]
        self.status = "queued"
        self.created_at = _now()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.exit_code: int | None = None
        self.error: str | None = None
        self.log = ""

    def summary(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "report_name": self.report_name,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "error": self.error,
        }

    def detail(self) -> dict:
        return {**self.summary(), "request": self.request, "log": self.log}


class JobManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._worker = threading.Thread(target=self._run_worker, daemon=True)
        self._worker.start()

    def validate(self, req) -> str | None:
        provider_meta = PROVIDERS.get(req.provider)
        if not provider_meta:
            return f"Unknown provider '{req.provider}'. Valid providers: {', '.join(PROVIDERS)}"
        method_meta = provider_meta["authMethods"].get(req.auth_method)
        if not method_meta:
            valid = ", ".join(provider_meta["authMethods"])
            return f"Unknown auth method '{req.auth_method}' for {req.provider}. Valid methods: {valid}"
        for field in method_meta["fields"]:
            if field.get("required") and not (req.auth or {}).get(field["name"]):
                return f"Missing required field '{field['name']}' for {req.provider}/{req.auth_method}"
        return None

    def create(self, req) -> Job:
        job_id = uuid.uuid4().hex
        report_name = req.report_name or f"{req.provider}-{job_id[:8]}"

        kwargs = engine_runner.build_run_kwargs(req, REPORT_DIR)
        kwargs["report_name"] = report_name

        job = Job(job_id, {**req.model_dump(), "report_name": report_name, "resolved_kwargs": self._redact(kwargs)})
        with self._lock:
            self._jobs[job_id] = job
            self._order.insert(0, job_id)
        job._kwargs = kwargs  # stashed for the worker only
        self._queue.put(job_id)
        return job

    @staticmethod
    def _redact(kwargs: dict) -> dict:
        secret_keys = {
            "aws_secret_access_key", "aws_session_token", "client_secret", "password",
            "access_key_secret", "token", "access_secret", "service_account",
        }
        return {k: ("<redacted>" if k in secret_keys and v else v) for k, v in kwargs.items()}

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return [self._jobs[jid] for jid in self._order]

    def _run_worker(self):
        while True:
            job_id = self._queue.get()
            job = self._jobs.get(job_id)
            if job is None:
                continue
            job.status = "running"
            job.started_at = _now()
            exit_code, log, error = engine_runner.execute(job._kwargs)
            job.log = log
            job.exit_code = exit_code
            job.error = error
            job.finished_at = _now()
            job.status = "completed" if exit_code in (0, 200) and not error else "failed"


manager = JobManager()
