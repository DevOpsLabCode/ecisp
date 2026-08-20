"""Orchestrates a container-image registry scan -- pull one image
reference from JFrog Artifactory, Docker Hub, GHCR, ECR, GCR, ACR, Harbor,
Quay, or any other OCI/Docker-v2-compliant registry, scan it with Trivy,
and produce the same report set the other scan types do.

Deliberately the simplest of the three job managers in this codebase (see
`codescan.code_scan_job` and `orgscan.org_scan_job` for the other two): one
scan type, one scanner, no multi-step pipeline -- so it's a single-worker
queue with no fan-out, but the same `shutdown()` lifecycle as the others
for the same reason (see `org_scan_job.py`'s docstring for the leaked-
worker-thread story that pattern guards against).
"""

from __future__ import annotations

import queue
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from ..orgscan.models import RepoScanResult
from ..orgscan.reporting import csv_report, html_report, json_report
from ..orgscan.reporting import sarif as sarif_report
from .image_scanner import ScannerExecutionError, ScannerUnavailable, run_registry_scan

REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "registryscan-reports"


def _now() -> str:
    return datetime.now(UTC).isoformat()


class RegistryScan:
    def __init__(self, scan_id: str, image_ref: str):
        self.id = scan_id
        self.image_ref = image_ref

        self.status = "queued"
        self.created_at = _now()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.error: str | None = None

        self.result: RepoScanResult | None = None

    def summary(self) -> dict:
        counts = self.result.severity_counts() if self.result else None
        return {
            "id": self.id,
            "image_ref": self.image_ref,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "severity_counts": counts,
            "finding_count": len(self.result.findings) if self.result else None,
        }

    def detail(self) -> dict:
        return {
            **self.summary(),
            "scanners_run": self.result.scanners_run if self.result else [],
            "findings": [f.to_dict() for f in self.result.findings] if self.result else [],
        }

    def _report_dir(self) -> Path:
        return REPORT_DIR / self.id


class RegistryScanManager:
    def __init__(self):
        self._scans: dict[str, RegistryScan] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple | None] = queue.Queue()
        self._worker = threading.Thread(target=self._run_worker, daemon=True)
        self._worker.start()

    def shutdown(self, timeout: float = 5.0):
        self._queue.put(None)
        self._worker.join(timeout=timeout)

    def create(
        self,
        image_ref: str,
        username: str | None = None,
        password: str | None = None,
        registry_token: str | None = None,
        insecure: bool = False,
    ) -> RegistryScan:
        scan = RegistryScan(uuid.uuid4().hex, image_ref)
        with self._lock:
            self._scans[scan.id] = scan
            self._order.insert(0, scan.id)
        # Credentials travel only through this in-memory queue message to
        # the worker thread -- never attached to the scan record, never
        # logged, never written to disk.
        self._queue.put(
            (
                scan.id,
                {
                    "username": username,
                    "password": password,
                    "registry_token": registry_token,
                    "insecure": insecure,
                },
            )
        )
        return scan

    def get(self, scan_id: str) -> RegistryScan | None:
        return self._scans.get(scan_id)

    def list(self) -> list[RegistryScan]:
        with self._lock:
            return [self._scans[sid] for sid in self._order]

    def _run_worker(self):
        while True:
            item = self._queue.get()
            if item is None:  # shutdown() sentinel
                return
            scan_id, payload = item
            scan = self._scans.get(scan_id)
            if scan is None:
                continue
            try:
                self._execute_scan(scan, payload)
            except Exception as exc:  # noqa: BLE001 -- surfaced on the scan record, not left to crash the worker thread
                scan.status = "failed"
                scan.error = str(exc)[:1000]
                scan.finished_at = _now()

    def _execute_scan(self, scan: RegistryScan, payload: dict):
        scan.status = "running"
        scan.started_at = _now()
        try:
            findings = run_registry_scan(
                scan.image_ref,
                username=payload["username"],
                password=payload["password"],
                registry_token=payload["registry_token"],
                insecure=payload["insecure"],
            )
        except (ScannerUnavailable, ScannerExecutionError) as exc:
            scan.status = "failed"
            scan.error = str(exc)[:1000]
            scan.finished_at = _now()
            return

        scan.result = RepoScanResult(
            repository=scan.image_ref,
            technologies=["trivy"],
            scanners_run=["trivy"],
            scanners_skipped={},
            findings=findings,
        )
        self._write_reports(scan)
        scan.status = "completed"
        scan.finished_at = _now()

    def _write_reports(self, scan: RegistryScan):
        results = [scan.result]
        out_dir = scan._report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "security-findings.sarif").write_text(sarif_report.to_sarif(results))
        (out_dir / "security-findings.json").write_text(json_report.to_json(scan.image_ref, results))
        (out_dir / "security-findings.csv").write_text(csv_report.to_csv(results))
        (out_dir / "security-report.html").write_text(html_report.to_html(scan.image_ref, results))
        try:
            from ..orgscan.reporting.pdf_report import to_pdf

            (out_dir / "security-report.pdf").write_bytes(to_pdf(scan.image_ref, results))
        except Exception:  # noqa: BLE001 -- PDF needs native libs (pango/cairo); the other four formats must not be blocked by its absence
            pass  # nosec B110


manager = RegistryScanManager()
