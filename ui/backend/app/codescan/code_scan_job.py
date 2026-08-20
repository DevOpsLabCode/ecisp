"""Orchestrates a single-source code scan (an uploaded archive or one
GitHub repo/branch) through the same SAST/SCA/Secrets/IaC pipeline the
org-wide scanner uses -- `orgscan.repo_scanner.scan_repo` is exactly "scan
one directory, tech-detect, run applicable scanners, dedupe" already, so
this reuses it directly rather than duplicating it.

Same single-worker-queue shape as `orgscan.org_scan_job.OrgScanManager`,
and for the same reason (the engine's/scanners' own process-global state
isn't safe to run concurrently) -- see that module's docstring. `shutdown()`
exists for the same reason too: leaked worker threads across test runs
previously corrupted weasyprint's native state (see org_scan_job.py's
`shutdown()` docstring for the full story), so anything that constructs a
manager needs a clean way to stop it.
"""

from __future__ import annotations

import queue
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from ..orgscan.github_client import GitHubAuthError, GitHubClient, commit_sha, parse_repo_url
from ..orgscan.models import RepoScanResult
from ..orgscan.repo_scanner import scan_repo
from ..orgscan.reporting import csv_report, html_report, json_report
from ..orgscan.reporting import sarif as sarif_report
from .archive_extract import UnsafeArchiveError, extract_archive
from .dast_scanner import DastExecutionError, DastUnavailable, run_dast

REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "codescan-reports"
UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "codescan-uploads"

# SpotBugs and Security Code Scan both compile the target (`mvn`/`gradle`,
# `dotnet build`) to analyze it -- for a cloned GitHub repo that's a trust
# decision the user already made by pointing at a specific repo, but for an
# anonymous uploaded archive it would mean running arbitrary build tooling
# (and whatever it pulls in) against untrusted input, which use case 1's
# "do not execute uploaded code" requirement rules out directly.
_BUILD_SCANNERS_EXCLUDED_FOR_UPLOADS = {
    "spotbugs": "disabled for uploaded archives: SpotBugs compiles the target (mvn/gradle), which would mean "
    "executing untrusted build tooling",
    "security_code_scan": "disabled for uploaded archives: Security Code Scan compiles the target (dotnet build), "
    "which would mean executing untrusted build tooling",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class CodeScan:
    def __init__(self, scan_id: str, source_type: str, source_label: str, branch: str | None = None):
        self.id = scan_id
        self.source_type = source_type  # "upload" | "repo_url"
        self.source_label = source_label  # filename, or "owner/repo"
        self.branch = branch
        self.commit_sha: str | None = None

        self.status = "queued"
        self.created_at = _now()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.error: str | None = None

        self.result: RepoScanResult | None = None

        self.dast_status = "not_run"  # not_run | running | completed | failed
        self.dast_target_url: str | None = None
        self.dast_error: str | None = None

        self._lock = threading.Lock()

    def summary(self) -> dict:
        counts = self.result.severity_counts() if self.result else None
        return {
            "id": self.id,
            "source_type": self.source_type,
            "source_label": self.source_label,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "severity_counts": counts,
            "finding_count": len(self.result.findings) if self.result else None,
            "dast_status": self.dast_status,
            "dast_target_url": self.dast_target_url,
            "dast_error": self.dast_error,
        }

    def detail(self) -> dict:
        return {
            **self.summary(),
            "technologies": self.result.technologies if self.result else [],
            "scanners_run": self.result.scanners_run if self.result else [],
            "scanners_skipped": self.result.scanners_skipped if self.result else {},
            "findings": [f.to_dict() for f in self.result.findings] if self.result else [],
        }

    def _report_dir(self) -> Path:
        return REPORT_DIR / self.id


class CodeScanManager:
    def __init__(self):
        self._scans: dict[str, CodeScan] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple | None] = queue.Queue()
        self._worker = threading.Thread(target=self._run_worker, daemon=True)
        self._worker.start()

    def shutdown(self, timeout: float = 5.0):
        self._queue.put(None)
        self._worker.join(timeout=timeout)

    def create_from_upload(self, archive_path: Path, filename: str) -> CodeScan:
        scan = CodeScan(uuid.uuid4().hex, "upload", filename)
        self._register(scan)
        self._queue.put(("scan_upload", scan.id, {"archive_path": archive_path}))
        return scan

    def create_from_repo_url(self, repo_url: str, branch: str | None, github_token: str | None) -> CodeScan:
        owner, repo = parse_repo_url(repo_url)
        scan = CodeScan(uuid.uuid4().hex, "repo_url", f"{owner}/{repo}", branch=branch)
        self._register(scan)
        self._queue.put(
            ("scan_repo_url", scan.id, {"owner": owner, "repo": repo, "branch": branch, "token": github_token})
        )
        return scan

    def add_dast(self, scan_id: str, target_url: str, spider_minutes: int, active_scan_minutes: int) -> CodeScan:
        scan = self._scans[scan_id]
        scan.dast_status = "running"
        scan.dast_target_url = target_url
        self._queue.put(
            (
                "dast",
                scan_id,
                {
                    "target_url": target_url,
                    "spider_minutes": spider_minutes,
                    "active_scan_minutes": active_scan_minutes,
                },
            )
        )
        return scan

    def _register(self, scan: CodeScan):
        with self._lock:
            self._scans[scan.id] = scan
            self._order.insert(0, scan.id)

    def get(self, scan_id: str) -> CodeScan | None:
        return self._scans.get(scan_id)

    def list(self) -> list[CodeScan]:
        with self._lock:
            return [self._scans[sid] for sid in self._order]

    def _run_worker(self):
        while True:
            item = self._queue.get()
            if item is None:  # shutdown() sentinel
                return
            kind, scan_id, payload = item
            scan = self._scans.get(scan_id)
            if scan is None:
                continue
            try:
                if kind == "scan_upload":
                    self._execute_upload_scan(scan, payload["archive_path"])
                elif kind == "scan_repo_url":
                    self._execute_repo_url_scan(scan, payload)
                elif kind == "dast":
                    self._execute_dast(scan, payload)
            except Exception as exc:  # noqa: BLE001 -- surfaced on the scan record, not left to crash the worker thread
                if kind == "dast":
                    scan.dast_status = "failed"
                    scan.dast_error = str(exc)[:1000]
                else:
                    scan.status = "failed"
                    scan.error = str(exc)[:1000]
                    scan.finished_at = _now()

    def _execute_upload_scan(self, scan: CodeScan, archive_path: Path):
        scan.status = "running"
        scan.started_at = _now()
        try:
            with tempfile.TemporaryDirectory(prefix="codescan-upload-") as work_dir:
                try:
                    extracted = extract_archive(archive_path, Path(work_dir))
                except UnsafeArchiveError as exc:
                    scan.status = "failed"
                    scan.error = f"Archive rejected: {exc}"
                    scan.finished_at = _now()
                    return
                scan.result = scan_repo(
                    extracted, scan.source_label, exclude_scanners=_BUILD_SCANNERS_EXCLUDED_FOR_UPLOADS
                )
        finally:
            archive_path.unlink(missing_ok=True)

        self._write_reports(scan)
        scan.status = "completed"
        scan.finished_at = _now()

    def _execute_repo_url_scan(self, scan: CodeScan, payload: dict):
        scan.status = "running"
        scan.started_at = _now()

        owner, repo, branch, token = payload["owner"], payload["repo"], payload["branch"], payload["token"]
        with GitHubClient(token) as gh:
            try:
                info = gh.get_repo(owner, repo)
            except GitHubAuthError as exc:
                scan.status = "failed"
                scan.error = str(exc)
                scan.finished_at = _now()
                return

            if info.get("private") and not token:
                scan.status = "failed"
                scan.error = f"{owner}/{repo} is private -- connect GitHub to scan it"
                scan.finished_at = _now()
                return

            clone_branch = branch or info.get("default_branch")
            with gh.clone(owner, repo, default_branch=clone_branch) as repo_dir:
                scan.commit_sha = commit_sha(repo_dir)
                scan.result = scan_repo(repo_dir, scan.source_label)

        self._write_reports(scan)
        scan.status = "completed"
        scan.finished_at = _now()

    def _execute_dast(self, scan: CodeScan, payload: dict):
        try:
            dast_findings = run_dast(payload["target_url"], payload["spider_minutes"], payload["active_scan_minutes"])
        except (DastUnavailable, DastExecutionError) as exc:
            scan.dast_status = "failed"
            scan.dast_error = str(exc)[:1000]
            return

        if scan.result is None:
            scan.dast_status = "failed"
            scan.dast_error = "No source scan result to merge DAST findings into"
            return

        scan.result.findings.extend(dast_findings)
        scan.result.scanners_run.append("zap")
        self._write_reports(scan)
        scan.dast_status = "completed"

    def _write_reports(self, scan: CodeScan):
        results = [scan.result]
        out_dir = scan._report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "security-findings.sarif").write_text(sarif_report.to_sarif(results))
        (out_dir / "security-findings.json").write_text(json_report.to_json(scan.source_label, results))
        (out_dir / "security-findings.csv").write_text(csv_report.to_csv(results))
        (out_dir / "security-report.html").write_text(html_report.to_html(scan.source_label, results))
        try:
            from ..orgscan.reporting.pdf_report import to_pdf

            (out_dir / "security-report.pdf").write_bytes(to_pdf(scan.source_label, results))
        except Exception:  # noqa: BLE001 -- PDF needs native libs (pango/cairo); the other four formats must not be blocked by its absence
            pass  # nosec B110


manager = CodeScanManager()
