"""Orchestrates a whole org scan: discover repos -> clone + scan each
(in parallel) -> group/create GitHub Issues for Critical/High findings ->
write every report format to disk -> email the summary.

Mirrors the single-worker-queue shape of `app.jobs.JobManager` (one org
scan actually running at a time -- fanning each one out internally with a
thread pool is what gets concurrency, not running multiple org scans
concurrently), but the PAT is never persisted into the job's stored state,
only held in memory for the duration of `_execute`.
"""
from __future__ import annotations

import queue
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

from . import email_report
from .github_client import GitHubAuthError, GitHubClient
from .issues import create_issues_for_scan
from .models import SEVERITIES, RepoScanResult
from .repo_scanner import scan_repo
from .reporting import csv_report, html_report, json_report
from .reporting import sarif as sarif_report

REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "orgscan-reports"


def _now() -> str:
    return datetime.now(UTC).isoformat()


class OrgScan:
    def __init__(self, scan_id: str, org: str, notify_email: str | None, create_issues: bool, max_workers: int):
        self.id = scan_id
        self.org = org
        self.notify_email = notify_email
        self.create_issues = create_issues
        self.max_workers = max_workers

        self.status = "queued"
        self.created_at = _now()
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.error: str | None = None

        self.total_repos = 0
        self.completed_repos = 0
        self.repo_results: list[RepoScanResult] = []
        self.issue_outcomes: dict[str, dict] = {}
        self.email_sent = False

        self._lock = threading.Lock()

    def severity_totals(self) -> dict[str, int]:
        totals = dict.fromkeys(SEVERITIES, 0)
        for r in self.repo_results:
            for sev, count in r.severity_counts().items():
                totals[sev] += count
        return totals

    def summary(self) -> dict:
        return {
            "id": self.id,
            "org": self.org,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "total_repos": self.total_repos,
            "completed_repos": self.completed_repos,
            "repos_with_findings": sum(1 for r in self.repo_results if r.findings),
            "severity_totals": self.severity_totals(),
            "issues_created": sum(1 for o in self.issue_outcomes.values() if o.get("action") == "created"),
            "email_sent": self.email_sent,
        }

    def detail(self) -> dict:
        return {
            **self.summary(),
            "repositories": [
                {
                    "repository": r.repository,
                    "technologies": r.technologies,
                    "scanners_run": r.scanners_run,
                    "scanners_skipped": r.scanners_skipped,
                    "severity_counts": r.severity_counts(),
                    "finding_count": len(r.findings),
                    "error": r.error,
                    "issue": self.issue_outcomes.get(r.repository),
                }
                for r in self.repo_results
            ],
        }

    def _report_dir(self) -> Path:
        return REPORT_DIR / self.id


def _scan_one_repo(gh: GitHubClient, repo: dict) -> RepoScanResult:
    owner, name = repo["full_name"].split("/", 1)
    try:
        with gh.clone(owner, name, default_branch=repo.get("default_branch")) as repo_dir:
            return scan_repo(repo_dir, repo["full_name"])
    except Exception as exc:  # noqa: BLE001 -- one repo failing to clone/scan must not abort the whole org scan
        return RepoScanResult(
            repository=repo["full_name"],
            technologies=[],
            scanners_run=[],
            scanners_skipped={},
            findings=[],
            error=str(exc)[:500],
        )


class OrgScanManager:
    def __init__(self):
        self._scans: dict[str, OrgScan] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._queue: queue.Queue[tuple[str, str] | None] = queue.Queue()
        self._worker = threading.Thread(target=self._run_worker, daemon=True)
        self._worker.start()

    def shutdown(self, timeout: float = 5.0):
        """Stops the worker thread. The module-level `manager` singleton
        lives for the app's whole process lifetime and never needs this --
        it exists so tests that construct their own OrgScanManager (one per
        test, for isolation) can tear the worker thread down afterward
        instead of leaking it. A pile of leaked daemon threads is harmless
        on its own (blocked on queue.get()), but a full test run creates
        enough of them that native libraries invoked from a worker thread
        (weasyprint's PDF rendering, see reporting/pdf_report.py) started
        segfaulting -- most likely global fontconfig/pango state getting
        corrupted under that much thread churn within one process.
        """
        self._queue.put(None)  # sentinel -- see _run_worker
        self._worker.join(timeout=timeout)

    def create(
        self,
        org: str,
        token: str,
        notify_email: str | None = None,
        create_issues: bool = True,
        max_workers: int = 4,
        include_archived: bool = False,
    ) -> OrgScan:
        scan_id = uuid.uuid4().hex
        scan = OrgScan(scan_id, org, notify_email, create_issues, max_workers)
        with self._lock:
            self._scans[scan_id] = scan
            self._order.insert(0, scan_id)
        scan._include_archived = include_archived  # stashed for the worker only
        self._queue.put((scan_id, token))
        return scan

    def get(self, scan_id: str) -> OrgScan | None:
        return self._scans.get(scan_id)

    def list(self) -> list[OrgScan]:
        with self._lock:
            return [self._scans[sid] for sid in self._order]

    def _run_worker(self):
        while True:
            item = self._queue.get()
            if item is None:  # shutdown() sentinel
                return
            scan_id, token = item
            scan = self._scans.get(scan_id)
            if scan is None:
                continue
            try:
                self._execute(scan, token)
            except Exception as exc:  # noqa: BLE001 -- surfaced on the scan record, not left to crash the worker thread
                scan.status = "failed"
                scan.error = str(exc)[:1000]
                scan.finished_at = _now()

    def _execute(self, scan: OrgScan, token: str):
        scan.status = "running"
        scan.started_at = _now()

        with GitHubClient(token) as gh:
            try:
                gh.verify()
            except GitHubAuthError as exc:
                scan.status = "failed"
                scan.error = str(exc)
                scan.finished_at = _now()
                return

            repos = gh.list_org_repos(scan.org, include_archived=getattr(scan, "_include_archived", False))
            scan.total_repos = len(repos)

            results: list[RepoScanResult] = []
            with ThreadPoolExecutor(max_workers=max(1, scan.max_workers)) as pool:
                futures = {pool.submit(_scan_one_repo, gh, repo): repo for repo in repos}
                for future in as_completed(futures):
                    results.append(future.result())
                    with scan._lock:
                        scan.completed_repos += 1

            # Deterministic ordering for the UI/report regardless of which
            # thread finished first.
            order = {r["full_name"]: i for i, r in enumerate(repos)}
            results.sort(key=lambda r: order.get(r.repository, 0))
            scan.repo_results = results

            if scan.create_issues:
                scan.issue_outcomes = create_issues_for_scan(gh, results)

            self._write_reports(scan)

            if scan.notify_email:
                attachments = self._read_report_attachments(scan)
                try:
                    scan.email_sent = email_report.send_report(
                        scan.notify_email, scan.org, results, "COMPLETED", attachments
                    )
                except Exception:  # noqa: BLE001 -- a failed email send shouldn't mark an otherwise-successful scan as failed
                    scan.email_sent = False

        scan.status = "completed"
        scan.finished_at = _now()

    def _write_reports(self, scan: OrgScan):
        out_dir = scan._report_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "security-findings.sarif").write_text(sarif_report.to_sarif(scan.repo_results))
        (out_dir / "security-findings.json").write_text(json_report.to_json(scan.org, scan.repo_results))
        (out_dir / "security-findings.csv").write_text(csv_report.to_csv(scan.repo_results))
        (out_dir / "security-report.html").write_text(html_report.to_html(scan.org, scan.repo_results))
        try:
            from .reporting.pdf_report import to_pdf

            (out_dir / "security-report.pdf").write_bytes(to_pdf(scan.org, scan.repo_results))
        except Exception:  # noqa: BLE001 -- PDF needs native libs (pango/cairo); the other four formats must not be blocked by its absence
            pass  # nosec B110

    def _read_report_attachments(self, scan: OrgScan) -> dict[str, tuple[bytes, str]]:
        out_dir = scan._report_dir()
        attachments = {}
        for filename, subtype in (
            ("security-report.html", "html"),
            ("security-findings.json", "json"),
            ("security-findings.sarif", "sarif"),
            ("security-findings.csv", "csv"),
            ("security-report.pdf", "pdf"),
        ):
            path = out_dir / filename
            if path.exists():
                attachments[filename] = (path.read_bytes(), subtype)
        return attachments


manager = OrgScanManager()
