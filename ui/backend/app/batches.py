"""
Groups many scan jobs created from one bulk-import file so they can be
tracked together. Jobs themselves are unchanged -- they still go through
the single JobManager queue in jobs.py; a Batch is just a list of job ids
plus the rows that failed to even become a job.
"""
import uuid
from datetime import UTC, datetime

from .batch_import import parse_upload, row_to_scan_request
from .jobs import manager


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Batch:
    def __init__(self, batch_id: str, filename: str):
        self.id = batch_id
        self.filename = filename
        self.created_at = _now()
        self.job_ids: list[str] = []
        self.errors: list[dict] = []  # [{row_number, message}]

    def _status_counts(self) -> dict[str, int]:
        counts = {"queued": 0, "running": 0, "completed": 0, "failed": 0}
        for job_id in self.job_ids:
            job = manager.get(job_id)
            if job:
                counts[job.status] = counts.get(job.status, 0) + 1
        return counts

    def summary(self) -> dict:
        return {
            "id": self.id,
            "filename": self.filename,
            "created_at": self.created_at,
            "queued_jobs": len(self.job_ids),
            "skipped_rows": len(self.errors),
            "status_counts": self._status_counts(),
        }

    def detail(self) -> dict:
        return {
            **self.summary(),
            "jobs": [manager.get(jid).summary() for jid in self.job_ids if manager.get(jid)],
            "errors": self.errors,
        }


class BatchManager:
    def __init__(self):
        self._batches: dict[str, Batch] = {}
        self._order: list[str] = []

    def create_from_file(self, filename: str, data: bytes) -> Batch:
        rows = parse_upload(filename, data)
        batch = Batch(uuid.uuid4().hex, filename)
        for row_number, row in enumerate(rows, start=1):
            req, error = row_to_scan_request(row)
            if error is None:
                error = manager.validate(req)
            if error:
                batch.errors.append({"row_number": row_number, "message": error})
                continue
            job = manager.create(req)
            batch.job_ids.append(job.id)
        self._batches[batch.id] = batch
        self._order.insert(0, batch.id)
        return batch

    def get(self, batch_id: str) -> Batch | None:
        return self._batches.get(batch_id)

    def list(self) -> list[Batch]:
        return [self._batches[bid] for bid in self._order]


batch_manager = BatchManager()
