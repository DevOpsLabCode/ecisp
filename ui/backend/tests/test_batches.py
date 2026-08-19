import time

from app import engine_runner
from app.batches import Batch, BatchManager


def wait_for_batch_terminal(batch: Batch, timeout: float = 5.0):
    from app.jobs import manager

    deadline = time.time() + timeout
    while time.time() < deadline:
        jobs = [manager.get(jid) for jid in batch.job_ids]
        if all(j and j.status in ("completed", "failed") for j in jobs):
            return
        time.sleep(0.02)
    raise AssertionError(f"batch {batch.id} jobs did not all reach a terminal status in {timeout}s")


class TestBatchManagerCreateFromFile:
    def test_valid_rows_become_jobs(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

        bm = BatchManager()
        csv_data = (
            b"provider,auth_method,report_name,profile\n"
            b"aws,profile,batch-test-1,audit-1\n"
            b"aws,profile,batch-test-2,audit-2\n"
        )
        batch = bm.create_from_file("accounts.csv", csv_data)
        assert len(batch.job_ids) == 2
        assert batch.errors == []
        wait_for_batch_terminal(batch)
        assert batch.summary()["status_counts"]["completed"] == 2

    def test_invalid_rows_are_recorded_as_errors_not_jobs(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

        bm = BatchManager()
        csv_data = (
            b"provider,auth_method,report_name,profile\n"
            b"aws,profile,batch-test-ok,audit-1\n"
            b"bogus,profile,batch-test-bad,audit-2\n"
            b"aws,profile,batch-test-missing,\n"
        )
        batch = bm.create_from_file("accounts.csv", csv_data)
        assert len(batch.job_ids) == 1
        assert len(batch.errors) == 2
        assert batch.errors[0]["row_number"] == 2
        assert "Unknown provider" in batch.errors[0]["message"]
        assert batch.errors[1]["row_number"] == 3
        assert "Missing required field" in batch.errors[1]["message"]
        wait_for_batch_terminal(batch)

    def test_all_invalid_file_yields_zero_jobs(self):
        bm = BatchManager()
        batch = bm.create_from_file("accounts.csv", b"provider,auth_method\nbogus,profile\n")
        assert batch.job_ids == []
        assert len(batch.errors) == 1

    def test_filename_and_created_at_are_recorded(self):
        bm = BatchManager()
        batch = bm.create_from_file("my-accounts.csv", b"provider,auth_method\n")
        assert batch.filename == "my-accounts.csv"
        assert batch.created_at


class TestBatchManagerQueries:
    def test_get_returns_none_for_unknown_id(self):
        bm = BatchManager()
        assert bm.get("does-not-exist") is None

    def test_get_returns_created_batch(self):
        bm = BatchManager()
        batch = bm.create_from_file("accounts.csv", b"provider,auth_method\n")
        assert bm.get(batch.id) is batch

    def test_list_returns_newest_first(self):
        bm = BatchManager()
        first = bm.create_from_file("first.csv", b"provider,auth_method\n")
        second = bm.create_from_file("second.csv", b"provider,auth_method\n")
        listed = bm.list()
        assert listed[0].id == second.id
        assert listed[1].id == first.id


class TestBatchSummaryAndDetail:
    def test_summary_shape(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

        bm = BatchManager()
        batch = bm.create_from_file(
            "accounts.csv", b"provider,auth_method,profile\naws,profile,audit-summary-test\n"
        )
        wait_for_batch_terminal(batch)
        summary = batch.summary()
        assert set(summary) == {"id", "filename", "created_at", "queued_jobs", "skipped_rows", "status_counts"}
        assert summary["queued_jobs"] == 1
        assert summary["skipped_rows"] == 0

    def test_detail_includes_jobs_and_errors(self, monkeypatch):
        monkeypatch.setattr(engine_runner, "ENGINE_AVAILABLE", True)
        monkeypatch.setattr(engine_runner, "engine_run", lambda **kwargs: 0)

        bm = BatchManager()
        batch = bm.create_from_file(
            "accounts.csv",
            b"provider,auth_method,profile\naws,profile,audit-detail-test\nbogus,profile,x\n",
        )
        wait_for_batch_terminal(batch)
        detail = batch.detail()
        assert len(detail["jobs"]) == 1
        assert len(detail["errors"]) == 1
