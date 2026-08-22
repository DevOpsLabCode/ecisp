"""run_forever() only ever exits via an exception (it's a poll loop by
design) -- these tests use a monkeypatched time.sleep that raises a
sentinel after N calls to escape it deliberately, rather than actually
looping forever or backgrounding a thread."""

from __future__ import annotations

import pytest

from app import responder


class _StopAfter:
    def __init__(self, n: int):
        self.n = n
        self.calls = 0

    def __call__(self, _seconds: float) -> None:
        self.calls += 1
        if self.calls >= self.n:
            raise StopIteration


class _FakeBackend:
    def __init__(self, commands: list[dict]):
        self._commands = commands
        self.reported: list[tuple[str, str]] = []

    def list_commands(self) -> list[dict]:
        return self._commands

    def report_status(self, command_id: str, status: str) -> None:
        self.reported.append((command_id, status))

    def list_aws_accounts(self) -> list[dict]:
        # No registered accounts -- the sweep still runs every cycle in
        # these tests (poll_interval_seconds=0 collapses the sweep
        # cadence to every cycle, see run_forever), this just keeps it a
        # clean no-op instead of exercising its own error path here.
        return []

    def report_account_coverage(self, account_id: str, status: str) -> None:
        raise AssertionError("no accounts were registered -- this should never be called")


def test_run_forever_processes_at_least_one_cycle_before_stopping(monkeypatch):
    stop_after = _StopAfter(1)
    monkeypatch.setattr(responder.time, "sleep", stop_after)
    backend = _FakeBackend([])

    with pytest.raises(StopIteration):
        responder.run_forever(backend, lambda: object(), poll_interval_seconds=0)

    assert stop_after.calls == 1


def test_run_forever_logs_when_a_cycle_actually_processes_commands(monkeypatch, caplog):
    stop_after = _StopAfter(1)
    monkeypatch.setattr(responder.time, "sleep", stop_after)
    backend = _FakeBackend(
        [{"id": "cmd-1", "status": "role_resolved", "resolved_role_arn": "not-a-real-arn"}]
    )

    with caplog.at_level("INFO"), pytest.raises(StopIteration):
        responder.run_forever(backend, lambda: object(), poll_interval_seconds=0)

    assert backend.reported == [("cmd-1", "failed")]
    assert any("Processed 1 command" in message for message in caplog.messages)


def test_run_forever_survives_a_cycle_that_raises_and_keeps_polling(monkeypatch):
    stop_after = _StopAfter(2)
    monkeypatch.setattr(responder.time, "sleep", stop_after)

    class _ExplodingBackend:
        def list_commands(self):
            raise RuntimeError("backend unreachable")

    with pytest.raises(StopIteration):
        responder.run_forever(_ExplodingBackend(), lambda: object(), poll_interval_seconds=0)

    # Reached the second sleep -- proves the loop didn't propagate the
    # exception out and die after the first failed cycle.
    assert stop_after.calls == 2


def test_run_forever_logs_when_a_sweep_actually_checks_accounts(monkeypatch, caplog):
    stop_after = _StopAfter(1)
    monkeypatch.setattr(responder.time, "sleep", stop_after)

    class _AccountBackend(_FakeBackend):
        def list_aws_accounts(self) -> list[dict]:
            return [{"account_id": "123456789012", "assume_role_status": "unverified"}]

        def report_account_coverage(self, account_id: str, status: str) -> None:
            self.reported.append((account_id, status))

    class _RaisingSts:
        # Doesn't matter whether the check itself succeeds or fails here
        # -- only that the sweep runs and logs having checked an account.
        def assume_role(self, **_kwargs):
            raise RuntimeError("simulated")

    backend = _AccountBackend([])

    with caplog.at_level("INFO"), pytest.raises(StopIteration):
        responder.run_forever(backend, lambda: _RaisingSts(), poll_interval_seconds=0)

    assert backend.reported == [("123456789012", "failed")]
    assert any("Swept account coverage for 1 account" in message for message in caplog.messages)


def test_handle_command_reports_failed_for_an_unexpected_status():
    command = {"id": "cmd-1", "status": "some_future_status", "resolved_role_arn": "arn:aws:iam::123456789012:role/x"}

    status = responder._handle_command(command, sts_client=object(), role_template=responder.DEFAULT_ROLE_TEMPLATE)

    assert status == "failed"
