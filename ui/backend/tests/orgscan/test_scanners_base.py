import subprocess

import pytest

from app.orgscan.scanners.base import ScannerExecutionError, ScannerUnavailable, require, run_capture


def test_require_finds_installed_binary():
    # "python3" is guaranteed present -- this whole test suite runs under it.
    assert require("python3")


def test_require_raises_for_missing_binary():
    with pytest.raises(ScannerUnavailable):
        require("definitely-not-a-real-binary-xyz")


def test_run_capture_returns_stdout_on_success(tmp_path):
    out = run_capture(["python3", "-c", "print('hello')"], cwd=tmp_path)
    assert out.strip() == "hello"


def test_run_capture_accepts_configured_ok_exit_codes(tmp_path):
    out = run_capture(["python3", "-c", "import sys; print('found'); sys.exit(1)"], cwd=tmp_path, ok_exit_codes=(0, 1))
    assert out.strip() == "found"


def test_run_capture_raises_on_unexpected_exit_code(tmp_path):
    with pytest.raises(ScannerExecutionError):
        run_capture(["python3", "-c", "import sys; sys.exit(2)"], cwd=tmp_path, ok_exit_codes=(0,))


def test_run_capture_raises_scanner_unavailable_on_missing_binary(tmp_path):
    with pytest.raises(ScannerUnavailable):
        run_capture(["definitely-not-a-real-binary-xyz"], cwd=tmp_path)


def test_run_capture_raises_on_timeout(tmp_path):
    with pytest.raises(ScannerExecutionError, match="timed out"):
        run_capture(["python3", "-c", "import time; time.sleep(5)"], cwd=tmp_path, timeout=0.1)


def test_run_capture_propagates_subprocess_type_errors_as_scanner_error(tmp_path, monkeypatch):
    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(ScannerExecutionError):
        run_capture(["python3"], cwd=tmp_path)
