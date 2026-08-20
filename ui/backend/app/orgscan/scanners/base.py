"""Shared plumbing for scanner adapters.

Every adapter module exposes:
    SCANNER_ID: str
    run(repo_dir: Path, repository: str) -> list[Finding]

`run` raises `ScannerUnavailable` when the underlying CLI isn't installed
(so the orchestrator can record a clear "skipped: tool not installed"
instead of crashing the whole org scan) and `ScannerExecutionError` when the
tool ran but failed for a reason other than "found things to report" (most
of these tools use a non-zero exit code to mean "findings present", which
is not a failure).
"""
from __future__ import annotations

import shutil
import subprocess  # nosec B404 -- used only for fixed scanner-CLI invocations built by this codebase, see run_capture() below
from pathlib import Path


class ScannerUnavailable(Exception):
    """The scanner's CLI/toolchain isn't installed in this environment."""


class ScannerExecutionError(Exception):
    """The scanner ran but exited in a way that isn't a normal findings-present result."""


def require(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise ScannerUnavailable(f"'{binary}' is not installed")
    return path


def run_capture(
    args: list[str],
    cwd: Path,
    timeout: int = 600,
    ok_exit_codes: tuple[int, ...] = (0,),
) -> str:
    """Runs a scanner CLI and returns stdout.

    Many of these tools (checkov, bandit, semgrep, gosec) exit non-zero
    specifically *because* they found something to report -- that's the
    success path, not a crash, so callers pass the exit codes that mean
    "ran fine, here's stdout" via `ok_exit_codes`.
    """
    try:
        # fixed CLI invocations built by this codebase, no shell=True.
        proc = subprocess.run(  # nosec B603
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerUnavailable(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(f"{args[0]} timed out after {timeout}s") from exc

    if proc.returncode not in ok_exit_codes:
        raise ScannerExecutionError(
            f"{' '.join(args)} exited {proc.returncode}: {proc.stderr[-2000:] or proc.stdout[-2000:]}"
        )
    return proc.stdout
