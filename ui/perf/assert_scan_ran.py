#!/usr/bin/env python3
"""
Asserts that a scan job (created by ui-deploy.yml's "real scan job" smoke
test) actually reached the engine's own authentication check, rather than
crashing inside our FastAPI/job-queue integration code.

A bogus AWS profile is used deliberately -- the job is EXPECTED to fail,
but it must fail on the engine's own "profile not found" error, not on an
unhandled exception on our side (e.g. the worker-thread asyncio event-loop
bug this guards against).

Usage: assert_scan_ran.py <path-to-job-detail-json>
"""
import json
import sys


def main() -> int:
    with open(sys.argv[1]) as f:
        detail = json.load(f)

    if detail["error"] is not None:
        print(
            "FAIL: unhandled crash in our integration, not the engine's own "
            f"error handling: {detail['error']}",
            file=sys.stderr,
        )
        return 1

    log = detail["log"]
    if "Authenticating to cloud provider" not in log:
        print("FAIL: engine never actually ran (log missing auth stage)", file=sys.stderr)
        return 1

    if "could not be found" not in log:
        print(
            "FAIL: expected an auth failure for the bogus profile, got something else:\n" + log,
            file=sys.stderr,
        )
        return 1

    print("OK: engine ran and failed on its own auth check, not on our integration code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
