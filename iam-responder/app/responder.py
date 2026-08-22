"""The poll loop: fetches every command waiting on this component (across
the whole fleet -- see backend_client.py) and, for each one, assumes into
the target AWS account and applies or removes the deny-all policy. This
is the only module that ties aws_actions.py and assume_role.py together
with the backend -- kept separate from both so each can be tested (and
read) in isolation.
"""

from __future__ import annotations

import logging
import time

from .account_coverage import check_account_coverage
from .assume_role import assumed_role_session
from .aws_actions import apply_deny_policy, parse_role_arn, remove_deny_policy
from .backend_client import GolemBackendClient

logger = logging.getLogger("golem.iam_responder")

DEFAULT_ROLE_TEMPLATE = "arn:aws:iam::{account_id}:role/golem-iam-responder"
DEFAULT_ACCOUNT_SWEEP_INTERVAL_SECONDS = 3600.0


def _iam_client_for(sts_client, role_arn: str, session_name: str):
    session = assumed_role_session(sts_client, role_arn, session_name)
    return session.client("iam")


def _handle_command(command: dict, sts_client, role_template: str) -> str:
    """Returns the status to report back -- never raises; any failure
    (bad ARN, AssumeRole denied, IAM call denied) becomes "failed" so one
    broken command can't take down the whole poll cycle."""
    command_id = command["id"]
    try:
        account_id, role_name = parse_role_arn(command["resolved_role_arn"])
        assume_role_arn = role_template.format(account_id=account_id)

        if command["status"] == "role_resolved":
            iam_client = _iam_client_for(sts_client, assume_role_arn, f"golem-containment-{command_id}")
            apply_deny_policy(iam_client, role_name)
            return "applied"

        if command["status"] == "release_pending":
            iam_client = _iam_client_for(sts_client, assume_role_arn, f"golem-release-{command_id}")
            remove_deny_policy(iam_client, role_name)
            return "released"

        # list_commands only ever returns these two statuses (see
        # containment_store.list_commands_for_iam_component) -- anything
        # else would mean the backend and this component have drifted.
        raise ValueError(f"unexpected command status {command['status']!r}")
    except Exception:
        logger.exception("Failed to process command %s", command_id)
        return "failed"


def process_once(backend: GolemBackendClient, sts_client, role_template: str = DEFAULT_ROLE_TEMPLATE) -> int:
    """Runs one poll-and-process cycle. Returns how many commands were
    processed, mainly so tests and the run loop's own logging have
    something concrete to report."""
    commands = backend.list_commands()
    for command in commands:
        status = _handle_command(command, sts_client, role_template)
        backend.report_status(command["id"], status)
    return len(commands)


def sweep_account_coverage(backend: GolemBackendClient, sts_client, role_template: str = DEFAULT_ROLE_TEMPLATE) -> int:
    """Checks every registered AWS account's cross-account trust
    relationship and reports the result -- the only thing in the whole
    containment system that can, since it's the only component with AWS
    credentials at all. Returns how many accounts were checked."""
    accounts = backend.list_aws_accounts()
    for account in accounts:
        status = check_account_coverage(sts_client, account["account_id"], role_template)
        backend.report_account_coverage(account["account_id"], status)
    return len(accounts)


def run_forever(
    backend: GolemBackendClient,
    sts_client_factory,
    role_template: str = DEFAULT_ROLE_TEMPLATE,
    poll_interval_seconds: float = 10.0,
    account_sweep_interval_seconds: float = DEFAULT_ACCOUNT_SWEEP_INTERVAL_SECONDS,
) -> None:
    """`sts_client_factory` is called fresh on every cycle (not held open
    across the whole process lifetime) -- keeps this immune to any
    long-lived-connection/credential-refresh edge cases boto3 clients can
    hit over a genuinely long-running poll loop.

    Account coverage sweeps run on their own, much slower cadence
    (default hourly) -- checking every registered account's trust
    relationship needs nowhere near the freshness containment commands
    do, and doing it every `poll_interval_seconds` would just be
    needless steady-state load against AWS STS/IAM for signals that
    don't change minute to minute."""
    logger.info("Golem IAM responder starting, polling every %ss", poll_interval_seconds)
    # poll_interval_seconds <= 0 has no meaningful "N cycles per sweep"
    # ratio (and would divide by zero) -- falls back to sweeping every
    # cycle, which only actually happens with that non-production value
    # (tests use it to make the loop spin instantly).
    sweep_every_n_cycles = (
        max(1, round(account_sweep_interval_seconds / poll_interval_seconds)) if poll_interval_seconds > 0 else 1
    )
    cycle = 0
    while True:
        try:
            count = process_once(backend, sts_client_factory(), role_template)
            if count:
                logger.info("Processed %d command(s)", count)
        except Exception:
            logger.exception("Poll cycle failed")

        cycle += 1
        if cycle % sweep_every_n_cycles == 0:
            try:
                swept = sweep_account_coverage(backend, sts_client_factory(), role_template)
                if swept:
                    logger.info("Swept account coverage for %d account(s)", swept)
            except Exception:
                logger.exception("Account coverage sweep failed")

        time.sleep(poll_interval_seconds)
