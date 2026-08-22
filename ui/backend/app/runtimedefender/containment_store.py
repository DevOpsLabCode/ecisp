"""CRUD for the containment tables (`containment_models.py`). Every
function takes an explicit `Session` rather than opening its own -- callers
own the transaction boundary (an API route commits once per request via
`db.session_scope()`; a test commits once per assertion), which keeps this
module a plain function library instead of a second place session lifetime
gets decided.

Wired into `main.py`'s ingest route (queues a command when a Falco rule is
mapped) and into the new `/commands` / `/response-rules` routes the
in-cluster responder polls -- see the containment build plan's Phase 1.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .containment_models import ResponseCommand, ResponseRule

# "log_only" is deliberately not enqueueable -- it exists so a rule can be
# marked reviewed-and-intentionally-alert-only in the same table, without a
# separate on/off flag. See the build plan's curated rule->response table.
RESPONSE_ACTIONS = ("isolate_network", "kill_process", "quarantine_node", "log_only")
ENQUEUEABLE_ACTIONS = tuple(a for a in RESPONSE_ACTIONS if a != "log_only")
# "release_pending" sits between an operator clicking Release and the
# responder actually deleting the NetworkPolicy -- the responder polls for
# it the same way it polls for "pending", then reports back "released".
COMMAND_STATUSES = ("pending", "applied", "failed", "release_pending", "released")
# What the in-cluster responder's poll loop acts on: apply a fresh command,
# or reverse one an operator already released. Anything else ("applied",
# "failed", "released") is a terminal state the responder has no more work
# to do for.
ACTIONABLE_STATUSES = ("pending", "release_pending")
# Only network isolation can be released -- once a kill_process command is
# "applied", the process is already gone; there's nothing left to reverse.
# See the build plan: confirmation for kill_process means "we know it
# happened," not "we can undo it."
RELEASABLE_ACTIONS = ("isolate_network",)


class UnknownResponseAction(ValueError):
    pass


class UnknownCommandStatus(ValueError):
    pass


class CommandNotFound(LookupError):
    pass


class InvalidCommandTransition(ValueError):
    """Raised when an operation is attempted from a command status it
    doesn't make sense from -- e.g. releasing a command that was never
    applied."""


def _now() -> datetime:
    return datetime.now(UTC)


def upsert_response_rule(session: Session, rule_id: str, action: str, *, enabled: bool = True) -> ResponseRule:
    """Creates or updates the response mapping for one Falco rule. Not
    batch/bulk by design -- each call is one operator decision, and the
    build plan's audit-log requirement (see Open Decisions) wants each of
    those as its own event, not folded into a bulk upsert."""
    if action not in RESPONSE_ACTIONS:
        raise UnknownResponseAction(f"Unknown response action {action!r}, expected one of {RESPONSE_ACTIONS}")

    rule = session.get(ResponseRule, rule_id)
    if rule is None:
        rule = ResponseRule(rule_id=rule_id, action=action, enabled=enabled, created_at=_now(), updated_at=_now())
        session.add(rule)
        return rule

    rule.action = action
    rule.enabled = enabled
    rule.updated_at = _now()
    return rule


def get_response_action(session: Session, rule_id: str) -> str | None:
    """The lookup the ingest path will make for every incoming Falco alert:
    is this rule opted into a response, and if so which one. Returns None
    for the default case (unmapped, or explicitly disabled) -- alert-only,
    unchanged from today's behavior."""
    rule = session.get(ResponseRule, rule_id)
    if rule is None or not rule.enabled:
        return None
    return rule.action


def list_response_rules(session: Session) -> list[ResponseRule]:
    return list(session.scalars(select(ResponseRule).order_by(ResponseRule.rule_id)))


def enqueue_command(
    session: Session,
    *,
    cluster_id: str,
    namespace: str,
    pod_name: str,
    action: str,
    idempotency_key: str | None = None,
) -> ResponseCommand:
    """Queues one containment action for one pod in one cluster. Idempotent
    by default (same cluster/namespace/pod/action collapses to the existing
    pending command) so a Falco rule re-firing during an active incident
    can't queue the same isolation twice -- see the build plan's
    confirmation/reversal flow."""
    if action not in ENQUEUEABLE_ACTIONS:
        raise UnknownResponseAction(f"{action!r} is not an enqueueable containment action")

    key = idempotency_key or f"{cluster_id}:{namespace}:{pod_name}:{action}"
    existing = session.scalars(
        select(ResponseCommand).where(ResponseCommand.idempotency_key == key, ResponseCommand.status == "pending")
    ).first()
    if existing is not None:
        return existing

    command = ResponseCommand(
        id=uuid.uuid4().hex,
        cluster_id=cluster_id,
        namespace=namespace,
        pod_name=pod_name,
        action=action,
        status="pending",
        idempotency_key=key,
        created_at=_now(),
        updated_at=_now(),
    )
    session.add(command)
    return command


def list_pending_commands(session: Session, cluster_id: str) -> list[ResponseCommand]:
    """What the in-cluster responder will long-poll -- scoped to exactly
    one `cluster_id`, never a fleet-wide query, so a compromised responder
    can only ever see its own cluster's commands (see the architecture
    diagram in the build plan)."""
    stmt = (
        select(ResponseCommand)
        .where(ResponseCommand.cluster_id == cluster_id, ResponseCommand.status == "pending")
        .order_by(ResponseCommand.created_at)
    )
    return list(session.scalars(stmt))


def list_actionable_commands(session: Session, cluster_id: str) -> list[ResponseCommand]:
    """What the responder's poll loop actually fetches: both "pending"
    (apply) and "release_pending" (reverse) commands for its own cluster,
    in one call -- the responder branches on each command's `status` to
    decide which action to take. See `list_pending_commands` for the
    apply-only view a dashboard might want instead."""
    stmt = (
        select(ResponseCommand)
        .where(ResponseCommand.cluster_id == cluster_id, ResponseCommand.status.in_(ACTIONABLE_STATUSES))
        .order_by(ResponseCommand.created_at)
    )
    return list(session.scalars(stmt))


def _get_command(session: Session, command_id: str, *, cluster_id: str | None = None) -> ResponseCommand:
    """`cluster_id`, when given, scopes the lookup to its owning cluster --
    a valid token for cluster A must never be able to act on cluster B's
    command, even by guessing or leaking its id (ids are opaque uuid4 hex,
    but this is cheap to enforce properly rather than lean on that alone).
    A mismatch is indistinguishable from "doesn't exist" to the caller, so
    this never leaks whether the id exists in another cluster."""
    command = session.get(ResponseCommand, command_id)
    if command is None or (cluster_id is not None and command.cluster_id != cluster_id):
        raise CommandNotFound(f"No response command with id {command_id!r}")
    return command


def update_command_status(
    session: Session, command_id: str, status: str, *, cluster_id: str | None = None
) -> ResponseCommand:
    """The responder's confirmation call ("applied" / "failed" /
    "released") -- see the build plan's confirmation + reversal flow,
    Phase 1. Not for requesting a release -- see `request_release`, which
    enforces that only an "applied" command can be released."""
    if status not in COMMAND_STATUSES:
        raise UnknownCommandStatus(f"Unknown command status {status!r}, expected one of {COMMAND_STATUSES}")

    command = _get_command(session, command_id, cluster_id=cluster_id)
    command.status = status
    command.updated_at = _now()
    return command


def request_release(session: Session, command_id: str, *, cluster_id: str | None = None) -> ResponseCommand:
    """The human-triggered reversal the build plan calls for: an operator
    releasing an isolation. Only valid from "applied" -- a command that
    never got applied (still "pending", or "failed") has nothing to
    reverse -- and only for `RELEASABLE_ACTIONS` -- a kill_process command
    has nothing to reverse either, just further along. The responder
    picks up "release_pending" on its next poll, deletes the
    NetworkPolicy, and reports back "released" via `update_command_status`."""
    command = _get_command(session, command_id, cluster_id=cluster_id)
    if command.action not in RELEASABLE_ACTIONS:
        raise InvalidCommandTransition(f"{command.action!r} commands cannot be released -- nothing to reverse")
    if command.status != "applied":
        raise InvalidCommandTransition(
            f"Cannot release a command in status {command.status!r} -- only an 'applied' command can be released"
        )

    command.status = "release_pending"
    command.updated_at = _now()
    return command
