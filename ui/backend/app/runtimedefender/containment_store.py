"""CRUD for the containment tables (`containment_models.py`). Every
function takes an explicit `Session` rather than opening its own -- callers
own the transaction boundary (an API route commits once per request via
`db.session_scope()`; a test commits once per assertion), which keeps this
module a plain function library instead of a second place session lifetime
gets decided.

No HTTP routes call into this yet -- that's the in-cluster responder work
that follows Phase 0 (see the containment build plan). This module is the
storage foundation that work builds on, kept independently testable now.
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
COMMAND_STATUSES = ("pending", "applied", "failed", "released")


class UnknownResponseAction(ValueError):
    pass


class UnknownCommandStatus(ValueError):
    pass


class CommandNotFound(LookupError):
    pass


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


def update_command_status(session: Session, command_id: str, status: str) -> ResponseCommand:
    """The responder's confirmation call ("applied" / "failed") and an
    operator's explicit reversal ("released") both land here -- see the
    build plan's confirmation + reversal flow, Phase 1."""
    if status not in COMMAND_STATUSES:
        raise UnknownCommandStatus(f"Unknown command status {status!r}, expected one of {COMMAND_STATUSES}")

    command = session.get(ResponseCommand, command_id)
    if command is None:
        raise CommandNotFound(f"No response command with id {command_id!r}")

    command.status = status
    command.updated_at = _now()
    return command
