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

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .containment_models import ResponseCommand, ResponseRule

# "log_only" is deliberately not enqueueable -- it exists so a rule can be
# marked reviewed-and-intentionally-alert-only in the same table, without a
# separate on/off flag. See the build plan's curated rule->response table.
RESPONSE_ACTIONS = ("isolate_network", "kill_process", "quarantine_node", "revoke_iam", "log_only")
ENQUEUEABLE_ACTIONS = tuple(a for a in RESPONSE_ACTIONS if a != "log_only")
# "release_pending" sits between an operator clicking Release and a
# responder actually reversing the action -- the in-cluster responder (for
# isolate_network) or the IAM-revocation component (for revoke_iam) polls
# for it the same way it polls for its own applicable pending state, then
# reports back "released". "role_resolved" is revoke_iam-only: the point
# where the in-cluster responder has handed off to the IAM component (see
# resolve_iam_role) but that component hasn't acted yet.
COMMAND_STATUSES = ("pending", "role_resolved", "applied", "failed", "release_pending", "released")
# Actions the in-cluster responder owns end to end (apply AND, where
# releasable, reverse) using only its Kubernetes RBAC -- no AWS access,
# ever. revoke_iam's "pending" state is still visible to it (it resolves
# the role ARN), but its "release_pending" state is not: reversing an IAM
# deny-policy needs AWS credentials the in-cluster responder must never
# hold. See the build plan's architecture diagram (no line between the
# in-cluster responder and the IAM component).
IN_CLUSTER_RESPONDER_ACTIONS = ("isolate_network", "kill_process", "quarantine_node")
# isolate_network's NetworkPolicy and revoke_iam's deny-policy are both
# clean, reversible actions -- unlike kill_process/quarantine_node, which
# remove the offending process, there's nothing to "undo" once it's gone.
RELEASABLE_ACTIONS = ("isolate_network", "revoke_iam")
# quarantine_node's cordon/taint/delete chain runs as three separate
# kubectl calls, and every one of them is safely re-runnable (cordon and
# `taint --overwrite` are no-ops if already applied; delete tolerates an
# already-gone pod) -- so a transient failure partway through is worth
# retrying automatically rather than reporting "failed" on the first
# attempt. isolate_network and kill_process are single kubectl calls each;
# there's no partial state to retry into, so they stay report-once.
RETRYABLE_ACTIONS = ("quarantine_node",)
MAX_APPLY_ATTEMPTS = 5


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
    # "role_resolved" is included alongside "pending" here -- a revoke_iam
    # command sits in that state while waiting on the separate IAM
    # component, and a Falco rule re-firing during that window shouldn't
    # queue a second attempt at revoking the same role.
    existing = session.scalars(
        select(ResponseCommand).where(
            ResponseCommand.idempotency_key == key, ResponseCommand.status.in_(("pending", "role_resolved"))
        )
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
    """What the in-cluster responder's poll loop actually fetches, scoped
    to its own cluster: every "pending" command regardless of action
    (including revoke_iam, which it only resolves a role ARN for -- see
    resolve_iam_role -- never applies), plus "release_pending" *only* for
    actions it's directly responsible for reversing
    (`IN_CLUSTER_RESPONDER_ACTIONS`). A revoke_iam release_pending command
    is deliberately never returned here -- that's the separate
    IAM-revocation component's job (`list_commands_for_iam_component`),
    and the in-cluster responder has no AWS credentials to act on it with
    even if it saw one."""
    stmt = (
        select(ResponseCommand)
        .where(
            ResponseCommand.cluster_id == cluster_id,
            or_(
                ResponseCommand.status == "pending",
                and_(
                    ResponseCommand.status == "release_pending",
                    ResponseCommand.action.in_(IN_CLUSTER_RESPONDER_ACTIONS),
                ),
            ),
        )
        .order_by(ResponseCommand.created_at)
    )
    return list(session.scalars(stmt))


def resolve_iam_role(
    session: Session, command_id: str, role_arn: str, *, cluster_id: str | None = None
) -> ResponseCommand:
    """The in-cluster responder's handoff for a revoke_iam command: it has
    read the target pod's ServiceAccount and resolved the IRSA role ARN
    from its `eks.amazonaws.com/role-arn` annotation using nothing but its
    existing Kubernetes RBAC, and now hands that ARN to the separate
    IAM-revocation component by moving the command to "role_resolved" --
    the in-cluster responder's role in Tier 4 ends here. Only valid from
    "pending" on a revoke_iam command."""
    command = _get_command(session, command_id, cluster_id=cluster_id)
    if command.action != "revoke_iam":
        raise InvalidCommandTransition(f"{command.action!r} commands have no IAM role to resolve")
    if command.status != "pending":
        raise InvalidCommandTransition(f"Cannot resolve a role for a command in status {command.status!r}")

    command.resolved_role_arn = role_arn
    command.status = "role_resolved"
    command.updated_at = _now()
    return command


def list_commands_for_iam_component(session: Session) -> list[ResponseCommand]:
    """What the separate IAM-revocation component polls: every
    "role_resolved" command (ready to have its deny-policy applied) and
    every revoke_iam "release_pending" command (ready to have that policy
    removed), across the *entire* fleet -- not scoped to one cluster_id,
    unlike every other list function in this module. That's deliberate:
    the IAM component authenticates with its own fleet-wide credential,
    entirely separate from any cluster's install token (see main.py), so
    it seeing every cluster's revoke_iam commands doesn't widen what a
    compromised in-cluster responder could ever reach -- it has no path to
    this credential at all."""
    stmt = (
        select(ResponseCommand)
        .where(
            or_(
                ResponseCommand.status == "role_resolved",
                and_(ResponseCommand.status == "release_pending", ResponseCommand.action == "revoke_iam"),
            )
        )
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
    enforces that only an "applied" command can be released.

    A "failed" report for a `RETRYABLE_ACTIONS` command doesn't go
    terminal immediately: it increments `attempts` and leaves `status`
    untouched (still "pending"), so the responder's next poll picks the
    same command back up and retries the whole chain -- safe, because
    every step of it is idempotent. Only once `attempts` reaches
    `MAX_APPLY_ATTEMPTS` does it actually become "failed", so a genuinely
    broken cluster (bad RBAC, API server down) still surfaces rather than
    retrying silently forever."""
    if status not in COMMAND_STATUSES:
        raise UnknownCommandStatus(f"Unknown command status {status!r}, expected one of {COMMAND_STATUSES}")

    command = _get_command(session, command_id, cluster_id=cluster_id)

    if status == "failed" and command.action in RETRYABLE_ACTIONS:
        command.attempts += 1
        command.updated_at = _now()
        if command.attempts >= MAX_APPLY_ATTEMPTS:
            command.status = "failed"
        return command

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
