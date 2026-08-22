"""CRUD for the coverage table (coverage_models.py). Same session-passing
convention as containment_store.py -- every function takes an explicit
`Session`, callers own the transaction boundary.

The build plan's whole reason for this module existing: on EKS, the
default VPC CNI does not enforce Kubernetes NetworkPolicy at all unless
explicitly configured to. Without something that actually tests this, "we
applied an isolation NetworkPolicy" and "that pod is actually isolated"
are two different claims that can silently diverge -- a cluster can look
fully covered in the dashboard while Tier 1 does nothing at all. This
module is what keeps those claims distinct: `network_policy_enforcement`
is never assumed from Tier 1 being configured, only ever written by an
actual test result (see the daily canary CronJob in
responder_install_script.py).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .coverage_models import AwsAccountCoverage, ClusterCoverage

NETWORK_POLICY_STATUSES = ("verified", "failed")
FALCO_DAEMONSET_STATUSES = ("healthy", "degraded", "unknown")
CAPABILITY_STATUSES = ("verified", "failed")
ASSUME_ROLE_STATUSES = ("verified", "failed")


class UnknownCoverageStatus(ValueError):
    pass


class InvalidAccountId(ValueError):
    """Raised for anything that doesn't look like a real 12-digit AWS
    account id -- catches an obvious typo in a registration call before it
    becomes a row iam-responder tries and fails to make sense of."""


def _now() -> datetime:
    return datetime.now(UTC)


def _get_or_create(session: Session, cluster_id: str) -> ClusterCoverage:
    coverage = session.get(ClusterCoverage, cluster_id)
    if coverage is None:
        coverage = ClusterCoverage(cluster_id=cluster_id, updated_at=_now())
        session.add(coverage)
    return coverage


def record_responder_heartbeat(session: Session, cluster_id: str) -> ClusterCoverage:
    """Called on every successful responder poll (see main.py's
    list_runtime_cluster_commands) -- the cheapest coverage signal there
    is, since the responder already has to poll regularly for every
    containment tier to function at all."""
    coverage = _get_or_create(session, cluster_id)
    now = _now()
    coverage.responder_last_seen_at = now
    coverage.updated_at = now
    return coverage


def report_network_policy_enforcement(session: Session, cluster_id: str, status: str) -> ClusterCoverage:
    """The daily canary test's result. Deliberately only two possible
    values, not three: "the deny-all policy actually blocked traffic" or
    it didn't -- and a canary run that couldn't even reach a clean
    conclusion (pods never came up, the pre-policy connectivity check
    itself failed) reports "failed" too, on purpose. Whether enforcement
    is genuinely broken or the test environment is, the operator-facing
    conclusion is identical either way: don't rely on isolation working
    on this cluster yet. The default "unverified" (see
    coverage_models.ClusterCoverage) is reserved for "never tested",
    which this function never reports -- only the daily job's own
    initial silence (no report received yet) leaves a cluster there."""
    if status not in NETWORK_POLICY_STATUSES:
        raise UnknownCoverageStatus(
            f"Unknown network policy status {status!r}, expected one of {NETWORK_POLICY_STATUSES}"
        )

    coverage = _get_or_create(session, cluster_id)
    now = _now()
    coverage.network_policy_enforcement = status
    coverage.network_policy_checked_at = now
    coverage.updated_at = now
    return coverage


def report_falco_daemonset_health(
    session: Session, cluster_id: str, status: str, *, ready: int | None = None, desired: int | None = None
) -> ClusterCoverage:
    """Reported every poll cycle (unlike the throttled network-policy
    canary) -- a plain DaemonSet status read has no CNI-style
    silent-failure mode and no blast radius, so there's no reason to
    delay surfacing Falco going down on some fraction of a cluster's
    nodes."""
    if status not in FALCO_DAEMONSET_STATUSES:
        raise UnknownCoverageStatus(f"Unknown Falco status {status!r}, expected one of {FALCO_DAEMONSET_STATUSES}")

    coverage = _get_or_create(session, cluster_id)
    now = _now()
    coverage.falco_daemonset_status = status
    coverage.falco_daemonset_ready = ready
    coverage.falco_daemonset_desired = desired
    coverage.falco_checked_at = now
    coverage.updated_at = now
    return coverage


def report_kill_process_capability(session: Session, cluster_id: str, status: str) -> ClusterCoverage:
    """`kubectl auth can-i delete pods` -- a non-destructive RBAC presence
    check, not a synthetic test against a real workload. There's no
    equivalent of the network-policy canary's CNI-enforcement gap here:
    if the verb is granted, kill_process's single `kubectl delete pod`
    call works, full stop."""
    if status not in CAPABILITY_STATUSES:
        raise UnknownCoverageStatus(f"Unknown capability status {status!r}, expected one of {CAPABILITY_STATUSES}")

    coverage = _get_or_create(session, cluster_id)
    now = _now()
    coverage.kill_process_capability = status
    coverage.kill_process_checked_at = now
    coverage.updated_at = now
    return coverage


def report_quarantine_node_capability(session: Session, cluster_id: str, status: str) -> ClusterCoverage:
    """`kubectl auth can-i patch nodes` -- same non-destructive shape as
    report_kill_process_capability. Deliberately never tests against a
    real node (no actual cordon/taint) -- unlike a throwaway canary pod,
    a real node can't be safely used as disposable test material."""
    if status not in CAPABILITY_STATUSES:
        raise UnknownCoverageStatus(f"Unknown capability status {status!r}, expected one of {CAPABILITY_STATUSES}")

    coverage = _get_or_create(session, cluster_id)
    now = _now()
    coverage.quarantine_node_capability = status
    coverage.quarantine_node_checked_at = now
    coverage.updated_at = now
    return coverage


def get_cluster_coverage(session: Session, cluster_id: str) -> ClusterCoverage | None:
    return session.get(ClusterCoverage, cluster_id)


def list_cluster_coverage(session: Session) -> list[ClusterCoverage]:
    """The fleet-wide capability matrix a dashboard renders -- every
    cluster's coverage row, not scoped to one cluster. Unlike
    containment_store.list_commands_for_iam_component, there's no
    privilege-separation reason this needs restricting: coverage state
    isn't actionable the way a containment command is, it's read-only
    fleet visibility, which is exactly what an operator dashboard needs
    regardless of which single cluster's token happens to be handy."""
    return list(session.scalars(select(ClusterCoverage).order_by(ClusterCoverage.cluster_id)))


# ---- AWS account coverage (Tier 4 only) ------------------------------


def register_aws_account(session: Session, account_id: str) -> AwsAccountCoverage:
    """An operator's explicit "start tracking this account" call --
    there's no way to auto-discover which accounts should have a
    golem-iam-responder trust relationship, so this has to be a
    deliberate registration, not passive discovery from incidents
    already seen (which would mean an account's cross-account trust
    goes untested until the first real revoke_iam incident needs it --
    exactly the failure mode this whole coverage system exists to
    avoid). Idempotent: registering an already-registered account is a
    no-op, not an error."""
    if not account_id.isdigit() or len(account_id) != 12:
        raise InvalidAccountId(f"{account_id!r} is not a 12-digit AWS account id")

    account = session.get(AwsAccountCoverage, account_id)
    if account is None:
        # assume_role_status is set explicitly here rather than left to
        # the column's ORM-level default -- that default only gets
        # applied to the in-memory object at flush/commit time, and the
        # API route that calls this returns to_dict() of the object
        # within the same still-open session, before either happens.
        account = AwsAccountCoverage(account_id=account_id, assume_role_status="unverified", updated_at=_now())
        session.add(account)
    return account


def report_aws_account_assume_role(session: Session, account_id: str, status: str) -> AwsAccountCoverage:
    """iam-responder/'s own periodic sweep result -- the only component
    that can ever call this, since it's the only thing with AWS
    credentials to attempt the assumption with in the first place."""
    if status not in ASSUME_ROLE_STATUSES:
        raise UnknownCoverageStatus(f"Unknown assume-role status {status!r}, expected one of {ASSUME_ROLE_STATUSES}")

    account = session.get(AwsAccountCoverage, account_id)
    if account is None:
        raise InvalidAccountId(f"AWS account {account_id!r} was never registered")

    now = _now()
    account.assume_role_status = status
    account.checked_at = now
    account.updated_at = now
    return account


def list_aws_account_coverage(session: Session) -> list[AwsAccountCoverage]:
    return list(session.scalars(select(AwsAccountCoverage).order_by(AwsAccountCoverage.account_id)))
