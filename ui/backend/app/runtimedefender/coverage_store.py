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

from .coverage_models import ClusterCoverage

NETWORK_POLICY_STATUSES = ("verified", "failed")


class UnknownCoverageStatus(ValueError):
    pass


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
