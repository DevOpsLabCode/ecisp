"""ORM model for the containment build plan's Phase 2: per-cluster
coverage signals, so "response tiers are wired up" and "response tiers
are actually proven to work on this specific cluster" stay two different,
separately-tracked facts. See coverage_store.py.

One row per cluster, upserted in place -- unlike ResponseCommand (one row
per incident), there's exactly one current coverage state per cluster,
not a history of them. A verified-then-regressed cluster overwrites its
own row rather than accumulating one; if a coverage history/timeline
becomes valuable later, that's a different table, not a retrofit of this
one.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ClusterCoverage(Base):
    __tablename__ = "cluster_coverage"

    cluster_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Updated on every successful GET .../commands poll (main.py) -- the
    # cheapest possible signal, since the responder already has to poll
    # regularly for containment to work at all. A cluster whose
    # responder_last_seen_at is stale is one where every tier above is
    # silently non-functional, not just unverified.
    responder_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # "unverified" (the default -- never tested), "verified" (the daily
    # canary test's deny-all policy actually blocked traffic), "failed"
    # (it didn't -- or the test itself couldn't run to a clean
    # conclusion; see coverage_store.py's report_network_policy_enforcement
    # docstring for why those two cases are deliberately not
    # distinguished further).
    network_policy_enforcement: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    network_policy_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # "healthy" (every Falco DaemonSet pod ready), "degraded" (some
    # nodes aren't), "unknown" (the check itself couldn't run -- Falco
    # not installed under the expected falco/falco name, or the
    # responder's own read failed). Checked every poll cycle -- a
    # DaemonSet status read is cheap, and Falco going down mid-day is
    # worth surfacing quickly, unlike the deliberately-throttled,
    # actually-disruptive network policy canary.
    falco_daemonset_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    falco_daemonset_ready: Mapped[int | None] = mapped_column(nullable=True)
    falco_daemonset_desired: Mapped[int | None] = mapped_column(nullable=True)
    falco_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Non-destructive `kubectl auth can-i` RBAC presence checks, not
    # synthetic tests against a real workload/node the way the network
    # policy canary is -- there's no CNI-style silent-gap risk for a plain
    # RBAC grant the way there is for NetworkPolicy enforcement, so
    # confirming the verb is actually granted is enough to call the
    # capability verified. "unverified" (never checked), "verified"
    # (can-i said yes), "failed" (can-i said no -- RBAC drifted or was
    # never granted for this specific cluster's responder).
    kill_process_capability: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    kill_process_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    quarantine_node_capability: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    quarantine_node_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "responder_last_seen_at": self.responder_last_seen_at.isoformat()
            if self.responder_last_seen_at
            else None,
            "network_policy_enforcement": self.network_policy_enforcement,
            "network_policy_checked_at": self.network_policy_checked_at.isoformat()
            if self.network_policy_checked_at
            else None,
            "falco_daemonset_status": self.falco_daemonset_status,
            "falco_daemonset_ready": self.falco_daemonset_ready,
            "falco_daemonset_desired": self.falco_daemonset_desired,
            "falco_checked_at": self.falco_checked_at.isoformat() if self.falco_checked_at else None,
            "kill_process_capability": self.kill_process_capability,
            "kill_process_checked_at": self.kill_process_checked_at.isoformat()
            if self.kill_process_checked_at
            else None,
            "quarantine_node_capability": self.quarantine_node_capability,
            "quarantine_node_checked_at": self.quarantine_node_checked_at.isoformat()
            if self.quarantine_node_checked_at
            else None,
            "updated_at": self.updated_at.isoformat(),
        }


class AwsAccountCoverage(Base):
    """The revoke_iam equivalent of ClusterCoverage -- but keyed by AWS
    account, not cluster_id, since Tier 4's capability is a property of
    the cross-account trust relationship in a given account, not of any
    one cluster (a single account can hold roles used by workloads across
    several clusters, and revoke_iam resolves its target account
    dynamically per-incident, from whatever role ARN a finding names --
    there's no static cluster-to-account mapping in this schema to hang
    this off of instead).

    Populated exclusively by iam-responder/ -- the only component with
    AWS credentials at all, and the only thing that can actually attempt
    the cross-account assume-role this checks. The in-cluster responder
    has no way to verify this and never tries."""

    __tablename__ = "aws_account_coverage"

    account_id: Mapped[str] = mapped_column(String(12), primary_key=True)
    # "unverified" (never attempted), "verified" (assumed the role and
    # confirmed IAM access in that account -- see
    # iam-responder/app/coverage_check.py), "failed" (assumption or the
    # follow-up IAM call didn't work -- the account's golem-iam-responder
    # trust policy is missing, misconfigured, or was revoked).
    assume_role_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unverified")
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "assume_role_status": self.assume_role_status,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
            "updated_at": self.updated_at.isoformat(),
        }
