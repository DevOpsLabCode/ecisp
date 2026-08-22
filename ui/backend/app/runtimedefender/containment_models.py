"""ORM models for the two tables the containment build plan's Phase 0
introduces. Neither has an in-memory equivalent to migrate away from --
`RuntimeCluster`/`RuntimeDefenderManager` (see `runtime_defender.py`) keep
their existing in-memory design unchanged, since these are genuinely new
concepts Phase 1 needs, not a persistence upgrade of something that already
worked.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ResponseRule(Base):
    """The Phase 1 opt-in mechanism: a Falco rule ID mapped to a response
    action. A rule with no row here -- the default, and expected to stay
    true for the vast majority of rules -- only ever alerts, exactly as
    Runtime Defender does today. See the build plan's rule-to-response
    pipeline, step 1."""

    __tablename__ = "response_rules"

    rule_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class ResponseCommand(Base):
    """One containment action queued for exactly one cluster. The
    in-cluster responder (Phase 1's next piece, not yet built) will
    long-poll for commands scoped to its own `cluster_id` only -- see the
    architecture diagram in the containment build plan for why the backend
    never reaches into a cluster directly."""

    __tablename__ = "response_commands"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cluster_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    namespace: Mapped[str] = mapped_column(String(255), nullable=False)
    pod_name: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    # Lets the same underlying detection re-fire without double-queuing a
    # second isolation command for a pod that's already being handled --
    # see the build plan's confirmation/reversal flow.
    idempotency_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    # Only meaningful for RETRYABLE_ACTIONS (containment_store.py) --
    # quarantine_node's cordon/taint/delete chain can fail partway through
    # (e.g. cordon succeeds, taint doesn't), and every step in that chain
    # is safely re-runnable, so a bounded number of automatic retries is
    # cheaper and more reliable than reporting "failed" on the first
    # transient error. See update_command_status.
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Only ever set for action="revoke_iam": the IRSA role ARN the
    # in-cluster responder resolved from the pod's ServiceAccount. The
    # in-cluster responder resolves it (plain Kubernetes read, no AWS
    # access); the separate IAM-revocation component is the only thing
    # that ever acts on it -- see containment_store.py's privilege-
    # separation notes and the containment build plan's architecture
    # diagram (no line between the in-cluster responder and the IAM
    # component).
    resolved_role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cluster_id": self.cluster_id,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "action": self.action,
            "status": self.status,
            "attempts": self.attempts,
            "resolved_role_arn": self.resolved_role_arn,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
