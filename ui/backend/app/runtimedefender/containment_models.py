"""ORM models for the two tables the containment build plan's Phase 0
introduces. Neither has an in-memory equivalent to migrate away from --
`RuntimeCluster`/`RuntimeDefenderManager` (see `runtime_defender.py`) keep
their existing in-memory design unchanged, since these are genuinely new
concepts Phase 1 needs, not a persistence upgrade of something that already
worked.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
