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
            "updated_at": self.updated_at.isoformat(),
        }
