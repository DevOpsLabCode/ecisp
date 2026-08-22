"""add cluster_coverage table

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-22 09:18:17.855975

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0004'
down_revision: str | Sequence[str] | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # A brand new table, not a column added to an already-populated one --
    # no backfill concern here the way 0002's `attempts` had.
    op.create_table(
        'cluster_coverage',
        sa.Column('cluster_id', sa.String(length=64), nullable=False),
        sa.Column('responder_last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('network_policy_enforcement', sa.String(length=16), nullable=False),
        sa.Column('network_policy_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('cluster_id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('cluster_coverage')
