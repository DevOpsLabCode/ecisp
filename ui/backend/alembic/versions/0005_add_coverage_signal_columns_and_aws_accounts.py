"""add coverage signal columns and aws account coverage

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-22 09:39:13.345831

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0005'
down_revision: str | Sequence[str] | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'aws_account_coverage',
        sa.Column('account_id', sa.String(length=12), nullable=False),
        sa.Column('assume_role_status', sa.String(length=16), nullable=False),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('account_id'),
    )
    # server_default backfills pre-existing cluster_coverage rows (created
    # by any signal report since migration 0004) on these three new NOT
    # NULL columns -- same reasoning as 0002's `attempts` column: matches
    # the ORM's own Python-side default, and is left in place rather than
    # dropped afterward since SQLite can't ALTER COLUMN ... DROP DEFAULT
    # and every real insert goes through the ORM default anyway.
    op.add_column(
        'cluster_coverage',
        sa.Column('falco_daemonset_status', sa.String(length=16), nullable=False, server_default='unknown'),
    )
    op.add_column('cluster_coverage', sa.Column('falco_daemonset_ready', sa.Integer(), nullable=True))
    op.add_column('cluster_coverage', sa.Column('falco_daemonset_desired', sa.Integer(), nullable=True))
    op.add_column('cluster_coverage', sa.Column('falco_checked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'cluster_coverage',
        sa.Column('kill_process_capability', sa.String(length=16), nullable=False, server_default='unverified'),
    )
    op.add_column('cluster_coverage', sa.Column('kill_process_checked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'cluster_coverage',
        sa.Column('quarantine_node_capability', sa.String(length=16), nullable=False, server_default='unverified'),
    )
    op.add_column(
        'cluster_coverage', sa.Column('quarantine_node_checked_at', sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cluster_coverage', 'quarantine_node_checked_at')
    op.drop_column('cluster_coverage', 'quarantine_node_capability')
    op.drop_column('cluster_coverage', 'kill_process_checked_at')
    op.drop_column('cluster_coverage', 'kill_process_capability')
    op.drop_column('cluster_coverage', 'falco_checked_at')
    op.drop_column('cluster_coverage', 'falco_daemonset_desired')
    op.drop_column('cluster_coverage', 'falco_daemonset_ready')
    op.drop_column('cluster_coverage', 'falco_daemonset_status')
    op.drop_table('aws_account_coverage')
