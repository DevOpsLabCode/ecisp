"""add resolved_role_arn to response_commands

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-22 08:50:52.540445

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0003'
down_revision: str | Sequence[str] | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable -- only ever set for action="revoke_iam", and only once the
    # in-cluster responder has resolved a role ARN (see
    # containment_store.resolve_iam_role). No backfill concern here, unlike
    # 0002's `attempts`.
    op.add_column('response_commands', sa.Column('resolved_role_arn', sa.String(length=512), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('response_commands', 'resolved_role_arn')
