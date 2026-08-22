"""add attempts to response_commands

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-22 08:25:13.366296

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: str | Sequence[str] | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default backfills any pre-existing rows (a NOT NULL column
    # added with no default would fail outright on a populated table).
    # Left in place rather than dropped afterward -- SQLite (the local
    # dev/test default, see app/db.py) can't ALTER COLUMN ... DROP DEFAULT
    # without a full table rebuild, and the column-level default is inert
    # in practice anyway: every real insert goes through the ORM, which
    # always supplies its own `default=0` (containment_models.py).
    op.add_column(
        'response_commands', sa.Column('attempts', sa.Integer(), nullable=False, server_default='0')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('response_commands', 'attempts')
