"""add step-up challenge

Revision ID: 83d26b5634e0
Revises: aa919f815781
Create Date: 2026-01-05 13:26:29.389160
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '83d26b5634e0'
down_revision: Union[str, Sequence[str], None] = 'aa919f815781'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add new value to existing PostgreSQL enum
    op.execute("ALTER TYPE challengetype ADD VALUE IF NOT EXISTS 'STEPUP'")


def downgrade() -> None:
    """Downgrade schema."""
    # PostgreSQL does NOT support removing enum values directly.
    # We must recreate the enum without STEPUP.

    op.execute("""
        ALTER TYPE challengetype RENAME TO challengetype_old;
    """)

    sa.Enum(
        'LOGIN',
        'RENEW',
        name='challengetype'
    ).create(op.get_bind())

    op.execute("""
        ALTER TABLE challenges
        ALTER COLUMN type
        TYPE challengetype
        USING type::text::challengetype;
    """)

    op.execute("DROP TYPE challengetype_old")
