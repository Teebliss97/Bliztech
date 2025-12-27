"""fix is_admin default

Revision ID: f0059c2dcce9
Revises: 1228cd992907
Create Date: 2025-12-27 01:17:47.149037

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "f0059c2dcce9"
down_revision = "1228cd992907"
branch_labels = None
depends_on = None


def upgrade():
    # 1) Backfill any existing rows (important if column was ever created nullable=True or DB has NULLs)
    op.execute('UPDATE "user" SET is_admin = FALSE WHERE is_admin IS NULL')

    # 2) Ensure the column has a server default and is NOT NULL going forward
    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column(
            "is_admin",
            existing_type=sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        )


def downgrade():
    # Remove server default (keep column)
    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column(
            "is_admin",
            existing_type=sa.Boolean(),
            nullable=False,
            server_default=None,
        )
