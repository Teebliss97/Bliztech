"""Add email verification fields

Revision ID: b395b2081bfa
Revises: 98675f43c0ac
Create Date: 2026-01-01 18:49:57.111517
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "b395b2081bfa"
down_revision = "98675f43c0ac"
branch_labels = None
depends_on = None


def upgrade():
    # --- security_event: add email_masked (nullable) ---
    with op.batch_alter_table("security_event", schema=None) as batch_op:
        # Only add if it doesn't exist (safe for re-runs / weird local states)
        # NOTE: Alembic doesn't support IF NOT EXISTS cleanly across DBs, so keep it simple.
        batch_op.add_column(sa.Column("email_masked", sa.String(length=255), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_security_event_email_masked"),
            ["email_masked"],
            unique=False,
        )

    # --- user: add email verification fields ---
    with op.batch_alter_table("user", schema=None) as batch_op:
        # IMPORTANT for Postgres:
        # boolean default must be true/false, not 0/1
        batch_op.add_column(
            sa.Column(
                "email_verified",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            )
        )
        batch_op.add_column(sa.Column("email_verified_at", sa.DateTime(), nullable=True))

    # Optional: remove server default after existing rows are set (cleaner schema)
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.alter_column("email_verified", server_default=None)


def downgrade():
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("email_verified_at")
        batch_op.drop_column("email_verified")

    with op.batch_alter_table("security_event", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_security_event_email_masked"))
        batch_op.drop_column("email_masked")
