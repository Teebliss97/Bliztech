"""Add referrals

Revision ID: ca794b05ffba
Revises: b395b2081bfa
Create Date: 2026-01-20 20:38:16.159663

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = 'ca794b05ffba'
down_revision = 'b395b2081bfa'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = inspect(bind)

    # -------------------------
    # 1) referrals table (create only if missing)
    # -------------------------
    existing_tables = set(insp.get_table_names())

    if "referrals" not in existing_tables:
        op.create_table(
            'referrals',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('referrer_id', sa.Integer(), nullable=False),
            sa.Column('referred_user_id', sa.Integer(), nullable=False),
            sa.Column('referral_code_used', sa.String(length=32), nullable=True),
            sa.Column('source', sa.String(length=50), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['referred_user_id'], ['user.id']),
            sa.ForeignKeyConstraint(['referrer_id'], ['user.id']),
            sa.PrimaryKeyConstraint('id'),
        )

    # Create indexes if missing (safe checks)
    if "referrals" in set(insp.get_table_names()):
        existing_indexes = {ix["name"] for ix in insp.get_indexes("referrals")}

        if "ix_referrals_created_at" not in existing_indexes:
            op.create_index("ix_referrals_created_at", "referrals", ["created_at"], unique=False)
        if "ix_referrals_referral_code_used" not in existing_indexes:
            op.create_index("ix_referrals_referral_code_used", "referrals", ["referral_code_used"], unique=False)
        if "ix_referrals_referred_user_id" not in existing_indexes:
            op.create_index("ix_referrals_referred_user_id", "referrals", ["referred_user_id"], unique=True)
        if "ix_referrals_referrer_id" not in existing_indexes:
            op.create_index("ix_referrals_referrer_id", "referrals", ["referrer_id"], unique=False)

    # -------------------------
    # 2) user table columns (add only if missing)
    # -------------------------
    if "user" in existing_tables:
        user_cols = {c["name"] for c in insp.get_columns("user")}
        user_indexes = {ix["name"] for ix in insp.get_indexes("user")}
        user_fks = insp.get_foreign_keys("user")

        # Add columns
        if "referral_code" not in user_cols:
            op.add_column("user", sa.Column("referral_code", sa.String(length=32), nullable=True))

        if "referred_by_id" not in user_cols:
            op.add_column("user", sa.Column("referred_by_id", sa.Integer(), nullable=True))

        # Add indexes
        if "ix_user_referral_code" not in user_indexes:
            op.create_index("ix_user_referral_code", "user", ["referral_code"], unique=True)

        if "ix_user_referred_by_id" not in user_indexes:
            op.create_index("ix_user_referred_by_id", "user", ["referred_by_id"], unique=False)

def downgrade():
    bind = op.get_bind()
    insp = inspect(bind)
    existing_tables = set(insp.get_table_names())

    # 1) user table cleanup
    if "user" in existing_tables:
        user_cols = {c["name"] for c in insp.get_columns("user")}
        user_indexes = {ix["name"] for ix in insp.get_indexes("user")}
        user_fks = insp.get_foreign_keys("user")

        # Drop FK (if exists)
        for fk in user_fks:
            if fk.get("constrained_columns") == ["referred_by_id"] and fk.get("referred_table") == "user":
                # sqlite may not always give a name; we used a name above
                try:
                    op.drop_constraint("fk_user_referred_by_id_user", "user", type_="foreignkey")
                except Exception:
                    pass
                break

        # Drop indexes
        if "ix_user_referred_by_id" in user_indexes:
            op.drop_index("ix_user_referred_by_id", table_name="user")
        if "ix_user_referral_code" in user_indexes:
            op.drop_index("ix_user_referral_code", table_name="user")

        # Drop columns
        if "referred_by_id" in user_cols:
            op.drop_column("user", "referred_by_id")
        if "referral_code" in user_cols:
            op.drop_column("user", "referral_code")

    # 2) referrals table cleanup
    if "referrals" in existing_tables:
        referrals_indexes = {ix["name"] for ix in insp.get_indexes("referrals")}
        if "ix_referrals_referrer_id" in referrals_indexes:
            op.drop_index("ix_referrals_referrer_id", table_name="referrals")
        if "ix_referrals_referred_user_id" in referrals_indexes:
            op.drop_index("ix_referrals_referred_user_id", table_name="referrals")
        if "ix_referrals_referral_code_used" in referrals_indexes:
            op.drop_index("ix_referrals_referral_code_used", table_name="referrals")
        if "ix_referrals_created_at" in referrals_indexes:
            op.drop_index("ix_referrals_created_at", table_name="referrals")

        op.drop_table("referrals")
