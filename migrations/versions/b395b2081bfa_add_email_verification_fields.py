"""Add email verification fields

Revision ID: b395b2081bfa
Revises: 98675f43c0ac
Create Date: 2026-01-01 18:49:57.111517

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b395b2081bfa'
down_revision = '98675f43c0ac'
branch_labels = None
depends_on = None

def upgrade():
    # Only modify the user table (security_event already has email_masked in your DB)
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'email_verified',
                sa.Boolean(),
                nullable=False,
                server_default=sa.text('0')  # 0 = False
            )
        )
        batch_op.add_column(sa.Column('email_verified_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('email_verified_at')
        batch_op.drop_column('email_verified')
