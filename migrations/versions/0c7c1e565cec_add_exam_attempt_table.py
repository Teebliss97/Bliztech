"""add exam_attempt table

Revision ID: 0c7c1e565cec
Revises: cc896c1dac53
Create Date: 2026-04-08 23:21:19.828003

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c7c1e565cec'
down_revision = 'cc896c1dac53'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'exam_attempt',
        sa.Column('id',           sa.Integer(),     nullable=False),
        sa.Column('user_id',      sa.Integer(),     nullable=False),
        sa.Column('exam_set',     sa.String(64),    nullable=False),
        sa.Column('score_pct',    sa.Integer(),     nullable=False),
        sa.Column('correct',      sa.Integer(),     nullable=False),
        sa.Column('total',        sa.Integer(),     nullable=False),
        sa.Column('passed',       sa.Boolean(),     nullable=False),
        sa.Column('elapsed_secs', sa.Integer(),     nullable=True),
        sa.Column('completed_at', sa.DateTime(),    nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fk_exam_attempt_user_id'),
        sa.PrimaryKeyConstraint('id', name='pk_exam_attempt'),
    )
    op.create_index('ix_exam_attempt_user_id', 'exam_attempt', ['user_id'], unique=False)


def downgrade():
    op.drop_index('ix_exam_attempt_user_id', table_name='exam_attempt')
    op.drop_table('exam_attempt')