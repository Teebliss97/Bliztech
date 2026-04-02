"""add lesson_read and quiz_attempt

Revision ID: a1b2c3d4e5f6
Revises: 13f245c9de96
Create Date: 2026-04-02 01:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '13f245c9de96'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('lesson_read',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('slug', sa.String(length=80), nullable=False),
    sa.Column('read_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'slug', name='uq_lesson_read_user_slug')
    )
    with op.batch_alter_table('lesson_read', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_lesson_read_slug'), ['slug'], unique=False)
        batch_op.create_index(batch_op.f('ix_lesson_read_user_id'), ['user_id'], unique=False)

    op.create_table('quiz_attempt',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('score', sa.Integer(), nullable=False),
    sa.Column('total', sa.Integer(), nullable=False),
    sa.Column('passed', sa.Boolean(), nullable=False),
    sa.Column('attempted_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('quiz_attempt', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_quiz_attempt_attempted_at'), ['attempted_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_quiz_attempt_user_id'), ['user_id'], unique=False)


def downgrade():
    with op.batch_alter_table('quiz_attempt', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_quiz_attempt_user_id'))
        batch_op.drop_index(batch_op.f('ix_quiz_attempt_attempted_at'))

    op.drop_table('quiz_attempt')
    with op.batch_alter_table('lesson_read', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_lesson_read_user_id'))
        batch_op.drop_index(batch_op.f('ix_lesson_read_slug'))

    op.drop_table('lesson_read')