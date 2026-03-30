"""add course access and topics

Revision ID: ac61590d23
Revises: ca794b05ffba
Create Date: 2026-03-01

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ac61590d23'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add has_course_access to user table
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('has_course_access', sa.Boolean(), nullable=False, server_default='0'))

    # Create course_access table
    op.create_table('course_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('granted_at', sa.DateTime(), nullable=False),
        sa.Column('granted_by', sa.String(length=255), nullable=True),
        sa.Column('gumroad_sale_id', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], name='fk_course_access_user'),
        sa.PrimaryKeyConstraint('id', name='pk_course_access'),
        sa.UniqueConstraint('user_id', name='uq_course_access_user_id')
    )
    op.create_index('ix_course_access_user_id', 'course_access', ['user_id'])

    # Create course_topic table
    op.create_table('course_topic',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('slug', sa.String(length=80), nullable=False),
        sa.Column('section', sa.String(length=2), nullable=False),
        sa.Column('lesson_number', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('lab', sa.Text(), nullable=True),
        sa.Column('order', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id', name='pk_course_topic'),
        sa.UniqueConstraint('slug', name='uq_course_topic_slug')
    )
    op.create_index('ix_course_topic_slug', 'course_topic', ['slug'])


def downgrade():
    op.drop_index('ix_course_topic_slug', table_name='course_topic')
    op.drop_table('course_topic')
    op.drop_index('ix_course_access_user_id', table_name='course_access')
    op.drop_table('course_access')
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('has_course_access')