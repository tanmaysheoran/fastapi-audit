"""Create audit_logs table.

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('request_id', sa.String(36), nullable=False),
        sa.Column('actor_id', sa.String(255), nullable=False),
        sa.Column(
            'actor_type',
            sa.Enum('PLATFORM_ADMIN', 'TENANT_USER', 'ANONYMOUS', name='actor_type_enum'),
            nullable=False
        ),
        sa.Column('actor_email', sa.String(255), nullable=True),
        sa.Column('tenant_id', sa.String(36), nullable=True),
        sa.Column('tenant_slug', sa.String(63), nullable=True),
        sa.Column('method', sa.String(10), nullable=False),
        sa.Column('path', sa.String(2048), nullable=False),
        sa.Column('route_pattern', sa.String(2048), nullable=True),
        sa.Column('query_params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('response_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status_code', sa.Integer, nullable=False),
        sa.Column('response_time_ms', sa.Integer, nullable=False),
        sa.Column('orm_diffs', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('action', sa.String(255), nullable=True),
        sa.Column('extra_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_request_id', 'audit_logs', ['request_id'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])
    op.create_index('ix_audit_logs_actor_id', 'audit_logs', ['actor_id'])


def downgrade() -> None:
    op.drop_index('ix_audit_logs_actor_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_tenant_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_created_at', table_name='audit_logs')
    op.drop_index('ix_audit_logs_request_id', table_name='audit_logs')
    op.drop_table('audit_logs')
    op.execute("DROP TYPE IF EXISTS actor_type_enum")
