"""add audit log

Revision ID: 838799e19a2b
Revises: 464ca61de495
Create Date: 2026-04-16 11:25:07.573678

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '838799e19a2b'
down_revision: Union[str, Sequence[str], None] = '464ca61de495'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# 1. Define the enum explicitly with create_type=False
vuln_status_enum = postgresql.ENUM(
    'OPEN', 'FIXED', 'FALSE_POSITIVE', 'RISK_ACCEPTED', 'IN_PROGRESS', 
    name='vulnstatus', 
    create_type=False
)

def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('audit_logs',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('vuln_id', sa.Integer(), nullable=False),
    # 2. Reference the predefined enum
    sa.Column('old_status', vuln_status_enum, nullable=False),
    sa.Column('new_status', vuln_status_enum, nullable=False),
    sa.Column('changed_by_user_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['changed_by_user_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['vuln_id'], ['vulnerabilities.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_vuln_id'), 'audit_logs', ['vuln_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_audit_logs_vuln_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_id'), table_name='audit_logs')
    op.drop_table('audit_logs')