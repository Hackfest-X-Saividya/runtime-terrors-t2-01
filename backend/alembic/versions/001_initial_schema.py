"""initial_schema

Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-10-28 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create table 'scans'
    op.create_table(
        'scans',
        sa.Column('scan_id', sa.UUID(), nullable=False),
        sa.Column('project_name', sa.String(length=255), nullable=False),
        sa.Column('submission_type', sa.String(length=50), nullable=False),
        sa.Column('language', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='queued', nullable=False),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('findings_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('scan_id')
    )

    # 2. Create table 'mitigations'
    op.create_table(
        'mitigations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('canonical_key', sa.String(length=150), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('remediation_guidance', sa.Text(), nullable=False),
        sa.Column('code_diff', sa.Text(), nullable=True),
        sa.Column(
            'references_json',
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
            nullable=True
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('canonical_key')
    )
    op.create_index('ix_mitigations_cwe_id', 'mitigations', ['cwe_id'], unique=False)
    op.create_index('ix_mitigations_rule_id', 'mitigations', ['rule_id'], unique=False)

    # 3. Create table 'findings'
    op.create_table(
        'findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('scan_id', sa.UUID(), nullable=False),
        sa.Column('mitigation_id', sa.UUID(), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=False),
        sa.Column('end_line', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('owasp', sa.String(length=100), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=True),
        sa.Column('snippet', sa.Text(), nullable=False),
        sa.Column('ml_score', sa.Float(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('mitigation', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='open', nullable=False),
        sa.ForeignKeyConstraint(['mitigation_id'], ['mitigations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.scan_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_findings_scan_id_severity', 'findings', ['scan_id', 'severity'], unique=False)
    op.create_index('ix_findings_status', 'findings', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_findings_status', table_name='findings')
    op.drop_index('ix_findings_scan_id_severity', table_name='findings')
    op.drop_table('findings')

    op.drop_index('ix_mitigations_rule_id', table_name='mitigations')
    op.drop_index('ix_mitigations_cwe_id', table_name='mitigations')
    op.drop_table('mitigations')

    op.drop_table('scans')
