"""security_frameworks

Revision ID: 002_security_frameworks
Revises: 001_initial_schema
Create Date: 2026-10-29 04:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_security_frameworks'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive columns to findings table
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('cvss_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('cvss_vector', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('cvss_severity', sa.String(length=20), nullable=True))
        batch_op.add_column(
            sa.Column('cvss_provenance', sa.String(length=30), server_default='unassessed', nullable=False)
        )
        batch_op.add_column(
            sa.Column(
                'security_frameworks',
                sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                'correlation_data',
                sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_column('correlation_data')
        batch_op.drop_column('security_frameworks')
        batch_op.drop_column('cvss_provenance')
        batch_op.drop_column('cvss_severity')
        batch_op.drop_column('cvss_vector')
        batch_op.drop_column('cvss_score')
