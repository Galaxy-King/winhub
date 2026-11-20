"""Revoke older browser sessions after self-service password changes."""
from alembic import op
import sqlalchemy as sa

revision = '20261120_01'
down_revision = '20261118_01'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('password_session_version', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    op.drop_column('users', 'password_session_version')
