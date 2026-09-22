"""Add durable Newsletter result report delivery state."""
from alembic import op
import sqlalchemy as sa


revision = '20260922_01'
down_revision = '20260921_01'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('newsletter_campaigns', sa.Column('result_report_json', sa.Text(), nullable=True))
    op.add_column(
        'newsletter_campaigns',
        sa.Column('result_report_status', sa.String(length=20), nullable=False, server_default='NotRequested'),
    )
    op.add_column(
        'newsletter_campaigns',
        sa.Column('result_report_use_gpg', sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.add_column('newsletter_campaigns', sa.Column('result_report_updated_at', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('newsletter_campaigns', 'result_report_updated_at')
    op.drop_column('newsletter_campaigns', 'result_report_use_gpg')
    op.drop_column('newsletter_campaigns', 'result_report_status')
    op.drop_column('newsletter_campaigns', 'result_report_json')
