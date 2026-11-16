"""Keep template usage notes separate from executable content."""
from alembic import op
import sqlalchemy as sa

revision = '20261116_02'
down_revision = '20261116_01'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'task_templates' in inspector.get_table_names() and 'description' not in {column['name'] for column in inspector.get_columns('task_templates')}:
        op.add_column('task_templates', sa.Column('description',sa.Text(),nullable=True))


def downgrade():
    inspector = sa.inspect(op.get_bind())
    if 'task_templates' in inspector.get_table_names() and 'description' in {column['name'] for column in inspector.get_columns('task_templates')}:
        op.drop_column('task_templates','description')
