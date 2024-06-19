"""Add date_created to User and Password models

Revision ID: 674fcc731f58
Revises: 8cf9e7a769cb
Create Date: 2024-06-19 07:56:39.233069

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func

# revision identifiers, used by Alembic.
revision = '674fcc731f58'
down_revision = '8cf9e7a769cb'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_created', sa.DateTime, nullable=False, server_default=func.now()))
    
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_created', sa.DateTime, nullable=False, server_default=func.now()))
    
    # Manually update existing records to set the date_created column
    op.execute('UPDATE "user" SET date_created = CURRENT_TIMESTAMP WHERE date_created IS NULL')
    op.execute('UPDATE "password" SET date_created = CURRENT_TIMESTAMP WHERE date_created IS NULL')

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('date_created')
    
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.drop_column('date_created')