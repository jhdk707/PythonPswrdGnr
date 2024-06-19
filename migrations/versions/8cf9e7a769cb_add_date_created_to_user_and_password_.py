"""Add date_created to User and Password models

Revision ID: 8cf9e7a769cb
Revises: 
Create Date: 2024-06-19 07:48:37.978248

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '8cf9e7a769cb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add date_created column with a default value for existing records
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_created', sa.DateTime, nullable=False, server_default=func.now()))
    
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.add_column(sa.Column('date_created', sa.DateTime, nullable=False, server_default=func.now()))
    
    # Update existing records to set the date_created column
    op.execute('UPDATE "user" SET date_created = NOW() WHERE date_created IS NULL')
    op.execute('UPDATE "password" SET date_created = NOW() WHERE date_created IS NULL')

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('date_created')
    
    with op.batch_alter_table('password', schema=None) as batch_op:
        batch_op.drop_column('date_created')

    # ### end Alembic commands ###
