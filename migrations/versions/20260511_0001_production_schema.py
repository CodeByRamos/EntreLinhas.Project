"""production schema for PostgreSQL

Revision ID: 20260511_0001
Revises:
Create Date: 2026-05-11
"""

from alembic import op
from models import sqlalchemy_schema

revision = "20260511_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    sqlalchemy_schema.db.metadata.create_all(bind=op.get_bind())


def downgrade():
    sqlalchemy_schema.db.metadata.drop_all(bind=op.get_bind())
