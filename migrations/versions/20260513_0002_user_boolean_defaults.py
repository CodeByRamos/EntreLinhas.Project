"""Set safe defaults for user boolean fields.

Revision ID: 20260513_0002
Revises: 20260511_0001
Create Date: 2026-05-13
"""

from alembic import op
import sqlalchemy as sa


revision = "20260513_0002"
down_revision = "20260511_0001"
branch_labels = None
depends_on = None


def _table_exists(inspector, table_name):
    return table_name in inspector.get_table_names()


def _columns(inspector, table_name):
    if not _table_exists(inspector, table_name):
        return {}
    return {column["name"]: column for column in inspector.get_columns(table_name)}


def _is_boolean_column(column):
    type_text = str(column["type"]).lower()
    type_name = column["type"].__class__.__name__.lower()
    return "bool" in type_text or "bool" in type_name


def _truth_literal(column, value):
    if _is_boolean_column(column):
        return "TRUE" if value else "FALSE"
    return "1" if value else "0"


def _fix_postgres_users(bind, columns):
    if "role" in columns:
        op.execute("UPDATE users SET role = 'user' WHERE role IS NULL")
        op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'user'")
        op.execute("ALTER TABLE users ALTER COLUMN role SET NOT NULL")
    else:
        op.add_column("users", sa.Column("role", sa.String(length=30), nullable=False, server_default="user"))

    required_flags = {
        "is_active": True,
        "is_admin": False,
        "is_verified": False,
    }

    for column_name, default_value in required_flags.items():
        if column_name not in columns:
            op.add_column(
                "users",
                sa.Column(
                    column_name,
                    sa.Integer(),
                    nullable=False,
                    server_default="1" if default_value else "0",
                ),
            )
            continue

        literal = _truth_literal(columns[column_name], default_value)
        op.execute(f"UPDATE users SET {column_name} = {literal} WHERE {column_name} IS NULL")
        op.execute(f"ALTER TABLE users ALTER COLUMN {column_name} SET DEFAULT {literal}")
        op.execute(f"ALTER TABLE users ALTER COLUMN {column_name} SET NOT NULL")

    # Compatibility for deployments that created this column with an older name.
    if "email_verified" in columns:
        literal = _truth_literal(columns["email_verified"], False)
        op.execute(f"UPDATE users SET email_verified = {literal} WHERE email_verified IS NULL")
        op.execute(f"ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT {literal}")
        op.execute("ALTER TABLE users ALTER COLUMN email_verified SET NOT NULL")


def _fix_sqlite_users(bind, columns):
    if "role" in columns:
        op.execute("UPDATE users SET role = 'user' WHERE role IS NULL")
    for column_name, default_value in {
        "is_active": 1,
        "is_admin": 0,
        "is_verified": 0,
        "email_verified": 0,
    }.items():
        if column_name in columns:
            op.execute(f"UPDATE users SET {column_name} = {default_value} WHERE {column_name} IS NULL")


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = _columns(inspector, "users")
    if not columns:
        return

    if bind.dialect.name == "postgresql":
        _fix_postgres_users(bind, columns)
    else:
        _fix_sqlite_users(bind, columns)


def downgrade():
    # Intentionally keep these data-safety defaults in place.
    pass
