"""Set safe defaults for post creation and profile updates.

Revision ID: 20260513_0003
Revises: 20260513_0002
Create Date: 2026-05-13
"""

from alembic import op
import sqlalchemy as sa


revision = "20260513_0003"
down_revision = "20260513_0002"
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


def _ensure_postgres_column(table, columns, name, column):
    if name not in columns:
        op.add_column(table, column)


def _fix_postgres_users(columns):
    _ensure_postgres_column(
        "users",
        columns,
        "default_avatar",
        sa.Column("default_avatar", sa.String(length=30), nullable=False, server_default="vazio"),
    )
    _ensure_postgres_column(
        "users",
        columns,
        "default_visibility_mode",
        sa.Column("default_visibility_mode", sa.String(length=20), nullable=False, server_default="anonymous"),
    )

    if "created_at" in columns:
        op.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
        op.execute("ALTER TABLE users ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP")
        op.execute("ALTER TABLE users ALTER COLUMN created_at SET NOT NULL")
    if "updated_at" in columns:
        op.execute("UPDATE users SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL")
        op.execute("ALTER TABLE users ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP")
        op.execute("ALTER TABLE users ALTER COLUMN updated_at SET NOT NULL")
    if "default_avatar" in columns:
        op.execute("UPDATE users SET default_avatar = 'vazio' WHERE default_avatar IS NULL OR TRIM(default_avatar) = ''")
        op.execute("ALTER TABLE users ALTER COLUMN default_avatar SET DEFAULT 'vazio'")
        op.execute("ALTER TABLE users ALTER COLUMN default_avatar SET NOT NULL")
    if "default_visibility_mode" in columns:
        op.execute(
            """
            UPDATE users
            SET default_visibility_mode = 'anonymous'
            WHERE default_visibility_mode IS NULL
               OR default_visibility_mode NOT IN ('anonymous', 'profile')
            """
        )
        op.execute("ALTER TABLE users ALTER COLUMN default_visibility_mode SET DEFAULT 'anonymous'")
        op.execute("ALTER TABLE users ALTER COLUMN default_visibility_mode SET NOT NULL")


def _fix_postgres_posts(columns):
    required_columns = {
        "visivel": sa.Column("visivel", sa.Integer(), nullable=False, server_default="1"),
        "status": sa.Column("status", sa.String(length=20), nullable=False, server_default="published"),
        "visibility_mode": sa.Column("visibility_mode", sa.String(length=20), nullable=False, server_default="anonymous"),
        "emotional_tag": sa.Column("emotional_tag", sa.String(length=30), nullable=False, server_default="vazio"),
        "sensitive_flag": sa.Column("sensitive_flag", sa.Integer(), nullable=False, server_default="0"),
        "mood_type": sa.Column("mood_type", sa.String(length=30), nullable=False, server_default="vazio"),
        "updated_at": sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        "is_deleted": sa.Column("is_deleted", sa.Integer(), nullable=False, server_default="0"),
        "report_count": sa.Column("report_count", sa.Integer(), nullable=False, server_default="0"),
    }
    for name, column in required_columns.items():
        _ensure_postgres_column("posts", columns, name, column)

    columns = _columns(sa.inspect(op.get_bind()), "posts")

    if "visivel" in columns:
        literal = _truth_literal(columns["visivel"], True)
        op.execute(f"UPDATE posts SET visivel = {literal} WHERE visivel IS NULL")
        op.execute(f"ALTER TABLE posts ALTER COLUMN visivel SET DEFAULT {literal}")
        op.execute("ALTER TABLE posts ALTER COLUMN visivel SET NOT NULL")
    if "status" in columns:
        op.execute("UPDATE posts SET status = 'published' WHERE status IS NULL OR status NOT IN ('draft', 'published')")
        op.execute("ALTER TABLE posts ALTER COLUMN status SET DEFAULT 'published'")
        op.execute("ALTER TABLE posts ALTER COLUMN status SET NOT NULL")
    if "visibility_mode" in columns:
        op.execute(
            """
            UPDATE posts
            SET visibility_mode = 'anonymous'
            WHERE visibility_mode IS NULL
               OR visibility_mode NOT IN ('anonymous', 'profile', 'alias')
            """
        )
        op.execute("ALTER TABLE posts ALTER COLUMN visibility_mode SET DEFAULT 'anonymous'")
        op.execute("ALTER TABLE posts ALTER COLUMN visibility_mode SET NOT NULL")
    if "emotional_tag" in columns:
        op.execute("UPDATE posts SET emotional_tag = 'vazio' WHERE emotional_tag IS NULL OR TRIM(emotional_tag) = ''")
        op.execute("ALTER TABLE posts ALTER COLUMN emotional_tag SET DEFAULT 'vazio'")
        op.execute("ALTER TABLE posts ALTER COLUMN emotional_tag SET NOT NULL")
    if "sensitive_flag" in columns:
        literal = _truth_literal(columns["sensitive_flag"], False)
        op.execute(f"UPDATE posts SET sensitive_flag = {literal} WHERE sensitive_flag IS NULL")
        op.execute(f"ALTER TABLE posts ALTER COLUMN sensitive_flag SET DEFAULT {literal}")
        op.execute("ALTER TABLE posts ALTER COLUMN sensitive_flag SET NOT NULL")
    if "mood_type" in columns:
        op.execute("UPDATE posts SET mood_type = COALESCE(NULLIF(TRIM(mood_type), ''), emotional_tag, 'vazio') WHERE mood_type IS NULL OR TRIM(mood_type) = ''")
        op.execute("ALTER TABLE posts ALTER COLUMN mood_type SET DEFAULT 'vazio'")
        op.execute("ALTER TABLE posts ALTER COLUMN mood_type SET NOT NULL")
    if "updated_at" in columns:
        op.execute("UPDATE posts SET updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL")
        op.execute("ALTER TABLE posts ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP")
        op.execute("ALTER TABLE posts ALTER COLUMN updated_at SET NOT NULL")
    if "is_deleted" in columns:
        literal = _truth_literal(columns["is_deleted"], False)
        op.execute(f"UPDATE posts SET is_deleted = {literal} WHERE is_deleted IS NULL")
        op.execute(f"ALTER TABLE posts ALTER COLUMN is_deleted SET DEFAULT {literal}")
        op.execute("ALTER TABLE posts ALTER COLUMN is_deleted SET NOT NULL")
    if "report_count" in columns:
        op.execute("UPDATE posts SET report_count = 0 WHERE report_count IS NULL")
        op.execute("ALTER TABLE posts ALTER COLUMN report_count SET DEFAULT 0")
        op.execute("ALTER TABLE posts ALTER COLUMN report_count SET NOT NULL")


def _fix_sqlite_table(table_name, values):
    for column_name, default_value in values.items():
        op.execute(f"UPDATE {table_name} SET {column_name} = {default_value} WHERE {column_name} IS NULL")


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    user_columns = _columns(inspector, "users")
    post_columns = _columns(inspector, "posts")

    if bind.dialect.name == "postgresql":
        if user_columns:
            _fix_postgres_users(user_columns)
        if post_columns:
            _fix_postgres_posts(post_columns)
    else:
        if user_columns:
            if "default_avatar" in user_columns:
                op.execute("UPDATE users SET default_avatar = 'vazio' WHERE default_avatar IS NULL OR TRIM(default_avatar) = ''")
            if "default_visibility_mode" in user_columns:
                op.execute("UPDATE users SET default_visibility_mode = 'anonymous' WHERE default_visibility_mode IS NULL OR default_visibility_mode NOT IN ('anonymous', 'profile')")
        if post_columns:
            _fix_sqlite_table(
                "posts",
                {
                    "visivel": 1,
                    "sensitive_flag": 0,
                    "is_deleted": 0,
                    "report_count": 0,
                },
            )
            op.execute("UPDATE posts SET status = 'published' WHERE status IS NULL OR status NOT IN ('draft', 'published')")
            op.execute("UPDATE posts SET visibility_mode = 'anonymous' WHERE visibility_mode IS NULL OR visibility_mode NOT IN ('anonymous', 'profile', 'alias')")
            op.execute("UPDATE posts SET emotional_tag = 'vazio' WHERE emotional_tag IS NULL OR TRIM(emotional_tag) = ''")
            op.execute("UPDATE posts SET mood_type = COALESCE(NULLIF(TRIM(mood_type), ''), emotional_tag, 'vazio') WHERE mood_type IS NULL OR TRIM(mood_type) = ''")
            op.execute("UPDATE posts SET updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL")


def downgrade():
    # Keep data-safety defaults in place.
    pass
