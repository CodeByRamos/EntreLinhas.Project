import sqlite3
from datetime import datetime, timedelta
import os
import re
import secrets
import logging
import time
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None
    DictCursor = None

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

# Pool de conexões (psycopg_pool). Importado de forma defensiva: se a lib não
# estiver instalada, o app cai para conexão direta (comportamento antigo) sem
# quebrar. Instale com `psycopg[binary,pool]` (já no requirements.txt).
try:
    from psycopg_pool import ConnectionPool
except ImportError:
    ConnectionPool = None

import threading

from utils.security import hash_password, verify_password, is_legacy_hash
from utils.validation import LIMITS, is_valid_email, is_valid_username, trim_text
from utils.safe_logging import log_exception
from utils.mood_styles import (
    normalize_default_avatar,
    normalize_emotional_tag,
)

# Caminho do banco SQLite local. Em produção, prefira DATABASE_URL com as migrations.
DB_PATH = os.environ.get(
    'SQLITE_DB_PATH',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')
)
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql+psycopg://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://", 1)
USE_POSTGRES = bool(DATABASE_URL.startswith(("postgresql://", "postgresql+")))
logger = logging.getLogger("entrelinhas.database")


def _as_datetime(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    return value


def _translate_sql_for_postgres(sql):
    translated = sql.replace("?", "%s")
    translated = translated.replace("datetime('now')", "CURRENT_TIMESTAMP")
    translated = translated.replace('datetime("now")', "CURRENT_TIMESTAMP")
    translated = translated.replace("last_insert_rowid()", "LASTVAL()")
    return translated


class _CompatRow(dict):
    def __init__(self, data, columns):
        super().__init__(data)
        self._columns = columns

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._columns[key])
        return super().__getitem__(key)


class _PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor
        self._lastrowid = None

    def execute(self, sql, params=()):
        # Postgres é estritamente tipado: um bool do Python (True/False) não entra
        # numa coluna INTEGER. Convertendo aqui, evitamos 500 em inserts com flags
        # (sensitive_flag, is_active, visivel, etc.) que no SQLite passavam batido.
        coerced = tuple(int(p) if isinstance(p, bool) else p for p in (params or ()))
        self._cursor.execute(_translate_sql_for_postgres(sql), coerced)
        if sql.lstrip().lower().startswith("insert"):
            self._lastrowid = self._read_last_insert_id()
        return self

    def _read_last_insert_id(self):
        try:
            lookup = self._cursor.connection.cursor()
            try:
                lookup.execute("SELECT LASTVAL()")
                row = lookup.fetchone()
                if not row:
                    return None
                if isinstance(row, dict):
                    return next(iter(row.values()), None)
                return row[0]
            finally:
                lookup.close()
        except Exception:
            return None

    def _wrap_row(self, row):
        if row is None:
            return None
        if isinstance(row, _CompatRow):
            return row
        columns = [item[0] for item in (self._cursor.description or [])]
        return _CompatRow(dict(row), columns)

    def fetchone(self):
        return self._wrap_row(self._cursor.fetchone())

    def fetchall(self):
        return [self._wrap_row(row) for row in self._cursor.fetchall()]

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._lastrowid

    def close(self):
        self._cursor.close()


class _PostgresConnection:
    """Conexão Postgres compatível com a API do sqlite3 usada no projeto.

    Pode envolver uma conexão NOVA (caminho direto) ou uma conexão emprestada
    de um pool — nesse caso, ``close()`` devolve ao pool em vez de fechar.
    """
    def __init__(self, url=None, raw=None, pool=None):
        self._pool = pool
        if raw is not None:
            self._conn = raw
            self._driver = "psycopg"
        elif psycopg2 is not None:
            self._driver = "psycopg2"
            self._conn = psycopg2.connect(url or DATABASE_URL, cursor_factory=DictCursor)
        elif psycopg is not None:
            self._driver = "psycopg"
            self._conn = psycopg.connect(url or DATABASE_URL, row_factory=dict_row)
        else:
            raise RuntimeError("Instale psycopg[binary] para usar PostgreSQL.")

    def execute(self, sql, params=()):
        cursor = self.cursor()
        return cursor.execute(sql, params)

    def cursor(self):
        return _PostgresCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._pool is not None:
            # Devolve ao pool. Antes, limpa qualquer transação pendente para a
            # próxima requisição não herdar estado abortado.
            try:
                self._conn.rollback()
            except Exception:
                pass
            try:
                self._pool.putconn(self._conn)
                return
            except Exception:
                pass
        try:
            self._conn.close()
        except Exception:
            pass


def _get_table_columns(conn, table_name):
    """Retorna o conjunto de colunas existentes em uma tabela."""
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _ensure_column(conn, table_name, column_name, definition):
    """Garante a existência de uma coluna, aplicando migração simples quando necessário."""
    columns = _get_table_columns(conn, table_name)
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def _ensure_unique_index(conn, index_name, table_name, column_name):
    """
    Garante um índice único para a coluna informada quando possível.
    Mantém compatibilidade com bancos legados que já tenham duplicatas.
    """
    existing_index = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
        (index_name,),
    ).fetchone()
    if existing_index:
        return

    duplicates = conn.execute(
        f"""
        SELECT {column_name}, COUNT(1) as total
        FROM {table_name}
        WHERE {column_name} IS NOT NULL AND TRIM({column_name}) <> ''
        GROUP BY {column_name}
        HAVING COUNT(1) > 1
        """
    ).fetchall()

    if duplicates:
        return

    conn.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table_name} ({column_name}) "
        f"WHERE {column_name} IS NOT NULL AND TRIM({column_name}) <> ''"
    )


def _sanitize_user_row(user_row):
    """Retorna dicionário do usuário sem campos sensíveis."""
    if not user_row:
        return None
    user_dict = dict(user_row)
    user_dict.pop("password_hash", None)
    return user_dict

_PG_POOL = None
_PG_POOL_PID = None
_PG_POOL_LOCK = threading.Lock()


def _reset_pg_pool_after_fork():
    """Após um fork (gunicorn --preload), o filho NÃO pode herdar o pool do pai
    (sockets/threads do pool não sobrevivem ao fork). Zera a referência sem
    fechar — fechar tocaria os fds compartilhados com o pai. O filho recria o
    seu próprio pool no primeiro uso."""
    global _PG_POOL, _PG_POOL_PID
    _PG_POOL = None
    _PG_POOL_PID = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_pg_pool_after_fork)


def _get_pg_pool():
    """Pool de conexões por processo (lazy + seguro contra fork do gunicorn).

    Reutilizar conexões evita o handshake TCP/TLS/auth a cada query — que é a
    maior fonte de lentidão no Neon. Retorna None se o pool não estiver
    disponível (lib ausente ou falha ao abrir): aí usamos conexão direta.
    """
    global _PG_POOL, _PG_POOL_PID
    if ConnectionPool is None or psycopg is None:
        return None
    pid = os.getpid()
    # Pool herdado de um fork (gunicorn preload) não pode ser reutilizado.
    if _PG_POOL is not None and _PG_POOL_PID != pid:
        _PG_POOL = None
    if _PG_POOL is None:
        with _PG_POOL_LOCK:
            if _PG_POOL is None or _PG_POOL_PID != os.getpid():
                try:
                    pool = ConnectionPool(
                        conninfo=DATABASE_URL,
                        min_size=1,
                        max_size=int(os.environ.get("PG_POOL_MAX", "5") or "5"),
                        timeout=float(os.environ.get("PG_POOL_TIMEOUT", "10") or "10"),
                        max_idle=120.0,
                        # prepare_threshold=None DESLIGA os prepared statements
                        # automáticos do psycopg3: conexões longevas no pool +
                        # PgBouncer transaction-mode do Neon (-pooler) fariam o
                        # EXECUTE cair num backend que não tem o PREPARE
                        # ("prepared statement does not exist"). Sem isso, quebra
                        # intermitente em produção sob carga.
                        kwargs={"row_factory": dict_row, "prepare_threshold": None},
                        check=ConnectionPool.check_connection,
                        name="entrelinhas",
                        open=False,
                    )
                    pool.open(wait=True, timeout=10.0)
                    _PG_POOL = pool
                    _PG_POOL_PID = os.getpid()
                except Exception as exc:
                    logger.warning("Não foi possível abrir o pool Postgres (usando conexão direta): %s", exc)
                    _PG_POOL = None
    return _PG_POOL


def get_db_connection():
    """Estabelece e retorna uma conexão com o banco de dados.

    No Postgres usa um pool (conexões reutilizadas = muito mais rápido). Se o
    pool não estiver disponível, cai para conexão direta com retry — o Neon pode
    falhar a primeira conexão enquanto "acorda".
    """
    if USE_POSTGRES:
        pool = _get_pg_pool()
        if pool is not None:
            timeout = float(os.environ.get("PG_POOL_TIMEOUT", "10") or "10")
            for attempt in range(3):
                try:
                    raw = pool.getconn(timeout=timeout)
                    return _PostgresConnection(raw=raw, pool=pool)
                except Exception as exc:
                    logger.warning("Pool getconn falhou (tentativa %s/3): %s", attempt + 1, exc)
                    time.sleep(0.3 * (attempt + 1))
            logger.warning("Pool indisponível; caindo para conexão direta.")
        # Conexão direta (sem pool ou pool falhou).
        last_exc = None
        for attempt in range(4):
            try:
                return _PostgresConnection(DATABASE_URL)
            except Exception as exc:
                last_exc = exc
                logger.warning("Falha ao conectar no Postgres (tentativa %s/4): %s", attempt + 1, exc)
                time.sleep(0.4 * (attempt + 1))
        raise last_exc
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Para acessar colunas pelo nome
    return conn

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabela de posts (desabafos)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            mensagem TEXT NOT NULL,
            data_postagem TEXT NOT NULL,
            categoria TEXT NOT NULL,
            visivel INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'published',
            alias_name TEXT,
            user_id INTEGER,
            profile_id INTEGER,
            visibility_mode TEXT NOT NULL DEFAULT 'anonymous',
            emotional_tag TEXT NOT NULL DEFAULT 'vazio',
            sensitive_flag INTEGER NOT NULL DEFAULT 0,
            mood_type TEXT NOT NULL DEFAULT 'vazio',
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            report_count INTEGER NOT NULL DEFAULT 0
        )
    ''')
    
    # Tabela de comentários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            mensagem TEXT NOT NULL,
            data_comentario TEXT NOT NULL,
            visivel INTEGER DEFAULT 1,
            user_id INTEGER,
            profile_id INTEGER,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')
    
    # Tabela de reações
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL,
            user_id TEXT,
            profile_id INTEGER,
            data_reacao TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')
    
    # Tabela de contagem de reações (para performance)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reaction_counts (
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            PRIMARY KEY (post_id, reaction_type),
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    """)

    # Tabela de reports de comentários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id INTEGER NOT NULL,
            user_id INTEGER,
            reason TEXT NOT NULL,
            data_report TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            FOREIGN KEY (comment_id) REFERENCES comments (id)
        )
    """)

    # Tabela de usuários (contas permanentes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            nickname TEXT NOT NULL,
            bio TEXT,
            email TEXT UNIQUE,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            is_admin BOOLEAN NOT NULL DEFAULT 0,
            is_verified BOOLEAN NOT NULL DEFAULT 0,
            email_verified_at TIMESTAMP
        )
    ''')

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            reference_id INTEGER,
            is_read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Tabela de perfis anônimos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            bio TEXT,
            token TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabela de reports de posts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            profile_id INTEGER,
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS echoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (post_id) REFERENCES posts (id),
            UNIQUE(user_id, post_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensitive_post_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            risk_level TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS psychologists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            professional_title TEXT,
            crp TEXT,
            contact_email TEXT,
            contact_link TEXT,
            bio TEXT,
            is_verified INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS daily_texts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_name TEXT,
            date TEXT UNIQUE,
            mood TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tabela de karma de comentários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comment_karma (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id INTEGER NOT NULL,
            user_id INTEGER,
            profile_id INTEGER,
            karma_type TEXT NOT NULL CHECK (karma_type IN ('up', 'down')),
            data TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (comment_id) REFERENCES comments (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(comment_id, user_id),
            UNIQUE(comment_id, profile_id)
        )
    ''')

    # Migrações leves para bancos antigos
    _ensure_column(conn, "posts", "user_id", "INTEGER")
    _ensure_column(conn, "posts", "profile_id", "INTEGER")
    _ensure_column(conn, "posts", "visibility_mode", "TEXT DEFAULT 'anonymous'")
    _ensure_column(conn, "posts", "status", "TEXT DEFAULT 'published'")
    _ensure_column(conn, "posts", "title", "TEXT")
    _ensure_column(conn, "posts", "alias_name", "TEXT")
    _ensure_column(conn, "posts", "emotional_tag", "TEXT DEFAULT 'vazio'")
    _ensure_column(conn, "posts", "sensitive_flag", "INTEGER DEFAULT 0")
    _ensure_column(conn, "posts", "mood_type", "TEXT DEFAULT 'vazio'")
    _ensure_column(conn, "posts", "updated_at", "TIMESTAMP")
    _ensure_column(conn, "posts", "is_deleted", "INTEGER DEFAULT 0")
    _ensure_column(conn, "posts", "report_count", "INTEGER DEFAULT 0")
    _ensure_column(conn, "posts", "overcome_at", "TEXT")
    _ensure_column(conn, "posts", "overcome_message", "TEXT")
    _ensure_column(conn, "posts", "listen_only", "INTEGER DEFAULT 0")
    _ensure_column(conn, "comments", "mensagem", "TEXT")
    _ensure_column(conn, "comments", "visivel", "INTEGER DEFAULT 1")
    _ensure_column(conn, "comments", "user_id", "INTEGER")
    _ensure_column(conn, "comments", "profile_id", "INTEGER")
    _ensure_column(conn, "reactions", "user_id", "TEXT")
    _ensure_column(conn, "reactions", "profile_id", "INTEGER")
    _ensure_column(conn, "reactions", "data_reacao", "TEXT DEFAULT CURRENT_TIMESTAMP")
    _ensure_column(conn, "users", "is_active", "BOOLEAN NOT NULL DEFAULT 1")
    _ensure_column(conn, "users", "is_admin", "BOOLEAN NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "role", "TEXT NOT NULL DEFAULT 'user'")
    _ensure_column(conn, "users", "is_verified", "BOOLEAN NOT NULL DEFAULT 0")
    _ensure_column(conn, "users", "email_verified_at", "TIMESTAMP")
    _ensure_column(conn, "users", "display_name", "TEXT")
    _ensure_column(conn, "users", "avatar_url", "TEXT")
    _ensure_column(conn, "users", "profile_photo", "TEXT")
    _ensure_column(conn, "users", "default_avatar", "TEXT DEFAULT 'vazio'")
    _ensure_column(conn, "users", "default_visibility_mode", "TEXT DEFAULT 'anonymous'")
    _ensure_column(conn, "reports", "user_id", "INTEGER")
    _ensure_column(conn, "reports", "profile_id", "INTEGER")
    _ensure_column(conn, "reports", "reason", "TEXT DEFAULT 'outro'")
    _ensure_column(conn, "reports", "details", "TEXT")
    _ensure_column(conn, "reports", "status", "TEXT DEFAULT 'pending'")
    _ensure_column(conn, "reports", "created_at", "TIMESTAMP")
    _ensure_column(conn, "reports_comments", "user_id", "INTEGER")
    if "updated_at" not in _get_table_columns(conn, "users"):
        conn.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP")
        conn.execute(
        """
        UPDATE users
        SET display_name = COALESCE(NULLIF(TRIM(display_name), ''), nickname, username)
        WHERE display_name IS NULL OR TRIM(display_name) = ''
        """
    )
    conn.execute(
        """
        UPDATE users
        SET default_visibility_mode = CASE
            WHEN default_visibility_mode IN ('anonymous', 'profile') THEN default_visibility_mode
            ELSE 'anonymous'
        END
        """
    )
    conn.execute(
        """
        UPDATE users
        SET display_name = COALESCE(NULLIF(TRIM(display_name), ''), nickname, username),
            default_avatar = COALESCE(NULLIF(TRIM(default_avatar), ''), 'vazio')
        WHERE display_name IS NULL OR TRIM(display_name) = ''
           OR default_avatar IS NULL OR TRIM(default_avatar) = ''
        """
    )
    conn.execute(
        """
        UPDATE posts
        SET status = CASE
            WHEN status IN ('draft', 'published') THEN status
            ELSE 'published'
        END
        """
    )
    conn.execute(
        """
        UPDATE posts
        SET emotional_tag = COALESCE(NULLIF(TRIM(emotional_tag), ''), 'vazio'),
            mood_type = COALESCE(NULLIF(TRIM(mood_type), ''), emotional_tag, 'vazio'),
            updated_at = COALESCE(updated_at, data_postagem, datetime('now')),
            is_deleted = COALESCE(is_deleted, 0),
            sensitive_flag = COALESCE(sensitive_flag, 0),
            report_count = (
                SELECT COUNT(*) FROM reports r WHERE r.post_id = posts.id
            )
        WHERE emotional_tag IS NULL OR TRIM(emotional_tag) = ''
           OR mood_type IS NULL OR TRIM(mood_type) = ''
           OR updated_at IS NULL
           OR is_deleted IS NULL
           OR sensitive_flag IS NULL
           OR report_count IS NULL
        """
    )
    conn.execute(
        """
        UPDATE reports
        SET reason = COALESCE(NULLIF(TRIM(reason), ''), 'outro'),
            status = COALESCE(NULLIF(TRIM(status), ''), 'pending'),
            created_at = COALESCE(created_at, data, datetime('now'))
        WHERE reason IS NULL OR TRIM(reason) = ''
           OR status IS NULL OR TRIM(status) = ''
           OR created_at IS NULL
        """
    )
    conn.execute(
        """
        UPDATE users
        SET updated_at = COALESCE(updated_at, created_at, datetime('now'))
        WHERE updated_at IS NULL
        """
    )
    conn.execute(
        """
        UPDATE users
        SET role = COALESCE(NULLIF(TRIM(role), ''), 'user'),
            is_active = COALESCE(is_active, 1),
            is_admin = COALESCE(is_admin, 0),
            is_verified = COALESCE(is_verified, 0)
        WHERE role IS NULL OR TRIM(role) = ''
           OR is_active IS NULL
           OR is_admin IS NULL
           OR is_verified IS NULL
        """
    )
    _ensure_unique_index(conn, "idx_users_email_unique", "users", "email")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_emotional_tag ON posts (emotional_tag)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_sensitive_flag ON posts (sensitive_flag)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_posts_report_count ON posts (report_count)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_echoes_post_id ON echoes (post_id)")

    conn.commit()
    conn.close()


# Índices de performance que valem para os DOIS bancos (SQLite e Postgres).
# Cobrem as colunas mais joinadas/filtradas (FKs lógicas) que faltavam — sem
# elas, cada listagem do feed e da moderação vira full scan no Postgres.
_PERF_INDEXES = [
    ("idx_comments_post_id", "comments", "(post_id)"),
    ("idx_reactions_post_id", "reactions", "(post_id)"),
    ("idx_reactions_lookup", "reactions", "(post_id, reaction_type, user_id)"),
    ("idx_comment_karma_comment_id", "comment_karma", "(comment_id)"),
    ("idx_reports_post_id", "reports", "(post_id)"),
    ("idx_reports_comments_comment_id", "reports_comments", "(comment_id)"),
    ("idx_reports_comments_user_id", "reports_comments", "(user_id)"),
    ("idx_posts_user_id", "posts", "(user_id)"),
    ("idx_posts_feed", "posts", "(visivel, status)"),
]


def ensure_performance_indexes():
    """Cria índices ausentes nas FKs lógicas. Idempotente; roda em SQLite e Postgres."""
    conn = get_db_connection()
    try:
        for name, table, cols in _PERF_INDEXES:
            try:
                conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {table} {cols}")
            except Exception as exc:
                logger.warning("ensure_performance_indexes %s: %s", name, exc)
        conn.commit()
    except Exception as exc:
        logger.warning("ensure_performance_indexes falhou: %s", exc)
    finally:
        conn.close()


def ensure_reports_comments_user_id():
    """Garante colunas adicionadas após o create_all em bancos já existentes.

    No Postgres o create_all() não altera tabela existente; aqui aplicamos os
    ALTER idempotentes. No SQLite usa o mesmo _ensure_column do init_db.
    """
    # (tabela, coluna, definição PG, definição SQLite). Cada migração roda
    # ISOLADA — uma falha (ex.: tabela ainda inexistente) não aborta as outras,
    # evitando o efeito cascata de transação abortada no Postgres.
    migrations = [
        ("reports_comments", "user_id", "INTEGER", "INTEGER"),
        ("posts", "overcome_at", "VARCHAR(20)", "TEXT"),
        ("posts", "overcome_message", "TEXT", "TEXT"),
        ("posts", "listen_only", "INTEGER DEFAULT 0", "INTEGER DEFAULT 0"),
        ("stranger_letter_deliveries", "reported_at", "VARCHAR(20)", "TEXT"),
    ]
    for table, col, pg_def, sqlite_def in migrations:
        conn = get_db_connection()
        try:
            if USE_POSTGRES:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {pg_def}")
            else:
                _ensure_column(conn, table, col, sqlite_def)
            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            logger.warning("migração ignorada (%s.%s): %s", table, col, exc)
        finally:
            conn.close()

# Funções para posts (desabafos)

def get_posts(limit=10, offset=0, include_hidden=False):
    """Retorna os posts mais recentes com paginação."""
    conn = get_db_connection()
    
    if include_hidden:
        posts = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE COALESCE(p.is_deleted, 0) = 0
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.visivel = 1 AND p.status = 'published' AND COALESCE(p.is_deleted, 0) = 0
            ORDER BY p.id DESC 
            LIMIT ? OFFSET ?
            ''', (limit, offset)).fetchall()
    
    conn.close()
    return posts

def get_hidden_posts(limit=50):
    """Retorna os posts ocultos mais recentes."""
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode, p.status, p.overcome_at, p.overcome_message, p.listen_only,
               u.username as author_username,
               u.nickname as author_nickname,
               u.display_name as author_display_name,
               u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url,
               u.default_avatar as author_default_avatar,
                   u.role as author_role
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.visivel = 0 AND COALESCE(p.is_deleted, 0) = 0
        ORDER BY p.id DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return posts

def get_post(post_id, include_hidden=False):
    """Retorna um post específico pelo ID."""
    conn = get_db_connection()
    
    if include_hidden:
        post = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ? AND COALESCE(p.is_deleted, 0) = 0
        ''', (post_id,)).fetchone()
    else:
        post = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ? AND p.visivel = 1 AND p.status = 'published' AND COALESCE(p.is_deleted, 0) = 0
        ''', (post_id,)).fetchone()
    
    conn.close()
    return post

def get_posts_by_user(user_id, limit=10, offset=0, include_hidden=True, visibility_mode=None, status=None):
    """Retorna posts de um usuário com paginação."""
    conn = get_db_connection()
    filters = ["p.user_id = ?", "COALESCE(p.is_deleted, 0) = 0"]
    params = [user_id]

    if not include_hidden:
        filters.append("p.visivel = 1")

    if visibility_mode in ("anonymous", "profile"):
        filters.append("p.visibility_mode = ?")
        params.append(visibility_mode)
    if status in ("draft", "published"):
        filters.append("p.status = ?")
        params.append(status)

    where_clause = " AND ".join(filters)

    params.extend([limit, offset])
    posts = conn.execute(
        f'''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode,
               p.status AS status, p.overcome_at, p.overcome_message, p.listen_only,
               u.username as author_username,
               u.nickname as author_nickname,
               u.display_name as author_display_name,
               u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url,
               u.default_avatar as author_default_avatar,
                   u.role as author_role
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE {where_clause}
        ORDER BY p.id DESC
        LIMIT ? OFFSET ?
        ''',
        tuple(params),
    ).fetchall()

    conn.close()
    return posts

def get_post_count_by_user(user_id, include_hidden=True, visibility_mode=None, status=None):
    """Retorna a quantidade de posts de um usuário."""
    conn = get_db_connection()
    filters = ["user_id = ?", "COALESCE(is_deleted, 0) = 0"]
    params = [user_id]
    if not include_hidden:
        filters.append("visivel = 1")
    if visibility_mode in ("anonymous", "profile"):
        filters.append("visibility_mode = ?")
        params.append(visibility_mode)
    if status in ("draft", "published"):
        filters.append("status = ?")
        params.append(status)
    where_clause = " AND ".join(filters)
    count = conn.execute(
        f"SELECT COUNT(*) FROM posts WHERE {where_clause}",
        tuple(params),
    ).fetchone()[0]

    conn.close()
    return count


def get_echoed_posts_by_user(user_id, limit=10, offset=0):
    """Retorna posts que o usuário ecoou, com paginação."""
    conn = get_db_connection()
    posts = conn.execute(
        '''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode,
               p.status AS status,
               e.created_at AS echoed_at,
               u.username as author_username,
               u.nickname as author_nickname,
               u.display_name as author_display_name,
               u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url,
               u.default_avatar as author_default_avatar,
                   u.role as author_role
        FROM echoes e
        JOIN posts p ON p.id = e.post_id
        LEFT JOIN users u ON p.user_id = u.id
        WHERE e.user_id = ?
          AND p.visivel = 1
          AND p.status = 'published'
          AND COALESCE(p.is_deleted, 0) = 0
        ORDER BY e.id DESC
        LIMIT ? OFFSET ?
        ''',
        (user_id, limit, offset),
    ).fetchall()
    conn.close()
    return posts


def get_echoed_post_count_by_user(user_id):
    """Conta quantos posts publicados o usuário ecoou."""
    conn = get_db_connection()
    count = conn.execute(
        '''
        SELECT COUNT(*)
        FROM echoes e
        JOIN posts p ON p.id = e.post_id
        WHERE e.user_id = ?
          AND p.visivel = 1
          AND p.status = 'published'
          AND COALESCE(p.is_deleted, 0) = 0
        ''',
        (user_id,),
    ).fetchone()[0]
    conn.close()
    return count

def update_post(post_id, mensagem, categoria, visibility_mode, title=None, status="published", emotional_tag=None, sensitive_flag=False):
    """Atualiza os dados de um post."""
    mensagem = trim_text(mensagem)
    categoria = trim_text(categoria)
    title = trim_text(title) or None
    emotional_tag = normalize_emotional_tag(emotional_tag)
    mood_type = emotional_tag
    if status not in ("draft", "published"):
        return False
    if len(mensagem) < LIMITS["post_content_min"] or len(mensagem) > LIMITS["post_content_max"]:
        return False
    if title and len(title) > LIMITS["post_title_max"]:
        return False
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        '''
        UPDATE posts
        SET mensagem = ?, categoria = ?, visibility_mode = ?, title = ?, status = ?,
            emotional_tag = ?, mood_type = ?, sensitive_flag = ?, updated_at = datetime('now')
        WHERE id = ?
        ''',
        (mensagem, categoria, visibility_mode, title, status, emotional_tag, mood_type, 1 if sensitive_flag else 0, post_id),
    )
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success

def delete_post(post_id):
    """Remove um post e seus dados relacionados."""
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM reports WHERE post_id = ?", (post_id,))
        conn.execute("DELETE FROM reactions WHERE post_id = ?", (post_id,))
        conn.execute("DELETE FROM reaction_counts WHERE post_id = ?", (post_id,))
        conn.execute("DELETE FROM echoes WHERE post_id = ?", (post_id,))
        conn.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
        cursor = conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()

def create_post(mensagem, categoria, user_id, visibility_mode='anonymous', title=None, status='published', emotional_tag=None, sensitive_flag=False, listen_only=False):
    """Cria um novo post com autoria obrigatória."""
    conn = get_db_connection()
    data_postagem = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    if visibility_mode not in ('anonymous', 'profile', 'alias'):
        conn.close()
        raise ValueError("Modo de visibilidade inválido.")
    if status not in ('draft', 'published'):
        conn.close()
        raise ValueError("Status inválido para o post.")

    mensagem = trim_text(mensagem)
    categoria = trim_text(categoria)
    title = trim_text(title) or None
    emotional_tag = normalize_emotional_tag(emotional_tag)
    mood_type = emotional_tag

    if len(mensagem) < LIMITS["post_content_min"] or len(mensagem) > LIMITS["post_content_max"]:
        conn.close()
        raise ValueError(
            f"Conteúdo deve ter entre {LIMITS['post_content_min']} e {LIMITS['post_content_max']} caracteres."
        )
    if title and len(title) > LIMITS["post_title_max"]:
        conn.close()
        raise ValueError(f"Título deve ter no máximo {LIMITS['post_title_max']} caracteres.")

    user = conn.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1",
        (user_id,),
    ).fetchone()
    if not user:
        conn.close()
        raise ValueError("Usuário inválido para criação do post.")
    
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO posts (
                mensagem, categoria, data_postagem, user_id, visibility_mode, status, title,
                emotional_tag, sensitive_flag, mood_type, listen_only, visivel, is_deleted, report_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, datetime('now'))
        ''', (
            mensagem, categoria, data_postagem, user_id, visibility_mode, status, title,
            emotional_tag, 1 if sensitive_flag else 0, mood_type, 1 if listen_only else 0,
        ))

        post_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return post_id
    except Exception as exc:
        conn.rollback()
        conn.close()
        log_exception(
            logger,
            "database.create_post",
            "posts.insert",
            exc,
            user_id=user_id,
            table="posts",
            operation="insert",
            status=status,
            emotional_tag=emotional_tag,
            category=categoria,
        )
        raise

def update_post_visibility(post_id, visibility):
    """Atualiza a visibilidade de um post."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE posts
        SET visivel = ?
        WHERE id = ?
    ''', (visibility, post_id))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Marco de Superação: o autor marca um desabafo como "eu superei isso".
# overcome_at (texto dd/mm/YYYY HH:MM) guarda quando virou marco.
# ---------------------------------------------------------------------------

def mark_post_overcome(post_id, user_id, message=None):
    """Marca um desabafo do PRÓPRIO autor como superado, com mensagem opcional
    para quem passa pela mesma situação. Idempotente."""
    conn = get_db_connection()
    overcome_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    message = (message or "").strip() or None
    try:
        cursor = conn.execute(
            "UPDATE posts SET overcome_at = ?, overcome_message = ? "
            "WHERE id = ? AND user_id = ? AND COALESCE(is_deleted, 0) = 0",
            (overcome_at, message, post_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.mark_post_overcome", "posts.update", e,
                      post_id=post_id, table="posts", operation="update")
        return False
    finally:
        conn.close()


def unmark_post_overcome(post_id, user_id):
    """Desfaz o marco de superação (só o autor)."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE posts SET overcome_at = NULL, overcome_message = NULL WHERE id = ? AND user_id = ?",
            (post_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.unmark_post_overcome", "posts.update", e,
                      post_id=post_id, table="posts", operation="update")
        return False
    finally:
        conn.close()


def get_overcome_posts_by_user(user_id, limit=20, offset=0):
    """Histórico de superações do usuário (mais recentes primeiro)."""
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode, p.status, p.overcome_at, p.overcome_message, p.listen_only,
               u.username as author_username, u.nickname as author_nickname,
               u.display_name as author_display_name, u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url, u.default_avatar as author_default_avatar,
               u.role as author_role
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.user_id = ? AND p.overcome_at IS NOT NULL AND COALESCE(p.is_deleted, 0) = 0
        ORDER BY p.id DESC
        LIMIT ? OFFSET ?
        ''',
        (user_id, limit, offset),
    ).fetchall()
    conn.close()
    return rows


def get_overcome_count_by_user(user_id):
    conn = get_db_connection()
    total = conn.execute(
        "SELECT COUNT(*) FROM posts "
        "WHERE user_id = ? AND overcome_at IS NOT NULL AND COALESCE(is_deleted, 0) = 0",
        (user_id,),
    ).fetchone()[0]
    conn.close()
    return total


# ---------------------------------------------------------------------------
# Acolher uma voz: desabafos publicados, visíveis, que aceitam resposta e ainda
# NÃO receberam nenhuma. Exclui os próprios do usuário e os "somente escuta".
# ---------------------------------------------------------------------------

_UNANSWERED_WHERE = (
    "p.visivel = 1 AND p.status = 'published' AND COALESCE(p.is_deleted, 0) = 0 "
    "AND COALESCE(p.listen_only, 0) = 0 AND p.user_id <> ? "
    "AND NOT EXISTS (SELECT 1 FROM comments c WHERE c.post_id = p.id AND c.visivel = 1)"
)


def get_unanswered_posts(exclude_user_id, limit=1, offset=0):
    """Vozes ainda sem resposta, em ordem aleatória (uma de cada vez)."""
    conn = get_db_connection()
    rows = conn.execute(
        f'''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode, p.status, p.overcome_at, p.overcome_message, p.listen_only,
               u.username as author_username, u.nickname as author_nickname,
               u.display_name as author_display_name, u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url, u.default_avatar as author_default_avatar,
               u.role as author_role
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE {_UNANSWERED_WHERE}
        ORDER BY RANDOM()
        LIMIT ? OFFSET ?
        ''',
        (exclude_user_id, limit, offset),
    ).fetchall()
    conn.close()
    return rows


def get_unanswered_count(exclude_user_id):
    conn = get_db_connection()
    total = conn.execute(
        f"SELECT COUNT(*) FROM posts p WHERE {_UNANSWERED_WHERE}",
        (exclude_user_id,),
    ).fetchone()[0]
    conn.close()
    return total


def get_community_emotional_pulse(sample=300):
    """Distribuição de emoções nos últimos `sample` desabafos publicados.

    O estado emocional coletivo da comunidade agora. Ordena por id DESC (recente)
    porque data_postagem é string e não ordena bem. Funciona em SQLite e Postgres.
    """
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT emotional_tag, COUNT(*) AS total FROM (
            SELECT emotional_tag FROM posts
            WHERE visivel = 1 AND status = 'published' AND COALESCE(is_deleted, 0) = 0
            ORDER BY id DESC
            LIMIT ?
        ) sub
        GROUP BY emotional_tag
        ORDER BY total DESC
        ''',
        (sample,),
    ).fetchall()
    conn.close()
    return rows


def get_emotional_timeline(user_id, limit=300):
    """Posts publicados do usuário em ordem cronológica (mais antigos primeiro).

    Ordena por id (monotônico com a criação) — data_postagem é string dd/mm/YYYY
    e não ordena bem lexicalmente. Base da Linha do Tempo Emocional.
    """
    conn = get_db_connection()
    rows = conn.execute(
        '''
        SELECT id, title, mensagem, categoria, emotional_tag, data_postagem,
               visibility_mode, overcome_at
        FROM posts
        WHERE user_id = ? AND status = 'published' AND COALESCE(is_deleted, 0) = 0
        ORDER BY id ASC
        LIMIT ?
        ''',
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows

def log_sensitive_post(post_id, risk_level):
    """Registra internamente posts de risco sem dados de usuário."""
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO sensitive_post_logs (post_id, risk_level, timestamp)
        VALUES (?, ?, datetime('now'))
        ''',
        (post_id, risk_level),
    )
    conn.commit()
    conn.close()

def get_post_count():
    """Retorna o número total de posts."""
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM posts WHERE status = 'published' AND visivel = 1 AND COALESCE(is_deleted, 0) = 0").fetchone()[0]
    conn.close()
    return count

def get_hidden_post_count():
    """Retorna o número de posts ocultos."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM posts WHERE visivel = 0 AND COALESCE(is_deleted, 0) = 0').fetchone()[0]
    conn.close()
    return count

# Funções para comentários

def get_comments(post_id, include_hidden=False):
    """Retorna os comentários de um post específico."""
    conn = get_db_connection()
    
    if include_hidden:
        comments = conn.execute('''
            SELECT c.id, c.post_id, c.mensagem, c.mensagem AS comment_text, c.data_comentario, c.visivel,
                   c.user_id, u.role AS author_role,
                   u.username AS author_username, u.display_name AS author_display_name
            FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ?
            ORDER BY c.id ASC
        ''', (post_id,)).fetchall()
    else:
        comments = conn.execute('''
            SELECT c.id, c.post_id, c.mensagem, c.mensagem AS comment_text, c.data_comentario, c.visivel,
                   c.user_id, u.role AS author_role,
                   u.username AS author_username, u.display_name AS author_display_name
            FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.post_id = ? AND c.visivel = 1
            ORDER BY c.id ASC
        ''', (post_id,)).fetchall()
    
    conn.close()
    return comments

def get_hidden_comments(post_id):
    """Retorna os comentários ocultos de um post específico."""
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
        FROM comments 
        WHERE post_id = ? AND visivel = 0 
        ORDER BY id ASC
    ''', (post_id,)).fetchall()
    conn.close()
    return comments

def get_all_comments(include_hidden=False):
    """Retorna todos os comentários."""
    conn = get_db_connection()
    
    if include_hidden:
        comments = conn.execute('''
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            ORDER BY id DESC
        ''').fetchall()
    else:
        comments = conn.execute('''
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            WHERE visivel = 1 
            ORDER BY id DESC
        ''').fetchall()
    
    conn.close()
    return comments

def get_all_hidden_comments():
    """Retorna todos os comentários ocultos."""
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
        FROM comments 
        WHERE visivel = 0 
        ORDER BY id DESC
    ''').fetchall()
    conn.close()
    return comments

def get_comment_by_id(comment_id, include_hidden=False):
    """Retorna um comentário específico pelo ID."""
    conn = get_db_connection()
    
    if include_hidden:
        comment = conn.execute('''
            SELECT c.id, c.post_id, c.mensagem, c.mensagem AS comment_text, c.data_comentario, c.visivel,
                   c.user_id, u.role AS author_role,
                   u.username AS author_username, u.display_name AS author_display_name
            FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.id = ?
        ''', (comment_id,)).fetchone()
    else:
        comment = conn.execute('''
            SELECT c.id, c.post_id, c.mensagem, c.mensagem AS comment_text, c.data_comentario, c.visivel,
                   c.user_id, u.role AS author_role,
                   u.username AS author_username, u.display_name AS author_display_name
            FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.id = ? AND c.visivel = 1
        ''', (comment_id,)).fetchone()
    
    conn.close()
    return comment

def create_comment(post_id, comment_text, user_id=None):
    """Cria um novo comentário para um post, associado ao autor."""
    conn = get_db_connection()
    data_comentario = datetime.now().strftime("%d/%m/%Y %H:%M")
    comment_text = trim_text(comment_text)
    if len(comment_text) < LIMITS["comment_content_min"] or len(comment_text) > LIMITS["comment_content_max"]:
        conn.close()
        return None

    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO comments (post_id, mensagem, data_comentario, visivel, user_id)
            VALUES (?, ?, ?, 1, ?)
        ''', (post_id, comment_text, data_comentario, user_id))
        
        comment_id = cursor.lastrowid
        conn.commit()
        return comment_id
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.create_comment", "comments.insert", e,
                      post_id=post_id, table="comments", operation="insert")
        raise  # deixa a rota mostrar o erro REAL
    finally:
        conn.close()

def update_comment_visibility(comment_id, visibility):
    """Atualiza a visibilidade de um comentário."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE comments
                SET visivel = ?
        WHERE id = ?
    ''', (visibility, comment_id))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

def get_comment_count():
    """Retorna o número total de comentários."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM comments').fetchone()[0]
    conn.close()
    return count

def get_hidden_comment_count():
    """Retorna o número de comentários ocultos."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM comments WHERE visivel = 0').fetchone()[0]
    conn.close()
    return count

# Funções para reações

def add_reaction(post_id, reaction_type, user_id='anonymous'):
    """Registra a reação de um usuário (no máx. 1 por tipo). Contagem é ao vivo."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Evita reação duplicada do mesmo usuário no mesmo tipo.
        existing = cursor.execute('''
            SELECT id FROM reactions
            WHERE post_id = ? AND reaction_type = ? AND user_id = ?
        ''', (post_id, reaction_type, user_id)).fetchone()
        if existing:
            return False

        cursor.execute('''
            INSERT INTO reactions (post_id, reaction_type, user_id, data_reacao)
            VALUES (?, ?, ?, datetime('now'))
        ''', (post_id, reaction_type, user_id))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.add_reaction", "reactions.insert", e,
                      post_id=post_id, reaction_type=reaction_type, table="reactions", operation="insert")
        raise  # deixa a rota mostrar o erro REAL, sem mascarar
    finally:
        conn.close()

def get_reaction_counts(post_id):
    """Contagem de cada tipo de reação, calculada AO VIVO a partir de `reactions`.

    Fonte única de verdade = a própria tabela de reações. Sem tabela denormalizada
    pra dessincronizar e sem upsert frágil. Sempre correto após refresh.
    """
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT reaction_type, COUNT(*) AS total
        FROM reactions
        WHERE post_id = ?
        GROUP BY reaction_type
    ''', (post_id,)).fetchall()
    conn.close()

    counts = {}
    for row in rows:
        counts[row['reaction_type']] = row['total']
    return counts

def get_reaction_count():
    """Retorna o número total de reações."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM reactions').fetchone()[0]
    conn.close()
    return count

def get_posts_by_category(categoria, limit=10, offset=0, include_hidden=False):
    """Retorna os posts de uma categoria específica com paginação."""
    conn = get_db_connection()
    
    if include_hidden:
        posts = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.categoria = ? AND COALESCE(p.is_deleted, 0) = 0
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
        ''', (categoria, limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
                   p.mood_type, p.report_count, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode, p.status, p.overcome_at,
                   p.overcome_message, p.listen_only,
                   u.username as author_username,
                   u.nickname as author_nickname,
                   u.display_name as author_display_name,
                   u.profile_photo as author_profile_photo,
                   u.avatar_url as author_avatar_url,
                   u.default_avatar as author_default_avatar,
                   u.role as author_role
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.categoria = ? AND p.visivel = 1 AND p.status = 'published' AND COALESCE(p.is_deleted, 0) = 0
            ORDER BY p.id DESC 
            LIMIT ? OFFSET ?
        ''', (categoria, limit, offset)).fetchall()
    
    conn.close()
    return posts

def get_post_count_by_category(categoria, include_hidden=False):
    """Retorna o número de posts em uma categoria específica."""
    conn = get_db_connection()
    
    if include_hidden:
        count = conn.execute('''
            SELECT COUNT(*) 
            FROM posts 
            WHERE categoria = ? AND COALESCE(is_deleted, 0) = 0
        ''', (categoria,)).fetchone()[0]
    else:
        count = conn.execute('''
            SELECT COUNT(*) 
            FROM posts 
            WHERE categoria = ? AND visivel = 1 AND status = 'published' AND COALESCE(is_deleted, 0) = 0
        ''', (categoria,)).fetchone()[0]
    
    conn.close()
    return count

def get_categories():
    """Retorna todas as categorias distintas usadas nos posts."""
    conn = get_db_connection()
    categories = conn.execute('''
        SELECT DISTINCT categoria 
        FROM posts 
        WHERE visivel = 1 AND status = 'published' AND COALESCE(is_deleted, 0) = 0
        ORDER BY categoria
    ''').fetchall()
    conn.close()
    
    # Converte para uma lista simples
    return [category['categoria'] for category in categories]


# Funções para estatísticas
def get_post_stats():
    """Retorna estatísticas gerais sobre os posts."""
    conn = get_db_connection()
    
    # Total de posts
    total_posts = conn.execute("SELECT COUNT(*) FROM posts WHERE visivel = 1 AND status = 'published'").fetchone()[0]
    
    # Posts por categoria
    posts_by_category = conn.execute('''
        SELECT categoria, COUNT(*) as count 
        FROM posts 
        WHERE visivel = 1 
        GROUP BY categoria 
        ORDER BY count DESC
    ''').fetchall()
    
    if USE_POSTGRES:
        posts_by_weekday = conn.execute('''
            SELECT
                CASE dow
                    WHEN 0 THEN 'Domingo'
                    WHEN 1 THEN 'Segunda'
                    WHEN 2 THEN 'Terça'
                    WHEN 3 THEN 'Quarta'
                    WHEN 4 THEN 'Quinta'
                    WHEN 5 THEN 'Sexta'
                    WHEN 6 THEN 'Sábado'
                END as dia_semana,
                COUNT(*) as count
            FROM (
                SELECT EXTRACT(DOW FROM COALESCE(updated_at, CURRENT_TIMESTAMP))::int as dow
                FROM posts
                WHERE visivel = 1
            ) grouped_posts
            GROUP BY dow
            ORDER BY dow
        ''').fetchall()

        posts_by_hour = conn.execute('''
            SELECT
                TO_CHAR(COALESCE(updated_at, CURRENT_TIMESTAMP), 'HH24') as hora,
                COUNT(*) as count
            FROM posts
            WHERE visivel = 1
            GROUP BY hora
            ORDER BY hora
        ''').fetchall()
    else:
        # Posts por dia da semana
        posts_by_weekday = conn.execute('''
            SELECT
                CASE
                    WHEN strftime('%w', data_postagem) = '0' THEN 'Domingo'
                    WHEN strftime('%w', data_postagem) = '1' THEN 'Segunda'
                    WHEN strftime('%w', data_postagem) = '2' THEN 'Terça'
                    WHEN strftime('%w', data_postagem) = '3' THEN 'Quarta'
                    WHEN strftime('%w', data_postagem) = '4' THEN 'Quinta'
                    WHEN strftime('%w', data_postagem) = '5' THEN 'Sexta'
                    WHEN strftime('%w', data_postagem) = '6' THEN 'Sábado'
                END as dia_semana,
                COUNT(*) as count
            FROM posts
            WHERE visivel = 1
            GROUP BY dia_semana
            ORDER BY strftime('%w', data_postagem)
        ''').fetchall()

        # Posts por hora do dia
        posts_by_hour = conn.execute('''
            SELECT
                strftime('%H', data_postagem) as hora,
                COUNT(*) as count
            FROM posts
            WHERE visivel = 1
            GROUP BY hora
            ORDER BY hora
        ''').fetchall()
    
    conn.close()
    
    return {
        'total_posts': total_posts,
        'posts_by_category': posts_by_category,
        'posts_by_weekday': posts_by_weekday,
        'posts_by_hour': posts_by_hour
    }

def get_comment_stats():
    """Retorna estatísticas gerais sobre os comentários."""
    conn = get_db_connection()
    
    # Total de comentários
    total_comments = conn.execute('SELECT COUNT(*) FROM comments').fetchone()[0]
    
    # Média de comentários por post
    avg_comments = conn.execute('''
        SELECT AVG(comment_count) as avg_comments
        FROM (
            SELECT post_id, COUNT(*) as comment_count
            FROM comments
            GROUP BY post_id
        )
    ''').fetchone()[0]
    
    # Posts com mais comentários
    most_commented_posts = conn.execute('''
        SELECT p.id, p.mensagem, COUNT(c.id) as comment_count
        FROM posts p
        JOIN comments c ON p.id = c.post_id
        WHERE p.visivel = 1
        GROUP BY p.id
        ORDER BY comment_count DESC
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return {
        'total_comments': total_comments,
        'avg_comments': avg_comments if avg_comments else 0,
        'most_commented_posts': most_commented_posts
    }

def get_reaction_stats():
    """Retorna estatísticas gerais sobre as reações."""
    conn = get_db_connection()
    
    # Total de reações
    total_reactions = conn.execute('SELECT COUNT(*) FROM reactions').fetchone()[0]
    
    # Reações por tipo
    reactions_by_type = conn.execute('''
        SELECT reaction_type, COUNT(*) as count
        FROM reactions
        GROUP BY reaction_type
        ORDER BY count DESC
    ''').fetchall()
    
    # Posts com mais reações
    most_reacted_posts = conn.execute('''
        SELECT p.id, p.mensagem, COUNT(r.id) as reaction_count
        FROM posts p
        JOIN reactions r ON p.id = r.post_id
        WHERE p.visivel = 1
        GROUP BY p.id
        ORDER BY reaction_count DESC
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return {
        'total_reactions': total_reactions,
        'reactions_by_type': reactions_by_type,
        'most_reacted_posts': most_reacted_posts
    }
def search_posts(query, limit=10, offset=0):
    """Pesquisa posts com base em uma consulta de texto."""
    conn = get_db_connection()
    
    # Usar LIKE para pesquisa de texto simples
    search_query = f"%{query}%"
    
    posts = conn.execute('''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.mood_type, p.report_count, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode, p.status, p.overcome_at, p.overcome_message, p.listen_only,
               u.username as author_username,
               u.nickname as author_nickname,
               u.display_name as author_display_name,
               u.profile_photo as author_profile_photo,
               u.avatar_url as author_avatar_url,
               u.default_avatar as author_default_avatar,
                   u.role as author_role
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.visivel = 1 AND p.status = 'published' AND COALESCE(p.is_deleted, 0) = 0 AND (
            p.mensagem LIKE ? OR
            p.categoria LIKE ? OR
            p.emotional_tag LIKE ?
        )
        ORDER BY p.id DESC 
        LIMIT ? OFFSET ?
    ''', (search_query, search_query, search_query, limit, offset)).fetchall()
    
    conn.close()
    return posts

def count_search_results(query):
    """Conta o número de resultados para uma pesquisa."""
    conn = get_db_connection()
    
    # Usar LIKE para pesquisa de texto simples
    search_query = f"%{query}%"
    
    count = conn.execute('''
        SELECT COUNT(*) 
        FROM posts 
        WHERE visivel = 1 AND status = 'published' AND COALESCE(is_deleted, 0) = 0 AND (
            mensagem LIKE ? OR
            categoria LIKE ? OR
            emotional_tag LIKE ?
        )
    ''', (search_query, search_query, search_query)).fetchone()[0]
    
    conn.close()
    return count


def create_profile(nickname, bio=None):
    """Cria um novo perfil anônimo."""
    conn = get_db_connection()
    
    # Gerar um token único para o perfil
    token = secrets.token_urlsafe(16)
    
    # Inserir o perfil no banco de dados
    cursor = conn.execute('''
        INSERT INTO profiles (nickname, bio, token, created_at)
        VALUES (?, ?, ?, datetime('now'))
    ''', (nickname, bio, token))
    
    conn.commit()
    
    # Obter o ID do perfil recém-criado
    profile_id = cursor.lastrowid
    if profile_id is None:
        profile_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    
    conn.close()
    return profile_id, token

def get_profile_by_token(token):
    """Obtém um perfil pelo token."""
    conn = get_db_connection()
    
    profile = conn.execute('''
        SELECT id, nickname, bio, created_at, token
        FROM profiles
        WHERE token = ?
    ''', (token,)).fetchone()
    
    conn.close()
    return profile

def update_profile(profile_id, nickname=None, bio=None):
    """Atualiza um perfil existente."""
    conn = get_db_connection()
    
    # Construir a consulta de atualização dinamicamente
    update_fields = []
    params = []
    
    if nickname is not None:
        update_fields.append('nickname = ?')
        params.append(nickname)
    
    if bio is not None:
        update_fields.append('bio = ?')
        params.append(bio)
    
    if update_fields:
        query = f'''
            UPDATE profiles
            SET {', '.join(update_fields)}
            WHERE id = ?
        '''
        params.append(profile_id)
        
        conn.execute(query, params)
        conn.commit()
    
    conn.close()
    return True

def get_posts_by_profile(profile_id, limit=10, offset=0):
    """Obtém os posts de um perfil específico."""
    conn = get_db_connection()
    
    posts = conn.execute('''
        SELECT id, mensagem, categoria, data_postagem, visivel
        FROM posts
        WHERE profile_id = ? AND visivel = 1
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    ''', (profile_id, limit, offset)).fetchall()
    
    conn.close()
    return posts

def get_comments_by_profile(profile_id, limit=20, offset=0):
    """Obtém os comentários de um perfil específico."""
    conn = get_db_connection()
    
    comments = conn.execute('''
        SELECT c.id, c.post_id, c.mensagem, c.data_comentario,
               p.mensagem as post_mensagem
        FROM comments c
        JOIN posts p ON c.post_id = p.id
        WHERE c.profile_id = ? AND p.visivel = 1
        ORDER BY c.id DESC
        LIMIT ? OFFSET ?
    ''', (profile_id, limit, offset)).fetchall()
    
    conn.close()
    return comments


REPORT_REASON_VALUES = {"ofensivo", "odio", "assedio", "perigoso", "spam", "exposicao", "outro"}


def create_report(post_id, profile_id=None, user_id=None, reason="outro", details=None):
    """Cria um novo report para um post."""
    conn = get_db_connection()
    reason = trim_text(reason) or "outro"
    reason = reason if reason in REPORT_REASON_VALUES else "outro"
    details = trim_text(details) or None
    if details and len(details) > LIMITS["report_details_max"]:
        conn.close()
        return False, "Conte um pouco menos nos detalhes para conseguirmos receber seu aviso."
    
    # Verificar se o usuário já reportou este post
    if user_id:
        existing_report = conn.execute('''
            SELECT id FROM reports 
            WHERE post_id = ? AND user_id = ? AND status = 'pending'
        ''', (post_id, user_id)).fetchone()

        if existing_report:
            conn.close()
            return False, "Voce ja avisou a moderacao sobre esse desabafo."
    elif profile_id:
        existing_report = conn.execute('''
            SELECT id FROM reports 
            WHERE post_id = ? AND profile_id = ? AND status = 'pending'
        ''', (post_id, profile_id)).fetchone()
        
        if existing_report:
            conn.close()
            return False, "Voce ja avisou a moderacao sobre esse desabafo."
    
    # Criar o report. ATENÇÃO: a coluna `data` é String(20) — no Postgres ela NÃO
    # aceita um timestamp (datetime('now')), só texto. Por isso gravamos uma string.
    data_label = datetime.now().strftime("%d/%m/%Y %H:%M")
    conn.execute('''
        INSERT INTO reports (post_id, profile_id, user_id, reason, details, status, data, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, datetime('now'))
    ''', (post_id, profile_id, user_id, reason, details, data_label))
    
    # Verificar quantos reports o post tem
    report_count = conn.execute('''
        SELECT COUNT(*) FROM reports WHERE post_id = ? AND status = 'pending'
    ''', (post_id,)).fetchone()[0]
    
    # Se atingir 5 ou mais reports, ocultar o post
    if report_count >= 5:
        conn.execute('''
            UPDATE posts SET visivel = 0 WHERE id = ?
        ''', (post_id,))
    conn.execute("UPDATE posts SET report_count = ? WHERE id = ?", (report_count, post_id))
    
    conn.commit()
    conn.close()
    return True, "Obrigada por cuidar deste espaco. A moderacao recebeu seu aviso."

def get_report_count(post_id):
    """Retorna a quantidade de reports de um post."""
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM reports WHERE post_id = ?
    ''', (post_id,)).fetchone()[0]
    conn.close()
    return count

# get_reports_by_post e get_all_reports tinham versões duplicadas/mortas aqui
# (sobrescritas pelas definições vivas mais abaixo). Removidas na limpeza Wave 3.


def add_comment_karma(comment_id, profile_id, karma_type):
    """Adiciona ou atualiza o karma de um comentário (compatível com Postgres).

    Antes dependia de capturar sqlite3.IntegrityError e fazer UPDATE depois — no
    Postgres isso quebra (exceção diferente + transação abortada). Agora checamos
    a existência antes, sem controle de fluxo por exceção.
    """
    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM comment_karma WHERE comment_id = ? AND profile_id = ?",
            (comment_id, profile_id),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE comment_karma SET karma_type = ?, data = datetime('now') WHERE comment_id = ? AND profile_id = ?",
                (karma_type, comment_id, profile_id),
            )
            message = "Karma atualizado com sucesso."
        else:
            conn.execute(
                "INSERT INTO comment_karma (comment_id, profile_id, karma_type, data) VALUES (?, ?, ?, datetime('now'))",
                (comment_id, profile_id, karma_type),
            )
            message = "Karma adicionado com sucesso."
        conn.commit()
        return True, message
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.add_comment_karma", "comment_karma.upsert", e, comment_id=comment_id)
        return False, "Não conseguimos registrar isso agora."
    finally:
        conn.close()

def remove_comment_karma(comment_id, profile_id):
    """Remove o karma de um comentário."""
    conn = get_db_connection()
    
    conn.execute('''
        DELETE FROM comment_karma 
        WHERE comment_id = ? AND profile_id = ?
    ''', (comment_id, profile_id))
    
    conn.commit()
    conn.close()
    return True, "Karma removido com sucesso."

def get_comment_karma_score(comment_id):
    """Retorna o score de karma de um comentário."""
    conn = get_db_connection()
    
    # Contar votos positivos
    up_votes = conn.execute('''
        SELECT COUNT(*) FROM comment_karma 
        WHERE comment_id = ? AND karma_type = 'up'
    ''', (comment_id,)).fetchone()[0]
    
    # Contar votos negativos
    down_votes = conn.execute('''
        SELECT COUNT(*) FROM comment_karma 
        WHERE comment_id = ? AND karma_type = 'down'
    ''', (comment_id,)).fetchone()[0]
    
    conn.close()
    
    # Calcular score (positivos - negativos)
    score = up_votes - down_votes
    return score, up_votes, down_votes

def get_user_comment_karma(comment_id, profile_id):
    """Retorna o karma que um usuário deu para um comentário."""
    conn = get_db_connection()
        
    karma = conn.execute('''
        SELECT karma_type FROM comment_karma 
        WHERE comment_id = ? AND profile_id = ?
    ''', (comment_id, profile_id)).fetchone()
    
    conn.close()
    
    if karma:
        return karma['karma_type']
    return None

def get_comments_with_karma(post_id):
    """Retorna os comentários de um post com informações de karma."""
    conn = get_db_connection()
    
    comments = conn.execute('''
        SELECT c.id, c.mensagem, c.data_comentario,
               COALESCE(SUM(CASE WHEN ck.karma_type = 'up' THEN 1 ELSE 0 END), 0) as up_votes,
               COALESCE(SUM(CASE WHEN ck.karma_type = 'down' THEN 1 ELSE 0 END), 0) as down_votes,
               (COALESCE(SUM(CASE WHEN ck.karma_type = 'up' THEN 1 ELSE 0 END), 0) - 
                COALESCE(SUM(CASE WHEN ck.karma_type = 'down' THEN 1 ELSE 0 END), 0)) as karma_score
        FROM comments c
        LEFT JOIN comment_karma ck ON c.id = ck.comment_id
        WHERE c.post_id = ?
        GROUP BY c.id, c.mensagem, c.data_comentario
        ORDER BY karma_score DESC, c.data_comentario ASC
    ''', (post_id,)).fetchall()
    
    conn.close()
    return comments

def get_high_karma_comments(min_karma=10, limit=50):
    """Retorna comentários com karma alto (apoio confiável)."""
    conn = get_db_connection()
    
    comments = conn.execute('''
        SELECT c.id, c.mensagem, c.data_comentario, c.post_id,
               (COALESCE(SUM(CASE WHEN ck.karma_type = 'up' THEN 1 ELSE 0 END), 0) - 
                COALESCE(SUM(CASE WHEN ck.karma_type = 'down' THEN 1 ELSE 0 END), 0)) as karma_score
        FROM comments c
        LEFT JOIN comment_karma ck ON c.id = ck.comment_id
        GROUP BY c.id, c.mensagem, c.data_comentario, c.post_id
        HAVING karma_score >= ?
        ORDER BY karma_score DESC, c.data_comentario DESC
        LIMIT ?
    ''', (min_karma, limit)).fetchall()
    
    conn.close()
    return comments


# Funções para usuários permanentes

def create_user(username, password, nickname, bio=None, email=None, display_name=None, avatar_url=None, default_visibility_mode='anonymous', profile_photo=None, default_avatar=None):
    """Cria um novo usuário permanente."""
    conn = get_db_connection()
    username = trim_text(username)
    nickname = trim_text(nickname)
    display_name = trim_text(display_name) or nickname or username
    bio = trim_text(bio) or None
    email = trim_text(email) or None
    default_avatar = normalize_default_avatar(default_avatar)

    if not is_valid_username(username):
        conn.close()
        return False, "Username inválido. Use 3 a 30 caracteres (letras, números, _ ou .)."
    if email and not is_valid_email(email):
        conn.close()
        return False, "E-mail inválido."
    if len(password) < LIMITS["password_min"] or len(password) > LIMITS["password_max"]:
        conn.close()
        return False, f"Senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
    if len(nickname) < LIMITS["nickname_min"] or len(nickname) > LIMITS["nickname_max"]:
        conn.close()
        return False, f"Apelido deve ter entre {LIMITS['nickname_min']} e {LIMITS['nickname_max']} caracteres."
    if len(display_name) < LIMITS["display_name_min"] or len(display_name) > LIMITS["display_name_max"]:
        conn.close()
        return False, f"Nome público deve ter entre {LIMITS['display_name_min']} e {LIMITS['display_name_max']} caracteres."
    if bio and len(bio) > LIMITS["bio_max"]:
        conn.close()
        return False, f"Bio deve ter no máximo {LIMITS['bio_max']} caracteres."
    
    # Verificar se o username já existe
    existing_user = conn.execute('''
        SELECT id FROM users WHERE username = ?
    ''', (username,)).fetchone()
    
    if existing_user:
        conn.close()
        return False, "Nome de usuário já existe."

    if email:
        existing_email = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if existing_email:
            conn.close()
            return False, "E-mail já está em uso."
    
    # Hash da senha
    password_hash = hash_password(password)
    
    try:
        # Criar o usuário
        cursor = conn.execute('''
            INSERT INTO users (
                username, password_hash, nickname, display_name, bio, email, avatar_url,
                profile_photo, default_avatar, default_visibility_mode,
                role, is_active, is_admin, is_verified, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 1, 0, 0, datetime('now'), datetime('now'))
        ''', (
            username,
            password_hash,
            nickname,
            display_name,
            bio,
            email,
            avatar_url,
            profile_photo,
            default_avatar,
            default_visibility_mode if default_visibility_mode in ('anonymous', 'profile') else 'anonymous',
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return True, user_id
        
    except Exception as e:
        log_exception(
            logger,
            "database.create_user",
            "users.insert",
            e,
            email=email,
            username=username,
            table="users",
            operation="insert",
        )
        conn.close()
        return False, "Não foi possível criar sua conta. Tente novamente mais tarde."

def authenticate_user(username, password):
    """Autentica um usuário."""
    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, username, nickname, display_name, bio, email, avatar_url, profile_photo,
               default_avatar, default_visibility_mode,
               created_at, updated_at, is_active, is_admin, role, password_hash
        FROM users
        WHERE (username = ? OR email = ?) AND is_active = 1
        """,
        (username, username),
    ).fetchone()
    
    if user and verify_password(password, user["password_hash"]):
        # Atualizar último login
        conn.execute('''
            UPDATE users SET last_login = datetime('now') WHERE id = ?
        ''', (user['id'],))

        if is_legacy_hash(user["password_hash"]):
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
                (hash_password(password), user["id"]),
            )
        conn.commit()
    else:
        user = None
    
    sanitized_user = _sanitize_user_row(user)
    conn.close()
    return sanitized_user

def get_user_by_id(user_id):
    """Retorna um usuário pelo ID."""
    conn = get_db_connection()
    
    user = conn.execute('''
        SELECT id, username, nickname, display_name, bio, email, avatar_url, profile_photo,
               default_avatar, default_visibility_mode,
               role, created_at, updated_at, last_login, is_active, is_admin, is_verified, email_verified_at
        FROM users 
        WHERE id = ? AND is_active = 1
    ''', (user_id,)).fetchone()
    
    conn.close()
    return user

def get_user_by_username(username):
    """Retorna um usuário pelo username."""
    conn = get_db_connection()
    
    user = conn.execute('''
SELECT id, username, nickname, display_name, bio, email, avatar_url, profile_photo,
               default_avatar, default_visibility_mode,
               role, created_at, updated_at, last_login, is_active, is_admin, is_verified, email_verified_at
        FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,)).fetchone()
    
    conn.close()
    return user


def get_user_by_email(email):
    """Retorna um usuário pelo e-mail."""
    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, username, nickname, display_name, bio, email, avatar_url, profile_photo,
               default_avatar, default_visibility_mode,
               created_at, last_login, is_active, is_admin, role, updated_at, is_verified, email_verified_at
        FROM users
        WHERE email = ? AND is_active = 1
        """,
        (email,),
    ).fetchone()

    conn.close()
    return user


def get_all_users(search=None, limit=200):
    """Lista usuários ativos para a gestão de cargos (admin)."""
    conn = get_db_connection()
    if search and search.strip():
        like = f"%{search.strip()}%"
        users = conn.execute('''
            SELECT id, username, nickname, display_name, email, role,
                   is_admin, is_verified, created_at
            FROM users
            WHERE is_active = 1
              AND (username LIKE ? OR display_name LIKE ? OR nickname LIKE ? OR email LIKE ?)
            ORDER BY id ASC
            LIMIT ?
        ''', (like, like, like, like, limit)).fetchall()
    else:
        users = conn.execute('''
            SELECT id, username, nickname, display_name, email, role,
                   is_admin, is_verified, created_at
            FROM users
            WHERE is_active = 1
            ORDER BY id ASC
            LIMIT ?
        ''', (limit,)).fetchall()
    conn.close()
    return users


def update_user_role(user_id, role):
    """Define o cargo (selo) de um usuário. Só o selo — não altera is_admin.

    O acesso à moderação continua governado por is_admin / create-admin.
    """
    from utils.roles import normalize_role
    role = normalize_role(role)
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
            (role, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.update_user_role", "users.update", e,
                      user_id=user_id, table="users", operation="update")
        return False
    finally:
        conn.close()


def update_user(user_id, username=None, nickname=None, bio=None, email=None, display_name=None, avatar_url=None, profile_photo=None, default_avatar=None, default_visibility_mode=None):
    """Atualiza informações do usuário."""
    conn = get_db_connection()
    
    updates = []
    params = []

    if username is not None:
        username = trim_text(username)
        if not is_valid_username(username):
            conn.close()
            return False, "Esse nome precisa ter entre 3 e 30 caracteres e usar apenas letras, números, _ ou ponto."
        existing_username = conn.execute(
            "SELECT id FROM users WHERE username = ? AND id <> ?",
            (username, user_id),
        ).fetchone()
        if existing_username:
            conn.close()
            return False, "Esse nome já está em uso."
        updates.append("username = ?")
        params.append(username)
    
    if nickname is not None:
        nickname = trim_text(nickname)
        if len(nickname) < LIMITS["nickname_min"] or len(nickname) > LIMITS["nickname_max"]:
            conn.close()
            return False, f"O apelido precisa ter entre {LIMITS['nickname_min']} e {LIMITS['nickname_max']} caracteres."
        updates.append("nickname = ?")
        params.append(nickname)
    
    if bio is not None:
        bio = trim_text(bio) or None
        if bio and len(bio) > LIMITS["bio_max"]:
            conn.close()
            return False, f"Sua bio precisa ter no máximo {LIMITS['bio_max']} caracteres."
        updates.append("bio = ?")
        params.append(bio)
        
    if display_name is not None:
        display_name = trim_text(display_name)
        if len(display_name) < LIMITS["display_name_min"] or len(display_name) > LIMITS["display_name_max"]:
            conn.close()
            return False, f"O nome público precisa ter entre {LIMITS['display_name_min']} e {LIMITS['display_name_max']} caracteres."
        updates.append("display_name = ?")
        params.append(display_name)

    if avatar_url is not None:
        updates.append("avatar_url = ?")
        params.append(avatar_url)

    if profile_photo is not None:
        updates.append("profile_photo = ?")
        params.append(profile_photo)

    if default_avatar is not None:
        updates.append("default_avatar = ?")
        params.append(normalize_default_avatar(default_avatar))

    if default_visibility_mode in ('anonymous', 'profile'):
        updates.append("default_visibility_mode = ?")
        params.append(default_visibility_mode)
    
    if email is not None:
        email = trim_text(email) or None
        if email and not is_valid_email(email):
            conn.close()
            return False, "Esse e-mail não parece válido."
        existing_email = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id <> ?",
            (email, user_id),
        ).fetchone()
        if existing_email:
            conn.close()
            return False, "Esse e-mail já está em uso."
        updates.append("email = ?")
        params.append(email)
    
    if not updates:
        conn.close()
        return False, "Nenhuma informação para atualizar."
    
    updates.append("updated_at = datetime('now')")
    params.append(user_id)
    
    try:
        conn.execute(f'''
            UPDATE users SET {", ".join(updates)} WHERE id = ?
        ''', params)
        
        conn.commit()
        conn.close()
        return True, "Seu perfil foi atualizado."
        
    except Exception as e:
        conn.close()
        return False, "Não conseguimos salvar isso agora. Tente de novo em instantes."

def change_password(user_id, old_password, new_password):
    """Altera a senha do usuário."""
    conn = get_db_connection()
    
    # Verificar senha atual
    user = conn.execute('''
        SELECT id, password_hash FROM users WHERE id = ?
    ''', (user_id,)).fetchone()
    
    if not user or not verify_password(old_password, user["password_hash"]):
        conn.close()
        return False, "Senha atual incorreta."
    
    # Atualizar senha
    new_password_hash = hash_password(new_password)
    
    try:
        conn.execute('''
            UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?
        ''', (new_password_hash, user_id))
        
        conn.commit()
        conn.close()
        return True, "Senha alterada com sucesso."
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao alterar senha: {str(e)}"


def set_new_password(user_id, new_password):
    """Define nova senha sem exigir senha antiga (usado no reset com token)."""
    conn = get_db_connection()
    if len(new_password) < LIMITS["password_min"] or len(new_password) > LIMITS["password_max"]:
        conn.close()
        return False, f"Senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
    new_password_hash = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
        (new_password_hash, user_id),
    )
    conn.commit()
    conn.close()
    return True, "Senha redefinida com sucesso."


def create_password_reset_token(user_id, hours_valid=1):
    conn = get_db_connection()
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=hours_valid)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, datetime('now'))",
        (user_id, token, expires_at),
    )
    conn.commit()
    conn.close()
    return token


def consume_password_reset_token(token):
    conn = get_db_connection()
    token = trim_text(token)
    row = conn.execute(
        """
        SELECT id, user_id, expires_at, used_at
        FROM password_reset_tokens
        WHERE token = ?
        """,
        (token,),
    ).fetchone()
    if not row:
        conn.close()
        return False, "Esse caminho de redefinição não parece mais válido. Peça um novo link e tente de novo.", None
    if row["used_at"]:
        conn.close()
        return False, "Esse caminho de redefinição já foi usado. Peça um novo link se ainda precisar.", None
    expires_at = _as_datetime(row["expires_at"])
    if datetime.utcnow() > expires_at:
        conn.close()
        return False, "Esse caminho de redefinição expirou. Peça um novo link e tente de novo.", None
    conn.execute(
        "UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?",
        (row["id"],),
    )
    conn.commit()
    conn.close()
    return True, "Caminho válido.", row["user_id"]


def create_email_verification_token(user_id, hours_valid=48):
    conn = get_db_connection()
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=hours_valid)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO email_verification_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, datetime('now'))",
        (user_id, token, expires_at),
    )
    conn.commit()
    conn.close()
    return token


def verify_email_with_token(token):
    conn = get_db_connection()
    token = trim_text(token)
    row = conn.execute(
        """
        SELECT id, user_id, expires_at, used_at
        FROM email_verification_tokens
        WHERE token = ?
        """,
        (token,),
    ).fetchone()
    if not row:
        conn.close()
        return False, "Esse caminho de confirmação não parece mais válido. Peça um novo envio e tente de novo."
    user = conn.execute("SELECT id, is_verified FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if not user:
        conn.close()
        return False, "Não encontramos essa conta para confirmar o e-mail."
    if user["is_verified"]:
        conn.close()
        return True, "Seu e-mail já está confirmado."
    if row["used_at"]:
        conn.close()
        return False, "Esse caminho de confirmação já foi usado. Peça um novo envio se ainda precisar."
    expires_at = _as_datetime(row["expires_at"])
    if datetime.utcnow() > expires_at:
        conn.close()
        return False, "Esse caminho de confirmação expirou. Peça um novo envio e tente de novo."

    conn.execute("UPDATE email_verification_tokens SET used_at = datetime('now') WHERE id = ?", (row["id"],))
    conn.execute("UPDATE users SET is_verified = 1, email_verified_at = datetime('now') WHERE id = ?", (row["user_id"],))
    conn.commit()
    conn.close()
    return True, "Seu e-mail foi confirmado."


def create_notification(user_id, notification_type, title, message, reference_id=None):
    title = trim_text(title)
    message = trim_text(message)
    if not title or not message:
        return False
    if len(title) > LIMITS["notification_title_max"] or len(message) > LIMITS["notification_message_max"]:
        return False
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO notifications (user_id, type, title, message, reference_id, is_read, created_at)
        VALUES (?, ?, ?, ?, ?, 0, datetime('now'))
        """,
        (user_id, trim_text(notification_type)[:30], title, message, reference_id),
    )
    conn.commit()
    conn.close()
    return True


def get_notifications_by_user(user_id, limit=30):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, user_id, type, title, message, reference_id, is_read, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows


def mark_notification_as_read(notification_id, user_id):
    conn = get_db_connection()
    cursor = conn.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        (notification_id, user_id),
    )
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success

def deactivate_user(user_id):
    """Desativa um usuário (soft delete)."""
    conn = get_db_connection()
    
    try:
        conn.execute('''
            UPDATE users SET is_active = 0, updated_at = datetime('now') WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        return True, "Usuário desativado com sucesso."
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao desativar usuário: {str(e)}"


def authenticate_admin(username, password):
    """Autentica usuário com permissão administrativa."""
    user = authenticate_user(username, password)
    if not user:
        return None
    if not user["is_admin"]:
        return None
    return user


def _legacy_ensure_admin_user(username, password, nickname=None, bio=None, email=None):
    """
    Cria ou promove um usuário para administrador.
    Retorna (success, message).
    """
    conn = get_db_connection()
    
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    password_hash = hash_password(password)

    try:
        if existing:
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?,
                    nickname = COALESCE(?, nickname),
                    bio = COALESCE(?, bio),
                    email = COALESCE(?, email),
                    role = 'admin',
                    updated_at = datetime('now'),
                    is_active = 1,
                    is_admin = 1
                WHERE id = ?
                """,
                (password_hash, nickname, bio, email, existing["id"]),
            )
            conn.commit()
            return True, f"Usuário '{username}' promovido/atualizado como admin."

        final_nickname = nickname or username
        conn.execute(
            """
            INSERT INTO users (username, password_hash, nickname, bio, email, role, created_at, updated_at, is_active, is_admin)
            VALUES (?, ?, ?, ?, ?, 'admin', datetime('now'), datetime('now'), 1, 1)
            """,
            (username, password_hash, final_nickname, bio, email),
        )
        conn.commit()
        return True, f"Usuário admin '{username}' criado com sucesso."
    except Exception as e:
        conn.rollback()
        return False, f"Erro ao configurar admin: {str(e)}"
    finally:
        conn.close()

def _username_from_email(email):
    local_part = (email or "").split("@", 1)[0].lower()
    username = re.sub(r"[^a-z0-9_.]+", "_", local_part).strip("._")
    username = username[:LIMITS["username_max"]] or "admin"
    if len(username) < LIMITS["username_min"]:
        username = "admin"
    return username


def _username_available(conn, username, current_user_id=None):
    row = conn.execute(
        "SELECT id FROM users WHERE username = ? AND id <> ?",
        (username, current_user_id or 0),
    ).fetchone()
    return row is None


def _unique_username(conn, base_username):
    base = (base_username or "admin")[:LIMITS["username_max"]]
    if len(base) < LIMITS["username_min"]:
        base = "admin"
    candidate = base
    suffix = 1
    while not _username_available(conn, candidate):
        suffix += 1
        suffix_text = f"_{suffix}"
        candidate = f"{base[:LIMITS['username_max'] - len(suffix_text)]}{suffix_text}"
    return candidate


def ensure_admin_user(username=None, password=None, nickname=None, bio=None, email=None, display_name=None):
    """
    Cria, reseta ou promove um usuario para administrador.
    Procura primeiro pelo e-mail e depois pelo username para evitar duplicidade.
    Retorna (success, message).
    """
    username_was_supplied = bool(trim_text(username))
    username = trim_text(username) or None
    nickname = trim_text(nickname) or None
    display_name = trim_text(display_name) or nickname or "Admin EntreLinhas"
    bio = trim_text(bio) or None
    email = trim_text(email) or None

    if not password or len(password) < LIMITS["password_min"] or len(password) > LIMITS["password_max"]:
        return False, f"A senha do admin precisa ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
    if email and not is_valid_email(email):
        return False, "O e-mail do admin não parece válido."
    if username and not is_valid_username(username):
        return False, "O username do admin precisa ter de 3 a 30 caracteres e usar apenas letras, números, ponto ou underline."
    if not username and not email:
        return False, "Informe ADMIN_EMAIL ou ADMIN_USERNAME para configurar o admin."
    if bio and len(bio) > LIMITS["bio_max"]:
        return False, f"A bio do admin precisa ter no máximo {LIMITS['bio_max']} caracteres."

    conn = get_db_connection()
    try:
        existing = None
        if email:
            existing = conn.execute(
                "SELECT id, username, nickname, display_name, bio, email FROM users WHERE LOWER(email) = LOWER(?)",
                (email,),
            ).fetchone()
        if not existing and username:
            existing = conn.execute(
                "SELECT id, username, nickname, display_name, bio, email FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if existing:
            user_id = existing["id"]
            final_username = username or existing["username"]
            if username_was_supplied and final_username != existing["username"] and not _username_available(conn, final_username, user_id):
                return False, "Esse username já pertence a outra conta."

            final_email = email if email is not None else existing["email"]
            if final_email:
                email_owner = conn.execute(
                    "SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id <> ?",
                    (final_email, user_id),
                ).fetchone()
                if email_owner:
                    return False, "Esse e-mail já pertence a outra conta."

            final_nickname = nickname or existing["nickname"] or final_username
            final_display_name = display_name or existing["display_name"] or final_nickname
            if len(final_nickname) < LIMITS["nickname_min"] or len(final_nickname) > LIMITS["nickname_max"]:
                return False, f"O apelido do admin precisa ter entre {LIMITS['nickname_min']} e {LIMITS['nickname_max']} caracteres."
            if len(final_display_name) < LIMITS["display_name_min"] or len(final_display_name) > LIMITS["display_name_max"]:
                return False, f"O nome público do admin precisa ter entre {LIMITS['display_name_min']} e {LIMITS['display_name_max']} caracteres."

            conn.execute(
                """
                UPDATE users
                SET username = ?,
                    password_hash = ?,
                    nickname = ?,
                    display_name = ?,
                    bio = ?,
                    email = ?,
                    role = 'admin',
                    updated_at = datetime('now'),
                    is_active = 1,
                    is_admin = 1,
                    is_verified = CASE WHEN ? IS NULL THEN is_verified ELSE 1 END,
                    email_verified_at = CASE WHEN ? IS NULL THEN email_verified_at ELSE COALESCE(email_verified_at, datetime('now')) END
                WHERE id = ?
                """,
                (
                    final_username,
                    hash_password(password),
                    final_nickname,
                    final_display_name,
                    bio if bio is not None else existing["bio"],
                    final_email,
                    final_email,
                    final_email,
                    user_id,
                ),
            )
            conn.commit()
            return True, f"Admin '{final_username}' atualizado com segurança."

        if not username:
            username = _unique_username(conn, _username_from_email(email))
        elif not _username_available(conn, username):
            return False, "Esse username já pertence a outra conta."

        if email:
            email_owner = conn.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
            if email_owner:
                return False, "Esse e-mail já pertence a outra conta."

        final_nickname = nickname or "Admin EntreLinhas"
        final_display_name = display_name or final_nickname
        if len(final_nickname) < LIMITS["nickname_min"] or len(final_nickname) > LIMITS["nickname_max"]:
            return False, f"O apelido do admin precisa ter entre {LIMITS['nickname_min']} e {LIMITS['nickname_max']} caracteres."
        if len(final_display_name) < LIMITS["display_name_min"] or len(final_display_name) > LIMITS["display_name_max"]:
            return False, f"O nome público do admin precisa ter entre {LIMITS['display_name_min']} e {LIMITS['display_name_max']} caracteres."

        conn.execute(
            """
            INSERT INTO users (
                username, password_hash, nickname, display_name, bio, email,
                role, created_at, updated_at, is_active, is_admin, is_verified,
                email_verified_at, default_avatar, default_visibility_mode
            )
            VALUES (?, ?, ?, ?, ?, ?, 'admin', datetime('now'), datetime('now'), 1, 1, ?, datetime('now'), 'eco', 'anonymous')
            """,
            (
                username,
                hash_password(password),
                final_nickname,
                final_display_name,
                bio,
                email,
                1 if email else 0,
            ),
        )
        conn.commit()
        return True, f"Admin '{username}' criado com segurança."
    except Exception as e:
        conn.rollback()
        return False, f"Não conseguimos configurar o admin: {str(e)}"
    finally:
        conn.close()


def get_user_stats(user_id):
    """Retorna estatísticas do usuário."""
    conn = get_db_connection()
    
    # Contar posts
    post_count = conn.execute('''
        SELECT COUNT(*) FROM posts WHERE user_id = ?
    ''', (user_id,)).fetchone()[0]
    
    # Contar comentários
    comment_count = conn.execute('''
        SELECT COUNT(*) FROM comments WHERE user_id = ?
    ''', (user_id,)).fetchone()[0]
    
    # Contar karma total dos comentários
    total_karma = conn.execute('''
        SELECT COALESCE(SUM(
            CASE WHEN ck.karma_type = 'up' THEN 1 
                 WHEN ck.karma_type = 'down' THEN -1 
                 ELSE 0 END
        ), 0) as total_karma
        FROM comments c
        LEFT JOIN comment_karma ck ON c.id = ck.comment_id
        WHERE c.user_id = ?
    ''', (user_id,)).fetchone()[0]
    
    echoes_given = conn.execute(
        "SELECT COUNT(*) FROM echoes WHERE user_id = ?",
        (user_id,),
    ).fetchone()[0]

    echoes_received = conn.execute(
        '''
        SELECT COUNT(*)
        FROM echoes e
        JOIN posts p ON p.id = e.post_id
        WHERE p.user_id = ?
        ''',
        (user_id,),
    ).fetchone()[0]

    conn.close()
    
    return {
        'post_count': post_count,
        'comment_count': comment_count,
        'total_karma': total_karma,
        'echoes_given': echoes_given,
        'echoes_received': echoes_received
    }


# Inicializa o banco de dados se este arquivo for executado diretamente
if __name__ == "__main__":
    init_db()
    print("Banco de dados inicializado com sucesso!")


# remove_report tinha uma versão duplicada/morta aqui (sobrescrita pela definição
# viva mais abaixo, que aceita user_id). Removida na limpeza Wave 3.


def get_user_reaction(post_id, reaction_type, user_id):
    """Verifica se um usuário já reagiu com um tipo específico a um post."""
    conn = get_db_connection()
    
    reaction = conn.execute('''
        SELECT id FROM reactions 
        WHERE post_id = ? AND reaction_type = ? AND user_id = ?
    ''', (post_id, reaction_type, user_id)).fetchone()
    
    conn.close()
    return reaction

def remove_reaction(post_id, reaction_type, user_id):
    """Remove a reação do usuário. Contagem é calculada ao vivo (sem denormalização)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            DELETE FROM reactions
            WHERE post_id = ? AND reaction_type = ? AND user_id = ?
        ''', (post_id, reaction_type, user_id))
        affected = cursor.rowcount
        conn.commit()
        return affected > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.remove_reaction", "reactions.delete", e,
                      post_id=post_id, reaction_type=reaction_type, table="reactions", operation="delete")
        raise  # deixa a rota mostrar o erro REAL, sem mascarar
    finally:
        conn.close()



# Funções para reports de comentários

def report_comment(comment_id, reason, user_id=None):
    """Registra um report para um comentário. Deduplica por usuário logado."""
    conn = get_db_connection()
    cursor = conn.cursor()
    data_report = datetime.now().strftime("%d/%m/%Y %H:%M")
    try:
        # Um mesmo usuário não avisa duas vezes sobre a mesma resposta.
        if user_id is not None:
            existing = cursor.execute(
                "SELECT id FROM reports_comments WHERE comment_id = ? AND user_id = ?",
                (comment_id, user_id),
            ).fetchone()
            if existing:
                return False
        cursor.execute("""
            INSERT INTO reports_comments (comment_id, user_id, reason, data_report, resolved)
            VALUES (?, ?, ?, ?, 0)
        """, (comment_id, user_id, reason, data_report))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.report_comment", "reports_comments.insert", e,
                      comment_id=comment_id, table="reports_comments", operation="insert")
        return False
    finally:
        conn.close()

def get_comment_reports(resolved=None):
    """Retorna reports de comentários, opcionalmente filtrando por status de resolução."""
    conn = get_db_connection()
    query = """
        SELECT rc.id, rc.comment_id, rc.reason, rc.data_report, rc.resolved, c.mensagem as comment_mensagem
        FROM reports_comments rc
        JOIN comments c ON rc.comment_id = c.id
    """
    params = []
    if resolved is not None:
        query += " WHERE rc.resolved = ?"
        params.append(resolved)
    query += " ORDER BY rc.data_report DESC"
    
    reports = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return reports

def resolve_comment_report(report_id):
    """Marca um report de comentário como resolvido."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE reports_comments
            SET resolved = 1
            WHERE id = ?
        """, (report_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Erro ao resolver report de comentário: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def remove_comment_report(report_id):
    """Remove um report de comentário permanentemente."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            DELETE FROM reports_comments
            WHERE id = ?
        """, (report_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Erro ao remover report de comentário: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


DAILY_TEXT_FALLBACKS = [
    {
        "title": "Hoje",
        "content": "Tem dias em que sobreviver em silêncio já é uma forma de coragem.",
        "author_name": "EntreLinhas",
        "mood": "tristeza",
    },
    {
        "title": "Eco",
        "content": "Algumas dores não pedem resposta. Só pedem um lugar onde possam existir.",
        "author_name": "EntreLinhas",
        "mood": "saudade",
    },
    {
        "title": "Entrelinhas",
        "content": "Nem tudo que pesa precisa ser carregado sozinho.",
        "author_name": "EntreLinhas",
        "mood": "esperanca",
    },
    {
        "title": "Vazio",
        "content": "Às vezes o vazio não é ausência. É só um quarto escuro esperando luz.",
        "author_name": "EntreLinhas",
        "mood": "vazio",
    },
    {
        "title": "Recomeço",
        "content": "Você ainda pode ser gentil com a versão de si mesmo que está tentando continuar.",
        "author_name": "EntreLinhas",
        "mood": "recomeco",
    },
]


def get_daily_text(target_date=None):
    """Retorna o texto ativo do dia ou um fallback autoral."""
    if target_date is None:
        target_date = datetime.now().date()
    date_key = target_date.isoformat() if hasattr(target_date, "isoformat") else str(target_date)
    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT id, title, content, author_name, date, mood, is_active
        FROM daily_texts
        WHERE date = ? AND is_active = 1
        LIMIT 1
        """,
        (date_key,),
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    index = target_date.timetuple().tm_yday % len(DAILY_TEXT_FALLBACKS) if hasattr(target_date, "timetuple") else 0
    fallback = dict(DAILY_TEXT_FALLBACKS[index])
    fallback["date"] = date_key
    fallback["is_active"] = 1
    return fallback


def get_active_help_volunteers():
    """Lista contatos cadastrados de apoio emocional quando existirem."""
    conn = get_db_connection()
    volunteers = conn.execute(
        """
        SELECT id, name, professional_title, crp, contact_email, contact_link, bio, is_verified
        FROM psychologists
        WHERE is_active = 1
        ORDER BY is_verified DESC, name ASC
        """
    ).fetchall()
    conn.close()
    return volunteers


def toggle_echo(post_id, user_id):
    """Adiciona ou remove um ECHO do usuario para um post."""
    conn = get_db_connection()
    try:
        post = conn.execute(
            "SELECT id FROM posts WHERE id = ? AND visivel = 1 AND status = 'published' AND COALESCE(is_deleted, 0) = 0",
            (post_id,),
        ).fetchone()
        if not post:
            return False, "not_found", 0, False

        existing = conn.execute(
            "SELECT id FROM echoes WHERE post_id = ? AND user_id = ?",
            (post_id, user_id),
        ).fetchone()
        if existing:
            conn.execute("DELETE FROM echoes WHERE id = ?", (existing["id"],))
            active = False
            action = "removed"
        else:
            conn.execute(
                "INSERT INTO echoes (post_id, user_id, created_at) VALUES (?, ?, datetime('now'))",
                (post_id, user_id),
            )
            active = True
            action = "added"
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM echoes WHERE post_id = ?", (post_id,)).fetchone()[0]
        return True, action, count, active
    except Exception:
        conn.rollback()
        return False, "error", 0, False
    finally:
        conn.close()


def get_echo_state(post_id, user_id=None):
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM echoes WHERE post_id = ?", (post_id,)).fetchone()[0]
    active = False
    if user_id:
        active = bool(
            conn.execute(
                "SELECT id FROM echoes WHERE post_id = ? AND user_id = ?",
                (post_id, user_id),
            ).fetchone()
        )
    conn.close()
    return {"count": count, "active": active}


def get_moderation_stats():
    conn = get_db_connection()
    stats = {
        "pending_reports": conn.execute("SELECT COUNT(*) FROM reports WHERE status = 'pending'").fetchone()[0],
        "sensitive_posts": conn.execute("SELECT COUNT(*) FROM posts WHERE sensitive_flag = 1 AND COALESCE(is_deleted, 0) = 0").fetchone()[0],
        "reported_posts": conn.execute("SELECT COUNT(DISTINCT post_id) FROM reports WHERE status = 'pending'").fetchone()[0],
    }
    conn.close()
    return stats


def get_admin_posts(filter_mode="all", limit=50, offset=0):
    conn = get_db_connection()
    filters = ["COALESCE(p.is_deleted, 0) = 0"]
    params = []
    if filter_mode == "visible":
        filters.append("p.visivel = 1")
    elif filter_mode == "hidden":
        filters.append("p.visivel = 0")
    elif filter_mode == "sensitive":
        filters.append("p.sensitive_flag = 1")
    elif filter_mode in ("reported", "pending"):
        filters.append("p.report_count > 0")
    where_clause = " AND ".join(filters)
    params.extend([limit, offset])
    posts = conn.execute(
        f"""
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.report_count, p.data_postagem, p.visivel, p.status,
               u.username as author_username, u.display_name as author_display_name
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE {where_clause}
        ORDER BY p.report_count DESC, p.id DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params),
    ).fetchall()
    conn.close()
    return posts


def get_reports_by_post(post_id):
    conn = get_db_connection()
    reports = conn.execute(
        """
        SELECT r.id, r.data, r.created_at, r.reason, r.details, r.status,
               p.nickname, u.username
        FROM reports r
        LEFT JOIN profiles p ON r.profile_id = p.id
        LEFT JOIN users u ON r.user_id = u.id
        WHERE r.post_id = ?
        ORDER BY r.created_at DESC, r.data DESC
        """,
        (post_id,),
    ).fetchall()
    conn.close()
    return reports


# ---------------------------------------------------------------------------
# Fila de moderação (Wave 2): conteúdo sensível/denunciado + histórico de ações
# ---------------------------------------------------------------------------

def get_sensitive_posts_for_queue(limit=50, offset=0):
    """Desabafos marcados como sensíveis e ainda visíveis (precisam de revisão)."""
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT p.id, p.title, p.mensagem, p.categoria, p.emotional_tag, p.sensitive_flag,
               p.report_count, p.data_postagem, p.visivel, p.status, p.visibility_mode,
               u.username AS author_username, u.display_name AS author_display_name
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.sensitive_flag = 1 AND p.visivel = 1
          AND COALESCE(p.is_deleted, 0) = 0 AND p.status = 'published'
        ORDER BY p.report_count DESC, p.id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    conn.close()
    return rows


def get_reported_comments_for_queue(limit=50):
    """Respostas com denúncias não resolvidas, agrupadas, com contagem e post de origem."""
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT c.id, c.post_id, c.mensagem, c.data_comentario, c.visivel,
               COUNT(rc.id) AS report_count,
               MAX(rc.data_report) AS last_report
        FROM comments c
        JOIN reports_comments rc ON rc.comment_id = c.id
        WHERE COALESCE(rc.resolved, 0) = 0 AND c.visivel = 1
        GROUP BY c.id, c.post_id, c.mensagem, c.data_comentario, c.visivel
        ORDER BY report_count DESC, c.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def clear_post_sensitive_flag(post_id):
    """Marca o post como revisado/ok: tira o flag de sensível (sai da fila), mantém visível."""
    conn = get_db_connection()
    try:
        cursor = conn.execute("UPDATE posts SET sensitive_flag = 0 WHERE id = ?", (post_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.clear_post_sensitive_flag", "posts.update", e,
                      post_id=post_id, table="posts", operation="update")
        return False
    finally:
        conn.close()


def soft_delete_post(post_id):
    """Remoção reversível pela moderação: is_deleted=1 + oculta. Preserva o registro."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE posts SET is_deleted = 1, visivel = 0 WHERE id = ?", (post_id,)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.soft_delete_post", "posts.update", e,
                      post_id=post_id, table="posts", operation="update")
        return False
    finally:
        conn.close()


def resolve_comment_reports(comment_id):
    """Resolve todas as denúncias pendentes de uma resposta (tira da fila)."""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE reports_comments SET resolved = 1 WHERE comment_id = ? AND COALESCE(resolved, 0) = 0",
            (comment_id,),
        )
        conn.commit()
        return cursor.rowcount
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.resolve_comment_reports", "reports_comments.update", e,
                      comment_id=comment_id, table="reports_comments", operation="update")
        return 0
    finally:
        conn.close()


def log_moderation_action(target_type, target_id, action, moderator_id=None,
                          moderator_username=None, notes=None):
    """Registra uma ação de moderação na trilha de auditoria."""
    conn = get_db_connection()
    created_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    notes = (notes or "").strip() or None
    try:
        conn.execute(
            "INSERT INTO moderation_actions "
            "(target_type, target_id, action, notes, moderator_id, moderator_username, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target_type, target_id, action, notes, moderator_id, moderator_username, created_at),
        )
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        log_exception(logger, "database.log_moderation_action", "moderation_actions.insert", e,
                      table="moderation_actions", operation="insert")
        return False
    finally:
        conn.close()


def get_moderation_actions(limit=80):
    """Histórico recente de ações de moderação."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM moderation_actions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return rows


def get_moderation_queue_counts():
    """Contagens para os badges da fila."""
    conn = get_db_connection()
    sensitive = conn.execute(
        "SELECT COUNT(*) FROM posts WHERE sensitive_flag = 1 AND visivel = 1 "
        "AND COALESCE(is_deleted, 0) = 0 AND status = 'published'"
    ).fetchone()[0]
    reported_comments = conn.execute(
        "SELECT COUNT(DISTINCT rc.comment_id) FROM reports_comments rc "
        "JOIN comments c ON c.id = rc.comment_id "
        "WHERE COALESCE(rc.resolved, 0) = 0 AND c.visivel = 1"
    ).fetchone()[0]
    conn.close()
    return {"sensitive_posts": sensitive, "reported_comments": reported_comments}


def get_all_reports(limit=50, offset=0, status=None):
    conn = get_db_connection()
    filters = []
    params = []
    if status in ("pending", "resolved", "dismissed"):
        filters.append("r.status = ?")
        params.append(status)
    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    params.extend([limit, offset])
    reports = conn.execute(
        f"""
        SELECT r.id, r.post_id, r.data, r.created_at, r.reason, r.details, r.status,
               p.nickname, u.username,
               posts.mensagem, posts.categoria, posts.emotional_tag, posts.sensitive_flag, posts.visivel,
               (SELECT COUNT(*) FROM reports r2 WHERE r2.post_id = r.post_id AND r2.status = 'pending') as total_reports
        FROM reports r
        LEFT JOIN profiles p ON r.profile_id = p.id
        LEFT JOIN users u ON r.user_id = u.id
        LEFT JOIN posts ON r.post_id = posts.id
        {where_clause}
        ORDER BY total_reports DESC, r.created_at DESC, r.data DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params),
    ).fetchall()
    conn.close()
    return reports


def resolve_report(report_id, status="resolved"):
    if status not in ("resolved", "dismissed"):
        status = "resolved"
    conn = get_db_connection()
    try:
        report = conn.execute("SELECT id, post_id FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not report:
            return False
        conn.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))
        pending = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE post_id = ? AND status = 'pending'",
            (report["post_id"],),
        ).fetchone()[0]
        conn.execute("UPDATE posts SET report_count = ? WHERE id = ?", (pending, report["post_id"]))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()


def remove_report(post_id, profile_id=None, user_id=None):
    """Remove apenas o report do usuario atual."""
    conn = get_db_connection()
    try:
        if user_id:
            cursor = conn.execute(
                "DELETE FROM reports WHERE post_id = ? AND user_id = ?",
                (post_id, user_id),
            )
        elif profile_id:
            cursor = conn.execute(
                "DELETE FROM reports WHERE post_id = ? AND profile_id = ?",
                (post_id, profile_id),
            )
        else:
            return False, "Nao encontramos um aviso seu para desfazer."

        if cursor.rowcount == 0:
            return False, "Nao encontramos um aviso seu para desfazer."

        report_count = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE post_id = ? AND status = 'pending'",
            (post_id,),
        ).fetchone()[0]
        conn.execute("UPDATE posts SET report_count = ? WHERE id = ?", (report_count, post_id))
        if report_count < 5:
            conn.execute("UPDATE posts SET visivel = 1 WHERE id = ?", (post_id,))
        conn.commit()
        return True, "Seu aviso foi retirado."
    except Exception:
        conn.rollback()
        return False, "Nao conseguimos desfazer esse aviso agora."
    finally:
        conn.close()
