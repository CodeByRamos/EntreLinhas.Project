import sqlite3
from datetime import datetime, timedelta
import os
import secrets
from utils.security import hash_password, verify_password, is_legacy_hash
from utils.validation import LIMITS, is_valid_email, is_valid_username, trim_text

# Caminho do banco de dados
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')


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

def get_db_connection():
    """Estabelece e retorna uma conexão com o banco de dados."""
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
            visivel INTEGER DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'published',
            alias_name TEXT,
            user_id INTEGER,
            profile_id INTEGER
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
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0,
            is_verified BOOLEAN DEFAULT 0,
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
        CREATE TABLE IF NOT EXISTS sensitive_post_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            risk_level TEXT NOT NULL
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
    _ensure_column(conn, "comments", "mensagem", "TEXT")
    _ensure_column(conn, "comments", "visivel", "INTEGER DEFAULT 1")
    _ensure_column(conn, "comments", "user_id", "INTEGER")
    _ensure_column(conn, "comments", "profile_id", "INTEGER")
    _ensure_column(conn, "reactions", "user_id", "TEXT")
    _ensure_column(conn, "reactions", "profile_id", "INTEGER")
    _ensure_column(conn, "reactions", "data_reacao", "TEXT DEFAULT CURRENT_TIMESTAMP")
    _ensure_column(conn, "users", "is_admin", "BOOLEAN DEFAULT 0")
    _ensure_column(conn, "users", "role", "TEXT NOT NULL DEFAULT 'user'")
    _ensure_column(conn, "users", "is_verified", "BOOLEAN DEFAULT 0")
    _ensure_column(conn, "users", "email_verified_at", "TIMESTAMP")
    _ensure_column(conn, "users", "display_name", "TEXT")
    _ensure_column(conn, "users", "avatar_url", "TEXT")
    _ensure_column(conn, "users", "default_visibility_mode", "TEXT DEFAULT 'anonymous'")
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
        UPDATE posts
        SET status = CASE
            WHEN status IN ('draft', 'published') THEN status
            ELSE 'published'
        END
        """
    )
    conn.execute(
        """
        UPDATE users
        SET updated_at = COALESCE(updated_at, created_at, datetime('now'))
        WHERE updated_at IS NULL
        """
    )
    _ensure_unique_index(conn, "idx_users_email_unique", "users", "email")
    
    conn.commit()
    conn.close()

# Funções para posts (desabafos)

def get_posts(limit=10, offset=0, include_hidden=False):
    """Retorna os posts mais recentes com paginação."""
    conn = get_db_connection()
    
    if include_hidden:
        posts = conn.execute('''
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                   u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                   u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.visivel = 1 AND p.status = 'published'
            ORDER BY p.id DESC 
            LIMIT ? OFFSET ?
            ''', (limit, offset)).fetchall()
    
    conn.close()
    return posts

def get_hidden_posts(limit=50):
    """Retorna os posts ocultos mais recentes."""
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT p.id, p.title, p.mensagem, p.categoria, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode,
               u.username as author_username,
               u.nickname as author_nickname
        FROM posts p
        LEFT JOIN users u ON p.user_id = u.id
        WHERE p.visivel = 0 
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
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                                      u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        ''', (post_id,)).fetchone()
    else:
        post = conn.execute('''
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                   u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ? AND p.visivel = 1 AND p.status = 'published'
        ''', (post_id,)).fetchone()
    
    conn.close()
    return post

def get_posts_by_user(user_id, limit=10, offset=0, include_hidden=True, visibility_mode=None, status=None):
    """Retorna posts de um usuário com paginação."""
    conn = get_db_connection()
    filters = ["p.user_id = ?"]
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
        SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
               p.user_id, p.visibility_mode,
               p.status AS status,
               u.username as author_username,
               u.nickname as author_nickname
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
    filters = ["user_id = ?"]
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

def update_post(post_id, mensagem, categoria, visibility_mode, title=None, status="published"):
    """Atualiza os dados de um post."""
    mensagem = trim_text(mensagem)
    categoria = trim_text(categoria)
    title = trim_text(title) or None
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
        SET mensagem = ?, categoria = ?, visibility_mode = ?, title = ?, status = ?
        WHERE id = ?
        ''',
        (mensagem, categoria, visibility_mode, title, status, post_id),
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
        conn.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
        cursor = conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.commit()
        return cursor.rowcount > 0
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()

def create_post(mensagem, categoria, user_id, visibility_mode='anonymous', title=None, status='published'):
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
    
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO posts (mensagem, categoria, data_postagem, user_id, visibility_mode, status, title)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (mensagem, categoria, data_postagem, user_id, visibility_mode, status, title))
    
    post_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return post_id

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

def log_sensitive_post(post_id, risk_level):
    """Registra internamente posts de risco sem dados de usuário."""
    conn = get_db_connection()
    conn.execute(
        '''
        INSERT INTO sensitive_post_logs (post_id, risk_level)
        VALUES (?, ?)
        ''',
        (post_id, risk_level),
    )
    conn.commit()
    conn.close()

def get_post_count():
    """Retorna o número total de posts."""
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM posts WHERE status = 'published'").fetchone()[0]
    conn.close()
    return count

def get_hidden_post_count():
    """Retorna o número de posts ocultos."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM posts WHERE visivel = 0').fetchone()[0]
    conn.close()
    return count

# Funções para comentários

def get_comments(post_id, include_hidden=False):
    """Retorna os comentários de um post específico."""
    conn = get_db_connection()
    
    if include_hidden:
        comments = conn.execute('''
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            WHERE post_id = ? 
            ORDER BY id ASC
        ''', (post_id,)).fetchall()
    else:
        comments = conn.execute('''
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            WHERE post_id = ? AND visivel = 1
            ORDER BY id ASC
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
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            WHERE id = ?
        ''', (comment_id,)).fetchone()
    else:
        comment = conn.execute('''
            SELECT id, post_id, mensagem, mensagem AS comment_text, data_comentario, visivel 
            FROM comments 
            WHERE id = ? AND visivel = 1
        ''', (comment_id,)).fetchone()
    
    conn.close()
    return comment

def create_comment(post_id, comment_text):
    """Cria um novo comentário para um post."""
    conn = get_db_connection()
    data_comentario = datetime.now().strftime("%d/%m/%Y %H:%M")
    comment_text = trim_text(comment_text)
    if len(comment_text) < LIMITS["comment_content_min"] or len(comment_text) > LIMITS["comment_content_max"]:
        conn.close()
        return None
    
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO comments (post_id, mensagem, data_comentario)
            VALUES (?, ?, ?)
        ''', (post_id, comment_text, data_comentario))
        
        comment_id = cursor.lastrowid
        conn.commit()
        print(f"Comentário criado com ID {comment_id} para o post {post_id}")
        return comment_id
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Erro ao criar comentário: {e}")
        return None
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
    """Adiciona uma reação a um post e atualiza a contagem."""
    conn = get_db_connection()
    
    cursor = conn.cursor()
    try:
        # Primeiro verifica se o usuário já reagiu com este tipo
        existing_user_reaction = cursor.execute('''
            SELECT id FROM reactions 
            WHERE post_id = ? AND reaction_type = ? AND user_id = ?
        ''', (post_id, reaction_type, user_id)).fetchone()
        
        if existing_user_reaction:
            # Usuário já reagiu, não adiciona novamente
            conn.close()
            return False
        
        # Registra a reação individual
        cursor.execute('''
            INSERT INTO reactions (post_id, reaction_type, user_id)
            VALUES (?, ?, ?)
        ''', (post_id, reaction_type, user_id))
        
        # Atualiza ou cria a contagem de reações usando INSERT OR REPLACE
        cursor.execute('''
            INSERT OR REPLACE INTO reaction_counts (post_id, reaction_type, count)
            VALUES (?, ?, COALESCE((SELECT count FROM reaction_counts WHERE post_id = ? AND reaction_type = ?), 0) + 1)
        ''', (post_id, reaction_type, post_id, reaction_type))
        
        conn.commit()
        print(f"Reação '{reaction_type}' adicionada e contagem atualizada para o post {post_id}.")
        return True
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Erro ao adicionar reação ou atualizar contagem: {e}")
        return False
    finally:
        conn.close()

def get_reaction_counts(post_id):
    """Retorna a contagem de cada tipo de reação para um post."""
    conn = get_db_connection()
    reaction_counts = conn.execute('''
        SELECT reaction_type, count 
        FROM reaction_counts 
        WHERE post_id = ?
    ''', (post_id,)).fetchall()
    conn.close()
    
    # Converte para um dicionário para facilitar o uso
    counts = {}
    for row in reaction_counts:
        counts[row['reaction_type']] = row['count']
    
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
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                   u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.categoria = ?
            ORDER BY p.id DESC
            LIMIT ? OFFSET ?
        ''', (categoria, limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT p.id, p.mensagem, p.categoria, p.data_postagem, p.visivel,
                   p.user_id, p.visibility_mode,
                   u.username as author_username,
                   u.nickname as author_nickname
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.categoria = ? AND p.visivel = 1 AND p.status = 'published'
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
            WHERE categoria = ?
        ''', (categoria,)).fetchone()[0]
    else:
        count = conn.execute('''
            SELECT COUNT(*) 
            FROM posts 
            WHERE categoria = ? AND visivel = 1 AND status = 'published'
        ''', (categoria,)).fetchone()[0]
    
    conn.close()
    return count

def get_categories():
    """Retorna todas as categorias distintas usadas nos posts."""
    conn = get_db_connection()
    categories = conn.execute('''
        SELECT DISTINCT categoria 
        FROM posts 
        WHERE visivel = 1 AND status = 'published'
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
        SELECT id, mensagem, categoria, data_postagem, visivel 
        FROM posts 
        WHERE visivel = 1 AND (
            mensagem LIKE ? OR
            categoria LIKE ?
        )
        ORDER BY id DESC 
        LIMIT ? OFFSET ?
    ''', (search_query, search_query, limit, offset)).fetchall()
    
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
        WHERE visivel = 1 AND (
            mensagem LIKE ? OR
            categoria LIKE ?
        )
    ''', (search_query, search_query)).fetchone()[0]
    
    conn.close()
    return count


def create_profile(nickname, bio=None):
    """Cria um novo perfil anônimo."""
    conn = get_db_connection()
    
    # Gerar um token único para o perfil
    token = secrets.token_urlsafe(16)
    
    # Inserir o perfil no banco de dados
    conn.execute('''
        INSERT INTO profiles (nickname, bio, token, created_at)
        VALUES (?, ?, ?, datetime('now'))
    ''', (nickname, bio, token))
    
    conn.commit()
    
    # Obter o ID do perfil recém-criado
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


def create_report(post_id, profile_id=None):
    """Cria um novo report para um post."""
    conn = get_db_connection()
    
    # Verificar se o usuário já reportou este post
    if profile_id:
        existing_report = conn.execute('''
            SELECT id FROM reports 
            WHERE post_id = ? AND profile_id = ?
        ''', (post_id, profile_id)).fetchone()
        
        if existing_report:
            conn.close()
            return False, "Você já reportou este desabafo."
    
    # Criar o report
    conn.execute('''
        INSERT INTO reports (post_id, profile_id, data)
        VALUES (?, ?, datetime('now'))
    ''', (post_id, profile_id))
    
    # Verificar quantos reports o post tem
    report_count = conn.execute('''
        SELECT COUNT(*) FROM reports WHERE post_id = ?
    ''', (post_id,)).fetchone()[0]
    
    # Se atingir 5 ou mais reports, ocultar o post
    if report_count >= 5:
        conn.execute('''
            UPDATE posts SET visivel = 0 WHERE id = ?
        ''', (post_id,))
    
    conn.commit()
    conn.close()
    return True, "Desabafo reportado com sucesso."

def get_report_count(post_id):
    """Retorna a quantidade de reports de um post."""
    conn = get_db_connection()
    count = conn.execute('''
        SELECT COUNT(*) FROM reports WHERE post_id = ?
    ''', (post_id,)).fetchone()[0]
    conn.close()
    return count

def get_reports_by_post(post_id):
    """Retorna todos os reports de um post específico."""
    conn = get_db_connection()
    reports = conn.execute('''
        SELECT r.id, r.data, p.nickname
        FROM reports r
        LEFT JOIN profiles p ON r.profile_id = p.id
                                   WHERE r.post_id = ?
        ORDER BY r.data DESC
    ''', (post_id,)).fetchall()
    conn.close()
    return reports

def get_all_reports(limit=50, offset=0):
    """Retorna todos os reports para o painel administrativo."""
    conn = get_db_connection()
    reports = conn.execute('''
        SELECT r.id, r.post_id, r.data, p.nickname, 
               posts.mensagem, posts.categoria,
               COUNT(r2.id) as total_reports
        FROM reports r
        LEFT JOIN profiles p ON r.profile_id = p.id
        LEFT JOIN posts ON r.post_id = posts.id
        LEFT JOIN reports r2 ON r.post_id = r2.post_id
        GROUP BY r.post_id
        ORDER BY total_reports DESC, r.data DESC
        LIMIT ? OFFSET ?
    ''', (limit, offset)).fetchall()
    conn.close()
    return reports


def add_comment_karma(comment_id, profile_id, karma_type):
    """Adiciona ou atualiza o karma de um comentário."""
    conn = get_db_connection()
    
    try:
        # Tentar inserir novo karma
        conn.execute('''
            INSERT INTO comment_karma (comment_id, profile_id, karma_type, data)
            VALUES (?, ?, ?, datetime('now'))
        ''', (comment_id, profile_id, karma_type))
        
        conn.commit()
        conn.close()
        return True, "Karma adicionado com sucesso."
        
    except sqlite3.IntegrityError:
        # Se já existe, atualizar
        conn.execute('''
            UPDATE comment_karma 
            SET karma_type = ?, data = datetime('now')
            WHERE comment_id = ? AND profile_id = ?
        ''', (karma_type, comment_id, profile_id))
        
        conn.commit()
        conn.close()
        return True, "Karma atualizado com sucesso."

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

def create_user(username, password, nickname, bio=None, email=None, display_name=None, avatar_url=None, default_visibility_mode='anonymous'):
    """Cria um novo usuário permanente."""
    conn = get_db_connection()
    username = trim_text(username)
    nickname = trim_text(nickname)
    display_name = trim_text(display_name) or nickname or username
    bio = trim_text(bio) or None
    email = trim_text(email) or None

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
                default_visibility_mode, role, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'user', datetime('now'), datetime('now'))
        ''', (
            username,
            password_hash,
            nickname,
            display_name,
            bio,
            email,
            avatar_url,
            default_visibility_mode if default_visibility_mode in ('anonymous', 'profile') else 'anonymous',
        ))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return True, user_id
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao criar usuário: {str(e)}"

def authenticate_user(username, password):
    """Autentica um usuário."""
    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, username, nickname, display_name, bio, email, avatar_url, default_visibility_mode,
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
        SELECT id, username, nickname, display_name, bio, email, avatar_url, default_visibility_mode,
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
SELECT id, username, nickname, display_name, bio, email, avatar_url, default_visibility_mode,
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
        SELECT id, username, nickname, display_name, bio, email, avatar_url, default_visibility_mode,
               created_at, last_login, is_active, is_admin, role, updated_at, is_verified, email_verified_at
        FROM users
        WHERE email = ? AND is_active = 1
        """,
        (email,),
    ).fetchone()

    conn.close()
    return user

def update_user(user_id, nickname=None, bio=None, email=None, display_name=None, avatar_url=None, default_visibility_mode=None):
    """Atualiza informações do usuário."""
    conn = get_db_connection()
    
    updates = []
    params = []
    
    if nickname is not None:
        nickname = trim_text(nickname)
        if len(nickname) < LIMITS["nickname_min"] or len(nickname) > LIMITS["nickname_max"]:
            conn.close()
            return False, f"Apelido deve ter entre {LIMITS['nickname_min']} e {LIMITS['nickname_max']} caracteres."
        updates.append("nickname = ?")
        params.append(nickname)
    
    if bio is not None:
        bio = trim_text(bio) or None
        if bio and len(bio) > LIMITS["bio_max"]:
            conn.close()
            return False, f"Bio deve ter no máximo {LIMITS['bio_max']} caracteres."
        updates.append("bio = ?")
        params.append(bio)
        
    if display_name is not None:
        display_name = trim_text(display_name)
        if len(display_name) < LIMITS["display_name_min"] or len(display_name) > LIMITS["display_name_max"]:
            conn.close()
            return False, f"Nome público deve ter entre {LIMITS['display_name_min']} e {LIMITS['display_name_max']} caracteres."
        updates.append("display_name = ?")
        params.append(display_name)

    if avatar_url is not None:
        updates.append("avatar_url = ?")
        params.append(avatar_url)

    if default_visibility_mode in ('anonymous', 'profile'):
        updates.append("default_visibility_mode = ?")
        params.append(default_visibility_mode)
    
    if email is not None:
        email = trim_text(email) or None
        if email and not is_valid_email(email):
            conn.close()
            return False, "E-mail inválido."
        existing_email = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id <> ?",
            (email, user_id),
        ).fetchone()
        if existing_email:
            conn.close()
            return False, "E-mail já está em uso."
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
        return True, "Usuário atualizado com sucesso."
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao atualizar usuário: {str(e)}"

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
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
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
        return False, "Token inválido.", None
    if row["used_at"]:
        conn.close()
        return False, "Token já utilizado.", None
    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > expires_at:
        conn.close()
        return False, "Token expirado.", None
    conn.execute(
        "UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?",
        (row["id"],),
    )
    conn.commit()
    conn.close()
    return True, "Token válido.", row["user_id"]


def create_email_verification_token(user_id, hours_valid=48):
    conn = get_db_connection()
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(hours=hours_valid)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
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
        return False, "Token inválido."
    user = conn.execute("SELECT id, is_verified FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if not user:
        conn.close()
        return False, "Conta não encontrada."
    if user["is_verified"]:
        conn.close()
        return False, "Conta já verificada."
    if row["used_at"]:
        conn.close()
        return False, "Token já utilizado."
    expires_at = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > expires_at:
        conn.close()
        return False, "Token expirado."

    conn.execute("UPDATE email_verification_tokens SET used_at = datetime('now') WHERE id = ?", (row["id"],))
    conn.execute("UPDATE users SET is_verified = 1, email_verified_at = datetime('now') WHERE id = ?", (row["user_id"],))
    conn.commit()
    conn.close()
    return True, "E-mail verificado com sucesso."


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
        INSERT INTO notifications (user_id, type, title, message, reference_id)
        VALUES (?, ?, ?, ?, ?)
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


def ensure_admin_user(username, password, nickname=None, bio=None, email=None):
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
    
    conn.close()
    
    return {
        'post_count': post_count,
        'comment_count': comment_count,
        'total_karma': total_karma
    }


# Inicializa o banco de dados se este arquivo for executado diretamente
if __name__ == "__main__":
    init_db()
    print("Banco de dados inicializado com sucesso!")


def remove_report(post_id, profile_id=None):
    """Remove um report de um post."""
    conn = get_db_connection()
    
    try:
        # Verificar se existe um report para remover
        if profile_id:
            existing_report = conn.execute('''
                SELECT id FROM reports 
                WHERE post_id = ? AND profile_id = ?
            ''', (post_id, profile_id)).fetchone()
            
            if not existing_report:
                conn.close()
                return False, "Você não reportou este desabafo."
            
            # Remover o report específico do usuário
            conn.execute('''
                DELETE FROM reports 
                WHERE post_id = ? AND profile_id = ?
            ''', (post_id, profile_id))
        else:
            # Se não há profile_id, remove todos os reports do post (admin)
            conn.execute('''
                DELETE FROM reports WHERE post_id = ?
            ''', (post_id,))
        
        # Verificar quantos reports o post ainda tem
        report_count = conn.execute('''
            SELECT COUNT(*) FROM reports WHERE post_id = ?
        ''', (post_id,)).fetchone()[0]
        
        # Se ficar com menos de 5 reports, tornar o post visível novamente
        if report_count < 5:
            conn.execute('''
                UPDATE posts SET visivel = 1 WHERE id = ?
            ''', (post_id,))
        
        conn.commit()
        conn.close()
        return True, "Report removido com sucesso."
        
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        print(f"Erro ao remover report: {e}")
        return False, "Erro ao remover report."


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
    """Remove uma reação específica de um usuário e atualiza a contagem."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Remove a reação individual
        cursor.execute('''
            DELETE FROM reactions 
            WHERE post_id = ? AND reaction_type = ? AND user_id = ?
        ''', (post_id, reaction_type, user_id))
        
        # Verifica se alguma linha foi afetada
        if cursor.rowcount == 0:
            conn.close()
            return False
        
        # Atualiza a contagem de reações
        current_count = cursor.execute('''
            SELECT count FROM reaction_counts 
            WHERE post_id = ? AND reaction_type = ?
        ''', (post_id, reaction_type)).fetchone()
        
        if current_count and current_count[0] > 1:
            # Decrementa a contagem
            cursor.execute('''
                UPDATE reaction_counts 
                SET count = count - 1 
                WHERE post_id = ? AND reaction_type = ?
            ''', (post_id, reaction_type))
        else:
            # Remove a entrada se a contagem chegou a zero ou menos
            cursor.execute('''
                DELETE FROM reaction_counts 
                WHERE post_id = ? AND reaction_type = ?
            ''', (post_id, reaction_type))
        
        conn.commit()
        print(f"Reação '{reaction_type}' removida e contagem atualizada para o post {post_id}.")
        return True
    except sqlite3.Error as e:
        conn.rollback()
        print(f"Erro ao remover reação ou atualizar contagem: {e}")
        return False
    finally:
        conn.close()



# Funções para reports de comentários

def report_comment(comment_id, reason):
    """Registra um report para um comentário."""
    conn = get_db_connection()
    cursor = conn.cursor()
    data_report = datetime.now().strftime("%d/%m/%Y %H:%M")
    try:
        cursor.execute("""
            INSERT INTO reports_comments (comment_id, reason, data_report)
            VALUES (?, ?, ?)
        """, (comment_id, reason, data_report))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao reportar comentário: {e}")
        conn.rollback()
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
    except sqlite3.Error as e:
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
    except sqlite3.Error as e:
        print(f"Erro ao remover report de comentário: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
    if len(new_password) < LIMITS["password_min"] or len(new_password) > LIMITS["password_max"]:
        conn.close()
        return False, f"Nova senha deve ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."