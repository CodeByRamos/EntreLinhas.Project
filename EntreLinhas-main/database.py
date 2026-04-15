import sqlite3
from datetime import datetime
import os
import secrets

# Caminho do banco de dados
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')

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
            mensagem TEXT NOT NULL,
            data_postagem TEXT NOT NULL,
            categoria TEXT NOT NULL,
            visivel INTEGER DEFAULT 1
        )
    ''')
    
    # Tabela de comentários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            data_comentario TEXT NOT NULL,
            visivel INTEGER DEFAULT 1,
            FOREIGN KEY (post_id) REFERENCES posts (id)
        )
    ''')
    
    # Tabela de reações
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL,
            data_reacao TEXT NOT NULL,
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
    
    conn.commit()
    conn.close()

# Funções para posts (desabafos)

def get_posts(limit=10, offset=0, include_hidden=False):
    """Retorna os posts mais recentes com paginação."""
    conn = get_db_connection()
    
    if include_hidden:
        posts = conn.execute('''
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            ORDER BY id DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            WHERE visivel = 1 
            ORDER BY id DESC 
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
    
    conn.close()
    return posts

def get_hidden_posts(limit=50):
    """Retorna os posts ocultos mais recentes."""
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT id, mensagem, categoria, data_postagem, visivel 
        FROM posts 
        WHERE visivel = 0 
        ORDER BY id DESC 
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return posts

def get_post(post_id, include_hidden=False):
    """Retorna um post específico pelo ID."""
    conn = get_db_connection()
    
    if include_hidden:
        post = conn.execute('''
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            WHERE id = ?
        ''', (post_id,)).fetchone()
    else:
        post = conn.execute('''
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            WHERE id = ? AND visivel = 1
        ''', (post_id,)).fetchone()
    
    conn.close()
    return post

def create_post(mensagem, categoria):
    """Cria um novo post."""
    conn = get_db_connection()
    data_postagem = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO posts (mensagem, categoria, data_postagem)
        VALUES (?, ?, ?)
    ''', (mensagem, categoria, data_postagem))
    
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

def get_post_count():
    """Retorna o número total de posts."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM posts').fetchone()[0]
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
            SELECT id, post_id, mensagem, data_comentario 
            FROM comments 
            WHERE post_id = ? 
            ORDER BY id ASC
        ''', (post_id,)).fetchall()
    else:
        comments = conn.execute('''
            SELECT id, post_id, mensagem, data_comentario 
            FROM comments 
            WHERE post_id = ? 
            ORDER BY id ASC
        ''', (post_id,)).fetchall()
    
    conn.close()
    return comments

def get_hidden_comments(post_id):
    """Retorna os comentários ocultos de um post específico."""
    conn = get_db_connection()
    comments = conn.execute('''
        SELECT id, post_id, comment_text, data_comentario, visivel 
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
            SELECT id, post_id, comment_text, data_comentario, visivel 
            FROM comments 
            ORDER BY id DESC
        ''').fetchall()
    else:
        comments = conn.execute('''
            SELECT id, post_id, comment_text, data_comentario, visivel 
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
        SELECT id, post_id, comment_text, data_comentario, visivel 
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
            SELECT id, post_id, mensagem, data_comentario 
            FROM comments 
            WHERE id = ?
        ''', (comment_id,)).fetchone()
    else:
        comment = conn.execute('''
            SELECT id, post_id, mensagem, data_comentario 
            FROM comments 
            WHERE id = ?
        ''', (comment_id,)).fetchone()
    
    conn.close()
    return comment

def create_comment(post_id, comment_text):
    """Cria um novo comentário para um post."""
    conn = get_db_connection()
    data_comentario = datetime.now().strftime("%d/%m/%Y %H:%M")
    
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
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            WHERE categoria = ?
            ORDER BY id DESC 
            LIMIT ? OFFSET ?
        ''', (categoria, limit, offset)).fetchall()
    else:
        posts = conn.execute('''
            SELECT id, mensagem, categoria, data_postagem, visivel 
            FROM posts 
            WHERE categoria = ? AND visivel = 1 
            ORDER BY id DESC 
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
            WHERE categoria = ? AND visivel = 1
        ''', (categoria,)).fetchone()[0]
    
    conn.close()
    return count

def get_categories():
    """Retorna todas as categorias distintas usadas nos posts."""
    conn = get_db_connection()
    categories = conn.execute('''
        SELECT DISTINCT categoria 
        FROM posts 
        WHERE visivel = 1
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
    total_posts = conn.execute('SELECT COUNT(*) FROM posts WHERE visivel = 1').fetchone()[0]
    
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

def create_user(username, password, nickname, bio=None, email=None):
    """Cria um novo usuário permanente."""
    import hashlib
    
    conn = get_db_connection()
    
    # Verificar se o username já existe
    existing_user = conn.execute('''
        SELECT id FROM users WHERE username = ?
    ''', (username,)).fetchone()
    
    if existing_user:
        conn.close()
        return False, "Nome de usuário já existe."
    
    # Hash da senha
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        # Criar o usuário
        cursor = conn.execute('''
            INSERT INTO users (username, password_hash, nickname, bio, email, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        ''', (username, password_hash, nickname, bio, email))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return True, user_id
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao criar usuário: {str(e)}"

def authenticate_user(username, password):
    """Autentica um usuário."""
    import hashlib
    
    conn = get_db_connection()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    user = conn.execute('''
        SELECT id, username, nickname, bio, email, created_at, is_active
        FROM users 
        WHERE username = ? AND password_hash = ? AND is_active = 1
    ''', (username, password_hash)).fetchone()
    
    if user:
        # Atualizar último login
        conn.execute('''
            UPDATE users SET last_login = datetime('now') WHERE id = ?
        ''', (user['id'],))
        conn.commit()
    
    conn.close()
    return user

def get_user_by_id(user_id):
    """Retorna um usuário pelo ID."""
    conn = get_db_connection()
    
    user = conn.execute('''
        SELECT id, username, nickname, bio, email, created_at, last_login, is_active
        FROM users 
        WHERE id = ? AND is_active = 1
    ''', (user_id,)).fetchone()
    
    conn.close()
    return user

def get_user_by_username(username):
    """Retorna um usuário pelo username."""
    conn = get_db_connection()
    
    user = conn.execute('''
        SELECT id, username, nickname, bio, email, created_at, last_login, is_active
        FROM users 
        WHERE username = ? AND is_active = 1
    ''', (username,)).fetchone()
    
    conn.close()
    return user

def update_user(user_id, nickname=None, bio=None, email=None):
    """Atualiza informações do usuário."""
    conn = get_db_connection()
    
    updates = []
    params = []
    
    if nickname is not None:
        updates.append("nickname = ?")
        params.append(nickname)
    
    if bio is not None:
        updates.append("bio = ?")
        params.append(bio)
    
    if email is not None:
        updates.append("email = ?")
        params.append(email)
    
    if not updates:
        conn.close()
        return False, "Nenhuma informação para atualizar."
    
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
    import hashlib
    
    conn = get_db_connection()
    
    # Verificar senha atual
    old_password_hash = hashlib.sha256(old_password.encode()).hexdigest()
    user = conn.execute('''
        SELECT id FROM users WHERE id = ? AND password_hash = ?
    ''', (user_id, old_password_hash)).fetchone()
    
    if not user:
        conn.close()
        return False, "Senha atual incorreta."
    
    # Atualizar senha
    new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
    
    try:
        conn.execute('''
            UPDATE users SET password_hash = ? WHERE id = ?
        ''', (new_password_hash, user_id))
        
        conn.commit()
        conn.close()
        return True, "Senha alterada com sucesso."
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao alterar senha: {str(e)}"

def deactivate_user(user_id):
    """Desativa um usuário (soft delete)."""
    conn = get_db_connection()
    
    try:
        conn.execute('''
            UPDATE users SET is_active = 0 WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        return True, "Usuário desativado com sucesso."
        
    except Exception as e:
        conn.close()
        return False, f"Erro ao desativar usuário: {str(e)}"

def get_user_stats(user_id):
    """Retorna estatísticas do usuário."""
    conn = get_db_connection()
    
    # Contar posts
    post_count = conn.execute('''
        SELECT COUNT(*) FROM posts WHERE user_id = ? AND visivel = 1
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

