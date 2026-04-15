import sqlite3
import os

# Caminho do banco de dados
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')

def init_db():
    # Conectar ao banco de dados (ou criar se não existir)
    conn = sqlite3.connect(DB_PATH)
    
    # Criar tabela de posts
    conn.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mensagem TEXT NOT NULL,
        categoria TEXT NOT NULL,
        data_postagem TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        visivel BOOLEAN DEFAULT 1,
        user_id INTEGER,
        profile_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Criar tabela de comentários
    conn.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        mensagem TEXT NOT NULL,
        data_comentario TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        profile_id INTEGER,
        FOREIGN KEY (post_id) REFERENCES posts (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Criar tabela de reações
    conn.execute('''
    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        reaction_type TEXT NOT NULL,
        user_id INTEGER,
        profile_id INTEGER,
        FOREIGN KEY (post_id) REFERENCES posts (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Criar tabela de usuários (contas permanentes)
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        nickname TEXT NOT NULL,
        bio TEXT,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
    ''')
    
    # Criar tabela de perfis anônimos (manter para compatibilidade)
    conn.execute('''
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nickname TEXT NOT NULL,
        bio TEXT,
        token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Criar tabela de reports
    conn.execute('''
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
    
    # Criar tabela de karma de comentários
    conn.execute('''
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
    
    # Commit e fechar conexão
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Banco de dados inicializado com sucesso!")

