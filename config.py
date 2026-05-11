import os
from utils.mood_styles import DEFAULT_AVATARS, EMOTIONAL_TAGS

# Configurações básicas
SECRET_KEY = os.environ.get('SECRET_KEY', 'chave-secreta-segura')
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{DB_PATH}")
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(5 * 1024 * 1024)))
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
PERMANENT_SESSION_LIFETIME_HOURS = int(os.environ.get('PERMANENT_SESSION_LIFETIME_HOURS', '24'))

TAGS_EMOCIONAIS = EMOTIONAL_TAGS

REPORT_REASONS = [
    {'valor': 'ofensivo', 'nome': 'Conteudo ofensivo'},
    {'valor': 'odio', 'nome': 'Discurso de odio'},
    {'valor': 'assedio', 'nome': 'Assedio'},
    {'valor': 'perigoso', 'nome': 'Conteudo perigoso'},
    {'valor': 'spam', 'nome': 'Spam'},
    {'valor': 'exposicao', 'nome': 'Exposicao pessoal'},
    {'valor': 'outro', 'nome': 'Outro'},
]

# Configurações de categorias
CATEGORIAS = [
    {'valor': 'estudo', 'nome': 'Estudo'},
    {'valor': 'família', 'nome': 'Família'},
    {'valor': 'trabalho', 'nome': 'Trabalho'},
    {'valor': 'amizade', 'nome': 'Amizade'},
    {'valor': 'relacionamento', 'nome': 'Relacionamento'},
    {'valor': 'saúde', 'nome': 'Saúde'},
    {'valor': 'outros', 'nome': 'Outros'}
]

# Configurações de reações
REACOES = [
    {'valor': 'te_entendo', 'nome': 'Te entendo', 'emoji': '🤝'},
    {'valor': 'forca', 'nome': 'Força!', 'emoji': '💪'},
    {'valor': 'abraco', 'nome': 'Abraço virtual', 'emoji': '🫂'},
    {'valor': 'coracao', 'nome': 'Coração', 'emoji': '❤️'},
    {'valor': 'inspirador', 'nome': 'Inspirador', 'emoji': '✨'}
]
