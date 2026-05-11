import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from utils.mood_styles import EMOTIONAL_TAGS

# Configurações básicas
ENVIRONMENT = os.environ.get('FLASK_ENV', os.environ.get('ENVIRONMENT', 'development')).lower()
IS_PRODUCTION = ENVIRONMENT == 'production'

SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY and not IS_PRODUCTION:
    SECRET_KEY = 'dev-only-change-me'

DB_PATH = os.environ.get(
    'SQLITE_DB_PATH',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')
)
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgresql://'):
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgresql://', 'postgresql+psycopg://', 1)
SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI or f"sqlite:///{DB_PATH}"
SQLALCHEMY_TRACK_MODIFICATIONS = False
USE_POSTGRES = bool(DATABASE_URL and DATABASE_URL.startswith(('postgresql://', 'postgresql+')))

MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', str(5 * 1024 * 1024)))
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
STORAGE_PROVIDER = os.environ.get('STORAGE_PROVIDER', 'local').lower()

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
SESSION_COOKIE_SECURE = os.environ.get(
    'SESSION_COOKIE_SECURE',
    'true' if IS_PRODUCTION else 'false'
).lower() == 'true'
PERMANENT_SESSION_LIFETIME_HOURS = int(os.environ.get('PERMANENT_SESSION_LIFETIME_HOURS', '24'))

TAGS_EMOCIONAIS = EMOTIONAL_TAGS

REPORT_REASONS = [
    {'valor': 'ofensivo', 'nome': 'Conteúdo ofensivo'},
    {'valor': 'odio', 'nome': 'Discurso de ódio'},
    {'valor': 'assedio', 'nome': 'Assédio'},
    {'valor': 'perigoso', 'nome': 'Conteúdo perigoso'},
    {'valor': 'spam', 'nome': 'Spam'},
    {'valor': 'exposicao', 'nome': 'Exposição pessoal'},
    {'valor': 'outro', 'nome': 'Outro'},
]

CATEGORIAS = [
    {'valor': 'estudo', 'nome': 'Estudo'},
    {'valor': 'família', 'nome': 'Família'},
    {'valor': 'trabalho', 'nome': 'Trabalho'},
    {'valor': 'amizade', 'nome': 'Amizade'},
    {'valor': 'relacionamento', 'nome': 'Relacionamento'},
    {'valor': 'saúde', 'nome': 'Saúde'},
    {'valor': 'outros', 'nome': 'Outros'}
]

REACOES = [
    {'valor': 'te_entendo', 'nome': 'Te entendo', 'emoji': '🤝'},
    {'valor': 'forca', 'nome': 'Força', 'emoji': '✦'},
    {'valor': 'abraco', 'nome': 'Abraço virtual', 'emoji': '♡'},
    {'valor': 'coracao', 'nome': 'Coração', 'emoji': '♥'},
    {'valor': 'inspirador', 'nome': 'Inspirador', 'emoji': '✨'}
]
