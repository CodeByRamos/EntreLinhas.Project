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
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000').rstrip('/')
# Verificação do Google Search Console: cole aqui (ou na env var) o código da
# meta tag "google-site-verification". Vazio = a tag não é renderizada.
GOOGLE_SITE_VERIFICATION = os.environ.get('GOOGLE_SITE_VERIFICATION', '').strip()

# Apoio ao projeto (monetização sutil). Tudo opcional: a página /apoiar só
# mostra o que estiver preenchido. PIX_KEY pode ser e-mail, CPF, telefone ou
# chave aleatória. NAME/CITY alimentam o "copia e cola"; sem eles, mostramos só
# a chave (Pix manual). RECURRING_URL é um link de apoio mensal (Apoia.se etc.).
PIX_KEY = os.environ.get('PIX_KEY', '').strip()
PIX_RECEIVER_NAME = os.environ.get('PIX_RECEIVER_NAME', '').strip()
PIX_CITY = os.environ.get('PIX_CITY', '').strip()
SUPPORT_RECURRING_URL = os.environ.get('SUPPORT_RECURRING_URL', '').strip()
SUPPORT_RECURRING_LABEL = os.environ.get('SUPPORT_RECURRING_LABEL', 'Apoio mensal').strip()

MAIL_SERVER = os.environ.get('MAIL_SERVER')
MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or MAIL_USERNAME
MAIL_ALLOW_CONSOLE_FALLBACK = os.environ.get(
    'MAIL_ALLOW_CONSOLE_FALLBACK',
    'false' if IS_PRODUCTION else 'true'
).lower() == 'true'

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
SESSION_COOKIE_SECURE = os.environ.get(
    'SESSION_COOKIE_SECURE',
    'true' if IS_PRODUCTION else 'false'
).lower() == 'true'
TEMPLATES_AUTO_RELOAD = not IS_PRODUCTION
PERMANENT_SESSION_LIFETIME_HOURS = int(os.environ.get('PERMANENT_SESSION_LIFETIME_HOURS', '24'))

# --- Segurança: CSRF (Flask-WTF) ---
# Token válido pela vida da sessão (evita expirar enquanto a pessoa escreve um desabafo longo).
WTF_CSRF_TIME_LIMIT = None
WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'

# --- Segurança: Rate limiting (Flask-Limiter) ---
# memory:// basta no Render single-instance; use redis://... em multi-instância.
RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
RATELIMIT_HEADERS_ENABLED = True
# Permite desligar via env caso necessário (ex.: testes de carga internos).
RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'

# --- hCaptcha (proteção anti-bot em cadastro/recuperação) ---
# Sem chaves configuradas, o captcha é simplesmente ignorado (no-op) — não quebra o fluxo.
HCAPTCHA_SITEKEY = os.environ.get('HCAPTCHA_SITEKEY', '')
HCAPTCHA_SECRET = os.environ.get('HCAPTCHA_SECRET', '')
HCAPTCHA_ENABLED = bool(HCAPTCHA_SITEKEY and HCAPTCHA_SECRET)

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

# Reações com ícones de linha (renderizados em SVG pelo front-end, sem emoji).
# 'valor' é a chave persistida no banco — não mude sem migrar os dados existentes.
# Conjunto enxuto: cada reação é uma resposta distinta a um desabafo
# (identificar-se / encorajar / acolher / ser tocado), sem sobreposição.
REACOES = [
    {'valor': 'te_entendo', 'nome': 'Te entendo', 'icon': 'empathy'},
    {'valor': 'forca', 'nome': 'Força', 'icon': 'sprout'},
    {'valor': 'abraco', 'nome': 'Abraço', 'icon': 'embrace'},
    {'valor': 'inspirador', 'nome': 'Me inspirou', 'icon': 'spark'}
]

# Reflexão da Semana — um convite reflexivo que rotaciona por número da semana
# (determinístico, sem banco). Pensado para autoconhecimento, não para engajamento.
REFLEXOES_SEMANAIS = [
    "Qual foi a coisa mais difícil que você enfrentou esta semana?",
    "O que você gostaria de ter dito a alguém, mas não disse?",
    "Que peso você está carregando que talvez já pudesse soltar?",
    "Quando foi a última vez que você se sentiu em paz? O que havia ali?",
    "O que o seu eu de um ano atrás não acreditaria que você superou?",
    "Por quem ou por quê você sente saudade hoje?",
    "O que você precisa ouvir, mas ninguém te disse ainda?",
    "Qual pequena vitória desta semana passou despercebida?",
    "Se o cansaço de hoje pudesse falar, o que ele diria?",
    "O que você tem evitado sentir?",
    "Que parte de você pede mais gentileza ultimamente?",
    "O que mudou em você nos últimos meses, sem você perceber?",
]
