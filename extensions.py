from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()

# Proteção CSRF para todos os forms/endpoints state-changing.
csrf = CSRFProtect()

# Rate limiting por IP. Sem limite global por padrão (default_limits vazio);
# cada rota sensível recebe seu @limiter.limit explicitamente. O storage vem de
# app.config['RATELIMIT_STORAGE_URI'] (use Redis em multi-instância; memória basta no Render single).
limiter = Limiter(key_func=get_remote_address)
