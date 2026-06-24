from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()

# Extensões de segurança (CSRF + rate limiting). São importadas de forma
# defensiva: se as libs não estiverem instaladas, o app AINDA sobe (com avisos)
# em vez de derrubar o site inteiro com um ModuleNotFoundError no boot.
# O caminho correto continua sendo `pip install -r requirements.txt`.
try:
    from flask_wtf import CSRFProtect
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    # Proteção CSRF para todos os forms/endpoints state-changing.
    csrf = CSRFProtect()

    # Rate limiting por IP. Sem limite global por padrão; cada rota sensível
    # recebe seu @limiter.limit. Storage vem de app.config['RATELIMIT_STORAGE_URI'].
    limiter = Limiter(key_func=get_remote_address)

    SECURITY_AVAILABLE = True
except ImportError:  # pragma: no cover - rede de segurança p/ ambiente sem as deps
    SECURITY_AVAILABLE = False

    class _NoopCSRF:
        """Stub de CSRF quando Flask-WTF não está instalado."""
        def init_app(self, app):
            return None

        def exempt(self, view):
            return view

    class _NoopLimiter:
        """Stub de rate limiter quando Flask-Limiter não está instalado.

        Espelha a superfície usada/plausível da API real para que adicionar
        @limiter.exempt / shared_limit no futuro não derrube o boot num ambiente
        sem a lib (o decorator é aplicado no import dos blueprints)."""
        enabled = False

        def init_app(self, app):
            return None

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

        # Alias: shared_limit tem a mesma forma de decorator que limit.
        shared_limit = limit

        def exempt(self, func=None, **kwargs):
            # Pode ser usado como @limiter.exempt ou @limiter.exempt(...).
            if func is None:
                def decorator(f):
                    return f
                return decorator
            return func

        def request_filter(self, func):
            return func

        def reset(self):
            return None

    csrf = _NoopCSRF()
    limiter = _NoopLimiter()
