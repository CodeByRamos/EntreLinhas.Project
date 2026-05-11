try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, render_template, session
import database as db
from extensions import db as sqlalchemy_db, migrate
from models import sqlalchemy_schema  # noqa: F401
from routes.main import main
from routes.posts import posts
from routes.comments import comments
from routes.reactions import reactions
from routes.admin import admin
from routes.stats import stats
from routes.search import search
from routes.profile import profile
from routes.reports import reports
from routes.karma import karma
from routes.auth import auth
from routes.notifications import notifications
from routes.help import support
from services.auth_service import get_current_user
from datetime import datetime
from datetime import timedelta
import os

def create_app():
    """Função de fábrica para criar a aplicação Flask."""
    app = Flask(__name__)
    
    # Carrega configurações
    try:
        app.config.from_pyfile('config.py')
    except FileNotFoundError:
        # Configurações padrão para produção
        app.config['DEBUG'] = False
    
    if app.config.get('IS_PRODUCTION'):
        if not app.config.get('USE_POSTGRES'):
            raise RuntimeError('DATABASE_URL com PostgreSQL precisa estar configurada em produção.')
        if app.config.get('STORAGE_PROVIDER', 'local') == 'local':
            raise RuntimeError('Configure storage persistente em produção: cloudinary ou s3.')

    # Configuração para sessões/autenticação
    secret_key = app.config.get('SECRET_KEY') or os.environ.get('SECRET_KEY')
    if not secret_key:
        if app.config.get('IS_PRODUCTION'):
            raise RuntimeError('SECRET_KEY precisa estar configurada em produção.')
        secret_key = 'dev-only-entrelinhas-secret'
    app.secret_key = secret_key
    app.config['SESSION_COOKIE_HTTPONLY'] = app.config.get('SESSION_COOKIE_HTTPONLY', True)
    app.config['SESSION_COOKIE_SAMESITE'] = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config['SESSION_COOKIE_SECURE'] = app.config.get('SESSION_COOKIE_SECURE', False)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
        hours=app.config.get('PERMANENT_SESSION_LIFETIME_HOURS', 24)
    )

    sqlalchemy_db.init_app(app)
    migrate.init_app(app, sqlalchemy_db)
    
    # Inicializa o banco SQLite apenas em desenvolvimento local.
    if not app.config.get('USE_POSTGRES'):
        db.init_db()
    
    # Registra os blueprints
    app.register_blueprint(main)
    app.register_blueprint(posts)
    app.register_blueprint(comments)
    app.register_blueprint(reactions)
    app.register_blueprint(admin)
    app.register_blueprint(stats)
    app.register_blueprint(search)
    app.register_blueprint(profile)
    app.register_blueprint(reports)
    app.register_blueprint(karma)
    app.register_blueprint(auth)
    app.register_blueprint(notifications)
    app.register_blueprint(support)

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(error):
        return render_template('errors/500.html'), 500
    
    # Contexto global para templates
    @app.context_processor
    def inject_now():
        return {
            'now': datetime.now(),
            'current_user': get_current_user(session)
        }
    
    return app

# Cria a aplicação
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
