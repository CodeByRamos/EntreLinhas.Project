"""Fixtures de teste do EntreLinhas.

Roda contra um SQLite TEMPORÁRIO isolado (nunca toca o entrelinhas.db real) e
força o caminho SQLite (sem DATABASE_URL). As variáveis de ambiente são
definidas ANTES de importar o app, pois config.py/database.py leem na importação.
"""
import os
import tempfile
import uuid

# --- Ambiente isolado (definido antes de importar o app) ---
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["SQLITE_DB_PATH"] = _tmp.name
os.environ.pop("DATABASE_URL", None)
os.environ["WTF_CSRF_ENABLED"] = "false"      # CSRF off por padrão; testes específicos ligam
os.environ["RATELIMIT_ENABLED"] = "true"
os.environ["SECRET_KEY"] = "test-secret"

import pytest  # noqa: E402
import app as _appmod  # noqa: E402
import database as db  # noqa: E402


@pytest.fixture()
def app():
    application = _appmod.app
    application.testing = True
    application.config["WTF_CSRF_ENABLED"] = False
    _appmod.limiter.enabled = False
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _new_user(is_admin=False):
    """Cria um usuário único e devolve seu id (e o ativa/admina conforme pedido)."""
    uname = "u_" + uuid.uuid4().hex[:12]
    ok, result = db.create_user(uname, "senha-de-teste-123", uname[:20])
    assert ok, f"falha ao criar usuário: {result}"
    uid = result
    if is_admin:
        conn = db._open_raw_connection()
        conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (uid,))
        conn.commit()
        conn.close()
    return uid


@pytest.fixture()
def make_user():
    """Fábrica: cada chamada cria um usuário novo e isolado."""
    return _new_user


@pytest.fixture()
def user_id(make_user):
    return make_user()


@pytest.fixture()
def logged_client(client, user_id):
    with client.session_transaction() as s:
        s["user_id"] = user_id
        s["username"] = "tester"
    client._test_user_id = user_id
    return client


@pytest.fixture()
def admin_client(client):
    aid = _new_user(is_admin=True)
    with client.session_transaction() as s:
        s["admin_logged_in"] = True
        s["admin_user_id"] = aid
        s["admin_username"] = "admin"
    client._test_admin_id = aid
    return client


def make_post(author_id, **kwargs):
    """Helper para criar um post de teste publicado."""
    defaults = dict(
        mensagem="Conteúdo de teste com tamanho mais do que suficiente aqui.",
        categoria="saúde",
        user_id=author_id,
        status="published",
        emotional_tag="vazio",
    )
    defaults.update(kwargs)
    return db.create_post(**defaults)
