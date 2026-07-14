"""Controle de acesso, CSRF, rate limiting e privilégio."""
from conftest import make_post


# --- Gates de autenticação no BACKEND (não dá pra burlar pelo front) ---

def test_guest_cannot_comment(client, make_user):
    pid = make_post(make_user())
    r = client.post(f"/api/comments/{pid}", json={"text": "tentativa anônima de comentar aqui"})
    assert r.status_code == 401
    assert r.get_json().get("auth_required") is True


def test_guest_cannot_react(client, make_user):
    pid = make_post(make_user())
    r = client.post(f"/api/reactions/{pid}", json={"type": "forca"})
    assert r.status_code == 401


def test_guest_cannot_echo(client, make_user):
    pid = make_post(make_user())
    r = client.post(f"/api/echo/{pid}", json={})
    assert r.status_code == 401


def test_guest_cannot_report_post(client, make_user):
    pid = make_post(make_user())
    r = client.post("/api/report", json={"post_id": pid, "reason": "spam"})
    assert r.status_code == 401


def test_guest_cannot_report_comment(client):
    r = client.post("/api/report_comment/1", json={"reason": "spam"})
    assert r.status_code == 401


def test_guest_cannot_post(client):
    r = client.post("/enviar", data={"conteudo": "x" * 20, "categoria": "saúde"})
    assert r.status_code == 302
    assert "/login" in r.headers.get("Location", "")


def test_login_required_pages_redirect_guest(client):
    for url in ["/acolher", "/superacoes", "/linha-do-tempo", "/meus-posts",
                "/cartas/desconhecidos", "/notificacoes"]:
        r = client.get(url)
        assert r.status_code in (301, 302), f"{url} deveria redirecionar guest"


def test_admin_pages_require_admin(client):
    # Sem sessão admin → redireciona para o login admin
    for url in ["/admin/moderacao", "/admin/usuarios", "/admin/posts"]:
        r = client.get(url)
        assert r.status_code in (301, 302)


def test_listen_only_blocks_comments(logged_client, make_user):
    pid = make_post(make_user(), listen_only=True)
    r = logged_client.post(f"/api/comments/{pid}", json={"text": "resposta num somente-escuta"})
    assert r.status_code == 403


# --- Privilégio: o selo de cargo NÃO concede poder de moderação ---

def test_selo_admin_cannot_manage_others_posts():
    from routes.posts import _can_manage_post
    other_post = {"user_id": 999}
    selo_admin = {"id": 1, "is_admin": 0, "role": "admin"}   # só selo cosmético
    real_admin = {"id": 2, "is_admin": 1, "role": "user"}
    owner = {"id": 999, "is_admin": 0, "role": "user"}
    assert _can_manage_post(other_post, selo_admin) is False
    assert _can_manage_post(other_post, real_admin) is True
    assert _can_manage_post(other_post, owner) is True


# --- CSRF (ligado explicitamente neste teste) ---

def test_csrf_blocks_tokenless_form_post(app):
    app.testing = False
    app.config["WTF_CSRF_ENABLED"] = True
    c = app.test_client()
    r = c.post("/login", data={"username": "x", "password": "y"})
    assert r.status_code == 400
    app.config["WTF_CSRF_ENABLED"] = False
    app.testing = True


# --- Rate limiting (ligado explicitamente) ---

def test_security_headers_present(client):
    h = client.get("/").headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert "Referrer-Policy" in h
    assert "Permissions-Policy" in h
    assert "Content-Security-Policy" in h
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_rate_limit_triggers_on_login_flood(app):
    import app as appmod
    appmod.limiter.enabled = True
    try:
        appmod.limiter.reset()
    except Exception:
        pass
    app.config["WTF_CSRF_ENABLED"] = False
    c = app.test_client()
    codes = [c.post("/login", data={"username": "flood", "password": "x"}).status_code
             for _ in range(14)]
    assert 429 in codes, f"esperava 429 no flood, veio {codes}"
    appmod.limiter.enabled = False
