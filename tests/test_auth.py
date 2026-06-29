"""Fluxo de conta: registro → esqueci a senha → e-mail/token → redefinir → login.

Cobre a recuperação de conta de ponta a ponta (antes sem nenhum teste).
"""
import database as db
from services.email_service import send_password_reset_email


def _register(client, email, password, username):
    return client.post("/registro", data={
        "email": email,
        "username": username,
        "password": password,
        "confirm_password": password,
        "nickname": "Tester",
        "display_name": "Tester",
    })


def _latest_reset_token(uid):
    conn = db._open_raw_connection()
    row = conn.execute(
        "SELECT token FROM password_reset_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (uid,),
    ).fetchone()
    conn.close()
    return row["token"] if row else None


def _clear_session(client):
    with client.session_transaction() as s:
        s.clear()


def test_password_reset_end_to_end(client):
    email = "reset_e2e@example.com"
    old_pw, new_pw = "senhaAntiga123", "senhaNova456"
    _register(client, email, old_pw, "reset_e2e")
    user = db.get_user_by_email(email)
    assert user, "registro deveria criar o usuário"
    uid = user["id"]

    # 1) Pede recuperação de senha.
    r = client.post("/esqueci-senha", data={"email": email})
    assert r.status_code in (200, 302)

    # 2) Um token de reset foi criado para o usuário.
    token = _latest_reset_token(uid)
    assert token, "esqueci-senha deveria gerar um token de redefinição"

    # 3) A página de redefinição abre com o token do link do e-mail.
    assert client.get(f"/redefinir-senha/{token}").status_code == 200

    # 4) Redefine a senha com o token.
    r = client.post("/redefinir-senha", data={
        "token": token, "new_password": new_pw, "confirm_password": new_pw,
    })
    assert r.status_code in (200, 302)

    # 5) A senha NOVA entra; a ANTIGA não.
    assert db.authenticate_user(email, new_pw), "deveria entrar com a senha nova"
    assert not db.authenticate_user(email, old_pw), "a senha antiga não pode mais valer"

    # 6) E o /login HTTP aceita a senha nova (redireciona = sucesso).
    _clear_session(client)
    r = client.post("/login", data={"email": email, "password": new_pw})
    assert r.status_code == 302, "login com a senha nova deveria ter sucesso (redirect)"


def test_reset_email_has_working_link(app):
    """O e-mail aponta para a rota de redefinição com o token (link clicável).

    Usa request context porque o envio sempre acontece durante uma requisição
    (e o context processor global lê request.path ao renderizar o template).
    """
    with app.test_request_context():
        result = send_password_reset_email("alguem@example.com", "tok_ABC123")
        url = result.get("debug_url") or ""
        assert "/redefinir-senha/" in url and "tok_ABC123" in url


def test_forgot_password_does_not_leak_account_existence(client):
    """Mesma resposta para e-mail existente e inexistente (anti-enumeração)."""
    _register(client, "exists@example.com", "senhaForte123", "exists_user")
    a = client.post("/esqueci-senha", data={"email": "exists@example.com"})
    b = client.post("/esqueci-senha", data={"email": "naoexiste@example.com"})
    assert a.status_code == b.status_code
    assert a.get_data(as_text=True) == b.get_data(as_text=True)


def test_reset_token_is_single_use(client):
    email = "single_use@example.com"
    _register(client, email, "senhaForte123", "single_use")
    uid = db.get_user_by_email(email)["id"]
    client.post("/esqueci-senha", data={"email": email})
    token = _latest_reset_token(uid)
    ok1, _msg1, _uid1 = db.consume_password_reset_token(token)
    ok2, _msg2, _uid2 = db.consume_password_reset_token(token)
    assert ok1 is True and ok2 is False, "token de reset deve ser de uso único"


def test_login_rejects_wrong_password(client):
    email = "login_wrong@example.com"
    _register(client, email, "senhaCerta123", "login_wrong")
    assert not db.authenticate_user(email, "senhaErrada999")
    assert db.authenticate_user(email, "senhaCerta123")
