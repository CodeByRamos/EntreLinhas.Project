"""Serviços de autenticação para uso incremental no backend."""

import re
import database as db

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email):
    """Valida formato básico de e-mail."""
    return bool(email and EMAIL_REGEX.match(email))


def generate_username_from_email(email):
    """
    Gera username único a partir do e-mail quando o usuário não informar um.
    Mantém compatibilidade com banco atual que exige username único.
    """
    local_part = (email.split("@", 1)[0] if email else "").strip().lower()
    base = re.sub(r"[^a-z0-9_]+", "_", local_part).strip("_") or "usuario"
    candidate = base[:30]
    suffix = 0
    while db.get_user_by_username(candidate):
        suffix += 1
        candidate = f"{base[:24]}_{suffix}"
    return candidate


def register_user(username, password, nickname, bio=None, email=None, display_name=None, avatar_url=None, default_visibility_mode='anonymous'):
    """
    Registra usuário com validações básicas para cadastro com e-mail/senha.
    Retorna (success: bool, payload: dict).
    """
    username = (username or '').strip()
    nickname = (nickname or '').strip()
    email = (email or '').strip() or None

    if not email or not password:
        return False, {'message': 'E-mail e senha são obrigatórios.'}

    if not is_valid_email(email):
        return False, {'message': 'Informe um e-mail válido.'}

    if username and len(username) < 3:
        return False, {'message': 'Username deve ter pelo menos 3 caracteres.'}

    if len(password) < 6:
        return False, {'message': 'Senha deve ter pelo menos 6 caracteres.'}

    if db.get_user_by_email(email):
        return False, {'message': 'E-mail já está em uso.'}

    if username and db.get_user_by_username(username):
        return False, {'message': 'Nome de usuário já existe.'}

    if not username:
        username = generate_username_from_email(email)

    if not nickname:
        nickname = username

    success, result = db.create_user(
        username=username,
        password=password,
        nickname=nickname,
        display_name=display_name or nickname,
        bio=bio,
        email=email,
        avatar_url=avatar_url,
        default_visibility_mode=default_visibility_mode,
    )
    if not success:
        return False, {'message': result}

    user = db.get_user_by_id(result)
    return True, {'message': 'Conta criada com sucesso!', 'user': user}


def authenticate_user(email, password):
    """Autentica via e-mail + senha."""
    email = (email or '').strip()
    if not email or not password:
        return False, {'message': 'E-mail e senha são obrigatórios.'}

    if not is_valid_email(email):
        return False, {'message': 'Informe um e-mail válido.'}

    user = db.authenticate_user(email, password)
    if not user:
        return False, {'message': 'E-mail ou senha incorretos.'}

    return True, {'message': 'Autenticação realizada.', 'user': user}


def get_current_user(session):
    """Obtém usuário atual a partir da sessão Flask sem exigir login global."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.get_user_by_id(user_id)