"""Serviços de autenticação para uso incremental no backend."""

import secrets

import database as db
from utils.validation import LIMITS, is_valid_email, is_valid_username

# Palavras suaves, no tom do EntreLinhas, para compor @usernames internos.
_USERNAME_WORDS = (
    "nevoa", "lunar", "eco", "brisa", "aurora", "sereno", "vento", "mare",
    "luz", "noite", "orvalho", "silencio", "abrigo", "raiz", "onda", "verso",
    "limiar", "prisma", "cais", "horizonte", "refugio", "respiro", "vagalume",
    "constelacao", "elo", "alvorada", "recanto", "semente",
)


def generate_random_username():
    """Gera um @username interno ALEATÓRIO e único (ex.: nevoa8421, eco9147).

    Nunca é derivado do e-mail — isso protege a privacidade do usuário. A
    unicidade é garantida por construção: tenta combinações palavra+número e,
    no caso improvável de esgotar, cai num token aleatório.
    """
    for _ in range(50):
        candidate = f"{secrets.choice(_USERNAME_WORDS)}{secrets.randbelow(9000) + 1000}"
        if not db.get_user_by_username(candidate):
            return candidate
    return f"eco{secrets.token_hex(5)}"


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

    if username and not is_valid_username(username):
        return False, {'message': 'Username inválido. Use 3 a 30 caracteres (letras, números, _ ou .).'}

    if len(password) < LIMITS["password_min"] or len(password) > LIMITS["password_max"]:
        return False, {'message': f'Senha deve ter entre {LIMITS["password_min"]} e {LIMITS["password_max"]} caracteres.'}

    if db.get_user_by_email(email):
        return False, {'message': 'E-mail já está em uso.'}

    if username and db.get_user_by_username(username):
        return False, {'message': 'Nome de usuário já existe.'}

    if not username:
        username = generate_random_username()

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