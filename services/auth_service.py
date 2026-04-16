"""Serviços de autenticação para uso incremental no backend."""

import database as db


def register_user(username, password, nickname, bio=None, email=None):
    """
    Registra usuário com validações básicas para cadastro com e-mail/senha.
    Retorna (success: bool, payload: dict).
    """
    username = (username or '').strip()
    nickname = (nickname or '').strip()
    email = (email or '').strip() or None

    if not username or not password or not nickname:
        return False, {'message': 'Username, senha e apelido são obrigatórios.'}

    if len(username) < 3:
        return False, {'message': 'Username deve ter pelo menos 3 caracteres.'}

    if len(password) < 6:
        return False, {'message': 'Senha deve ter pelo menos 6 caracteres.'}

    success, result = db.create_user(
        username=username,
        password=password,
        nickname=nickname,
        bio=bio,
        email=email,
    )
    if not success:
        return False, {'message': result}

    user = db.get_user_by_id(result)
    return True, {'message': 'Conta criada com sucesso!', 'user': user}


def authenticate_user(login, password):
    """Autentica via username ou e-mail + senha."""
    login = (login or '').strip()
    if not login or not password:
        return False, {'message': 'Credenciais obrigatórias.'}

    user = db.authenticate_user(login, password)
    if not user:
        return False, {'message': 'Username/e-mail ou senha incorretos.'}

    return True, {'message': 'Autenticação realizada.', 'user': user}


def get_current_user(session):
    """Obtém usuário atual a partir da sessão Flask sem exigir login global."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.get_user_by_id(user_id)