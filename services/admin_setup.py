"""Rotina segura para criar ou resetar o administrador."""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - python-dotenv faz parte do deploy atual.
    load_dotenv = None

import database as db
from utils.validation import LIMITS, is_valid_email, trim_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class AdminSetupError(RuntimeError):
    """Erro esperado na configuracao do administrador."""


def _load_project_env():
    if load_dotenv:
        load_dotenv(PROJECT_ROOT / ".env")


def create_or_reset_admin_from_env():
    """
    Le ADMIN_EMAIL e ADMIN_PASSWORD do ambiente e cria/reseta o admin.
    Nao apaga usuarios, nao recria banco e usa hash via database.ensure_admin_user.
    """
    _load_project_env()

    admin_email = trim_text(os.environ.get("ADMIN_EMAIL"))
    admin_password = os.environ.get("ADMIN_PASSWORD") or ""
    admin_username = trim_text(os.environ.get("ADMIN_USERNAME")) or None
    admin_nickname = trim_text(os.environ.get("ADMIN_NICKNAME")) or "Admin EntreLinhas"
    admin_bio = trim_text(os.environ.get("ADMIN_BIO")) or None

    if not admin_email:
        raise AdminSetupError("Defina ADMIN_EMAIL antes de criar ou resetar o admin.")
    if not is_valid_email(admin_email):
        raise AdminSetupError("ADMIN_EMAIL não parece um e-mail válido.")
    if not admin_password:
        raise AdminSetupError("Defina ADMIN_PASSWORD antes de criar ou resetar o admin.")
    if len(admin_password) < LIMITS["password_min"] or len(admin_password) > LIMITS["password_max"]:
        raise AdminSetupError(
            f"ADMIN_PASSWORD precisa ter entre {LIMITS['password_min']} e {LIMITS['password_max']} caracteres."
        )

    if not db.USE_POSTGRES:
        db.init_db()

    success, message = db.ensure_admin_user(
        username=admin_username,
        password=admin_password,
        nickname=admin_nickname,
        display_name=admin_nickname,
        bio=admin_bio,
        email=admin_email,
    )
    if not success:
        raise AdminSetupError(message)

    user = db.get_user_by_email(admin_email)
    return {
        "message": message,
        "email": admin_email,
        "username": user["username"] if user else admin_username,
        "database": "PostgreSQL" if db.USE_POSTGRES else "SQLite local",
    }


def _is_truthy(value):
    return (value or "").strip().lower() in ("1", "true", "yes", "on", "sim")


def bootstrap_admin_on_boot(logger=None):
    """Cria o admin no boot a partir de ADMIN_EMAIL/ADMIN_PASSWORD.

    Pensado para hospedagens sem shell (ex.: Render): basta definir as variáveis
    de ambiente e fazer o deploy — o admin passa a existir sem rodar nenhum
    comando. É idempotente e seguro:

    * Sem ADMIN_EMAIL ou ADMIN_PASSWORD → não faz nada.
    * Se o admin já existe → NÃO mexe na senha (preserva troca feita pela UI),
      a menos que ADMIN_FORCE_RESET esteja ligado.
    * ADMIN_FORCE_RESET=1 → recria/reseta a senha para o valor do ambiente
      (resgate de acesso quando o usuário esquece a senha).

    Nunca derruba o boot: qualquer erro é apenas registrado.
    """
    _load_project_env()

    admin_email = trim_text(os.environ.get("ADMIN_EMAIL"))
    admin_password = os.environ.get("ADMIN_PASSWORD") or ""
    if not admin_email or not admin_password:
        return None  # nada configurado — segue o boot normalmente.

    force_reset = _is_truthy(os.environ.get("ADMIN_FORCE_RESET"))

    try:
        existing = db.get_user_by_email(admin_email)
    except Exception as exc:  # pragma: no cover - falha de banco no boot
        if logger:
            logger.warning("bootstrap_admin: não consegui consultar admin: %s", exc)
        existing = None

    already_admin = bool(existing) and bool(existing["is_admin"])
    if already_admin and not force_reset:
        if logger:
            logger.info("bootstrap_admin: admin '%s' já existe — preservado.", admin_email)
        return {"created": False, "email": admin_email}

    try:
        result = create_or_reset_admin_from_env()
        if logger:
            logger.info("bootstrap_admin: %s", result["message"])
        return {"created": True, "email": admin_email, "message": result["message"]}
    except AdminSetupError as exc:
        if logger:
            logger.warning("bootstrap_admin: configuração inválida — %s", exc)
    except Exception as exc:  # pragma: no cover - nunca derruba o boot
        if logger:
            logger.warning("bootstrap_admin: falha inesperada — %s", exc)
    return None
