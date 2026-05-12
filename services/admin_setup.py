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
