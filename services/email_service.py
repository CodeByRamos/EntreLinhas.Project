"""Camada de envio de e-mails com fallback seguro para desenvolvimento."""

import os
from urllib.parse import quote


def _base_url():
    return os.environ.get("APP_BASE_URL", "http://localhost:5000").rstrip("/")


def _build_link(path, token):
    safe_token = quote(token, safe="")
    return f"{_base_url()}{path}?token={safe_token}"


def send_password_reset_email(to_email, token):
    """
    Prepara envio de e-mail de reset.
    Em dev sem provider, retorna preview_url para uso local.
    """
    preview_url = _build_link("/redefinir-senha", token)
    # Ponto de integração futuro com provider real.
    return {"sent": False, "preview_url": preview_url, "to": to_email}


def send_email_verification(to_email, token):
    """
    Prepara envio de e-mail de verificação.
    Em dev sem provider, retorna preview_url para uso local.
    """
    preview_url = _build_link("/verificar-email", token)
    # Ponto de integração futuro com provider real.
    return {"sent": False, "preview_url": preview_url, "to": to_email}