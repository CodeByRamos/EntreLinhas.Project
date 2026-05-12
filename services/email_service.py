"""Envio centralizado de e-mails do EntreLinhas.

Em produção, a aplicação deve usar SMTP real. Em desenvolvimento, quando SMTP
não estiver configurado, os links seguros são impressos no terminal para teste.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import quote

from flask import current_app, render_template


def _config(name: str, default=None):
    try:
        return current_app.config.get(name, default)
    except RuntimeError:
        return os.environ.get(name, default)


def _bool_config(name: str, default: bool = False) -> bool:
    value = _config(name, default)
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _base_url() -> str:
    return str(_config("APP_BASE_URL", "http://127.0.0.1:5000")).rstrip("/")


def _build_link(path: str, token: str) -> str:
    safe_token = quote(token, safe="")
    return f"{_base_url()}{path}/{safe_token}"


def _smtp_ready() -> bool:
    return bool(_config("MAIL_SERVER") and _config("MAIL_DEFAULT_SENDER"))


def _print_console_fallback(to_email: str, subject: str, action_url: str) -> None:
    line = "=" * 72
    print(f"\n{line}")
    print("EntreLinhas - e-mail em modo local")
    print(f"Para: {to_email}")
    print(f"Assunto: {subject}")
    print(f"Link de teste: {action_url}")
    print(f"{line}\n")


def _send_email(to_email: str, subject: str, text_body: str, html_body: str, action_url: str) -> dict:
    if not _smtp_ready():
        if _bool_config("MAIL_ALLOW_CONSOLE_FALLBACK", True):
            _print_console_fallback(to_email, subject, action_url)
            return {"sent": False, "debug_url": action_url, "fallback": "console"}
        return {"sent": False, "error": "SMTP não configurado."}

    message = EmailMessage()
    sender = _config("MAIL_DEFAULT_SENDER")
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    server = _config("MAIL_SERVER")
    port = int(_config("MAIL_PORT", 587))
    username = _config("MAIL_USERNAME")
    password = _config("MAIL_PASSWORD")
    use_ssl = _bool_config("MAIL_USE_SSL", False)
    use_tls = _bool_config("MAIL_USE_TLS", True)

    try:
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(server, port, context=context, timeout=20) as smtp:
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(server, port, timeout=20) as smtp:
                if use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
    except Exception as exc:  # pragma: no cover - depende do provedor SMTP externo
        if _bool_config("MAIL_ALLOW_CONSOLE_FALLBACK", False):
            _print_console_fallback(to_email, subject, action_url)
            return {
                "sent": False,
                "debug_url": action_url,
                "fallback": "console",
                "error": str(exc),
            }
        return {"sent": False, "error": str(exc)}

    return {"sent": True}


def send_email_verification(to_email: str, token: str) -> dict:
    """Envia o e-mail de confirmação de conta."""
    action_url = _build_link("/verificar-email", token)
    subject = "Confirme seu email no EntreLinhas"
    context = {"action_url": action_url}
    text_body = render_template("emails/verify_email.txt", **context)
    html_body = render_template("emails/verify_email.html", **context)
    return _send_email(to_email, subject, text_body, html_body, action_url)


def send_password_reset_email(to_email: str, token: str) -> dict:
    """Envia o e-mail de redefinição de senha."""
    action_url = _build_link("/redefinir-senha", token)
    subject = "Redefina sua senha no EntreLinhas"
    context = {"action_url": action_url}
    text_body = render_template("emails/reset_password.txt", **context)
    html_body = render_template("emails/reset_password.html", **context)
    return _send_email(to_email, subject, text_body, html_body, action_url)
