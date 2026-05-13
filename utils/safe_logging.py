"""Helpers para logs de produção sem expor dados sensíveis."""

from __future__ import annotations

import logging


SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "confirm_password",
    "token",
    "cookie",
    "session",
}


def mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return None
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[:1] + "***"
    else:
        masked_local = f"{local[:2]}***{local[-1:]}"
    return f"{masked_local}@{domain}"


def clean_context(context: dict) -> dict:
    safe = {}
    for key, value in context.items():
        if key in SENSITIVE_KEYS:
            continue
        if key == "email":
            safe["email_masked"] = mask_email(value)
            continue
        safe[key] = value
    return safe


def log_exception(logger: logging.Logger, event: str, stage: str, exc: BaseException, **context) -> None:
    safe_context = clean_context(context)
    logger.exception(
        "%s failed stage=%s exc_type=%s exc_message=%s context=%s",
        event,
        stage,
        exc.__class__.__name__,
        str(exc),
        safe_context,
    )


def log_warning(logger: logging.Logger, event: str, stage: str, message: str, **context) -> None:
    safe_context = clean_context(context)
    logger.warning(
        "%s warning stage=%s message=%s context=%s",
        event,
        stage,
        message,
        safe_context,
    )
