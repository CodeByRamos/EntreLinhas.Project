"""Respostas de erro de API que mostram a causa REAL quando preciso.

Por padrão, em produção, o usuário vê só a mensagem amigável. Mas se a env
`DEBUG_API_ERRORS=1` estiver ligada (ou se ENVIRONMENT != production), a resposta
inclui o tipo e a mensagem da exceção + contexto — pra diagnosticar o erro real
sem precisar caçar log. Desligue depois de resolver.
"""

import os


def debug_errors_enabled():
    if os.environ.get("DEBUG_API_ERRORS", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    env = os.environ.get("FLASK_ENV", os.environ.get("ENVIRONMENT", "development")).strip().lower()
    return env != "production"


def api_error(message, exc=None, **context):
    """Monta o corpo de erro. Inclui o detalhe real só em modo debug."""
    payload = {"success": False, "error": message}
    if exc is not None and debug_errors_enabled():
        payload["detail"] = f"{exc.__class__.__name__}: {exc}"
        if context:
            payload["context"] = {key: str(value) for key, value in context.items()}
    return payload
