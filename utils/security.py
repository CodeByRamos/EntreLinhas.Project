"""Utilitários de segurança para autenticação."""

import hashlib
import hmac
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password):
    """Gera hash seguro para uma senha usando algoritmos modernos do Werkzeug."""
    return generate_password_hash(password)


def verify_password(password, stored_hash):
    """
    Verifica senha em hash moderno e mantém compatibilidade com hashes legados SHA-256.
    """
    if not stored_hash:
        return False

    if is_legacy_hash(stored_hash):
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)

    return check_password_hash(stored_hash, password)


def is_legacy_hash(stored_hash):
    """Identifica hashes antigos em hex puro (SHA-256)."""
    return len(stored_hash) == 64 and all(ch in '0123456789abcdef' for ch in stored_hash.lower())