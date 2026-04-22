"""
Utilitaires de sécurité - DevSecOps FastAPI
"""
import re
import os
import hmac
import hashlib
import logging

logger = logging.getLogger(__name__)

_SECRET_KEY = os.getenv("SECRET_KEY", "")


def get_app_version() -> str:
    """Retourne la version de l'application."""
    return os.getenv("APP_VERSION", "1.0.0")


def verify_token(token: str) -> bool:
    """
    Vérifie un token Bearer (comparaison timing-safe).
    En production : utiliser une vraie validation JWT.
    """
    if not _SECRET_KEY:
        logger.error("SECRET_KEY non définie - authentification désactivée")
        return False

    expected = hmac.new(
        _SECRET_KEY.encode(),
        b"valid-token",
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(token, expected)


def sanitize_input(value: str, max_length: int = 1024) -> str:
    """
    Sanitise une entrée utilisateur :
    - Limite la longueur
    - Supprime les caractères dangereux (XSS, SQLi)
    """
    if not isinstance(value, str):
        raise ValueError("L'entrée doit être une chaîne de caractères")

    value = value[:max_length]
    value = re.sub(r"[<>\"'%;()&+]", "", value)

    patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+=",
        r"--",
        r"\/\*",
    ]
    for pattern in patterns:
        value = re.sub(pattern, "", value, flags=re.IGNORECASE)

    return value.strip()


def hash_sensitive_data(data: str) -> str:
    """Hash une donnée sensible pour les logs (non réversible)."""
    return hashlib.sha256(data.encode()).hexdigest()[:12] + "..."
