"""Regras centralizadas de validação e limites do sistema."""

import re

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\.]+$")

LIMITS = {
    "email_max": 254,
    "username_min": 3,
    "username_max": 30,
    "display_name_min": 2,
    "display_name_max": 40,
    "nickname_min": 2,
    "nickname_max": 30,
    "bio_max": 180,
    "password_min": 8,
    "password_max": 128,
    "post_title_max": 120,
    "post_content_min": 10,
    "post_content_max": 1000,
    "comment_content_min": 2,
    "comment_content_max": 300,
    "notification_title_max": 80,
    "notification_message_max": 240,
    "token_min": 32,
    "token_max": 128,
}


def trim_text(value):
    return (value or "").strip()


def is_valid_email(email):
    email = trim_text(email)
    return bool(email and len(email) <= LIMITS["email_max"] and EMAIL_REGEX.match(email))


def is_valid_username(username):
    username = trim_text(username)
    if not username:
        return False
    if len(username) < LIMITS["username_min"] or len(username) > LIMITS["username_max"]:
        return False
    return bool(USERNAME_REGEX.match(username))