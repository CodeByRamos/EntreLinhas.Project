"""Compatibilidade para análise sensível usada pelas rotas."""

from utils.sensitive_filter import (
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    evaluate_sensitive_content,
    contains_hate_speech,
)

__all__ = [
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "evaluate_sensitive_content",
    "contains_hate_speech",
    "evaluate_post_content",
    "analyze_post_content",
]


def evaluate_post_content(text):
    return evaluate_sensitive_content(text)


def analyze_post_content(text):
    return evaluate_sensitive_content(text)["risk_level"]
