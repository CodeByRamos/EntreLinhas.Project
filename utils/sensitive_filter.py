"""Filtro sensível para risco emocional e dano pessoal."""

import re
import unicodedata

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

SENSITIVE_CATEGORIES = {
    "suicide_ideation": {
        "risk_level": RISK_HIGH,
        "terms": [
            "suicidio", "suicida", "me matar", "quero morrer", "queria morrer",
            "vontade de morrer", "nao quero mais viver", "nao aguento mais viver",
            "tirar minha vida", "acabar com minha vida", "acabar com tudo",
            "sumir pra sempre", "desaparecer pra sempre", "prefiro morrer",
            "morrer seria melhor", "hoje eu morro", "vou me matar",
            "pensei em me matar", "penso em me matar", "planejei minha morte",
            "carta de despedida", "despedida", "ultimo adeus", "nao vejo saida",
        ],
    },
    "self_harm": {
        "risk_level": RISK_HIGH,
        "terms": [
            "automutilacao", "me cortar", "me cortei", "vontade de me cortar",
            "me machucar", "me ferir", "me arranhar", "me queimar", "me bater",
            "abrir minha pele", "sangue no braco", "cortes no braco", "lamina",
            "gilete", "estilete",
        ],
    },
    "overdose": {
        "risk_level": RISK_HIGH,
        "terms": [
            "overdose", "tomar varios remedios", "tomei muitos remedios",
            "misturar remedios", "apagar pra sempre", "beber ate morrer",
        ],
    },
    "extreme_distress": {
        "risk_level": RISK_MEDIUM,
        "terms": [
            "nao aguento mais", "estou no limite", "cheguei no limite",
            "nao tenho mais forca", "cansei de existir", "nao consigo continuar",
            "nao queria ter nascido", "ninguem vai sentir minha falta",
            "sou um peso", "todo mundo ficaria melhor sem mim",
            "nada faz sentido", "vontade de sumir", "queria desaparecer",
            "desesperanca", "dor insuportavel", "nao suporto mais",
        ],
    },
}

CRITICAL_PATTERNS = (
    r"\b(vou|irei)\s+me\s+matar\s+(agora|hoje|nesta\s+noite)\b",
    r"\b(hoje)\s+eu\s+(me\s+mato|morro|acabo\s+com\s+a\s+minha\s+vida)\b",
    r"\b(ja\s+tenho|peguei|comprei)\s+(corda|veneno|remedio|remedios|arma|lamina|gilete|estilete)\b",
    r"\b(tomei|vou\s+tomar)\s+(muitos|varios|varias)\s+(remedios|comprimidos)\b",
)


def normalize_sensitive_text(text):
    normalized = unicodedata.normalize("NFKD", text or "")
    without_accents = "".join(char for char in normalized if not unicodedata.combining(char))
    lowered = without_accents.lower()
    cleaned = re.sub(r"[^a-z0-9\s]", " ", lowered)
    return re.sub(r"\s+", " ", cleaned).strip()


def evaluate_sensitive_content(text):
    normalized_text = normalize_sensitive_text(text)
    matched_terms = []
    matched_category = None
    risk_level = RISK_LOW

    for category, config in SENSITIVE_CATEGORIES.items():
        category_matches = [term for term in config["terms"] if term in normalized_text]
        if not category_matches:
            continue

        matched_terms.extend(category_matches)
        if config["risk_level"] == RISK_HIGH:
            matched_category = category
            risk_level = RISK_HIGH
            break
        if risk_level != RISK_HIGH:
            matched_category = matched_category or category
            risk_level = RISK_MEDIUM

    should_block = any(re.search(pattern, normalized_text) for pattern in CRITICAL_PATTERNS)
    if should_block:
        risk_level = RISK_HIGH
        matched_category = matched_category or "suicide_ideation"

    return {
        "is_sensitive": risk_level in (RISK_MEDIUM, RISK_HIGH),
        "category": matched_category,
        "risk_level": risk_level,
        "should_block": should_block,
        "matched_terms": sorted(set(matched_terms)),
    }
