import re
import unicodedata


RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"


LOW_KEYWORDS = (
    "cansado de tudo",
    "nao aguento",
    "sem sentido",
    "vontade de sumir",
    "queria desaparecer",
    "desesperanca",
    "nada faz sentido",
)

MEDIUM_KEYWORDS = (
    "nao quero mais viver",
    "quero desistir de tudo",
    "viver nao vale a pena",
    "dor insuportavel",
    "nao vejo saida",
    "nao tenho forcas",
    "nao suporto mais",
    "me cortar",
    "automutilacao",
    "me machucar",
)

HIGH_KEYWORDS = (
    "quero me matar",
    "vou me matar",
    "vou acabar com minha vida",
    "tirar minha propria vida",
    "cometer suicidio",
    "acabar com tudo hoje",
    "me matar hoje",
    "me matar agora",
    "me cortar profundamente",
    "vou dar um fim em tudo",
    "vou desaparecer pra sempre",
    "não faz sentido continuar aqui",
    "cansei de existir",
    "não tem mais solução pra mim",
    "quero sumir de vez",
    "minha vida acabou",
    "não vejo saída nenhuma",
    "não vale mais a pena viver",
    "tô pronto pra acabar com tudo",
    "não tem mais volta",
    "vou fazer isso hoje mesmo",
    "não quero acordar amanhã",
    "queria simplesmente deixar de existir",
    "vou apagar minha existência",
    "ninguém vai sentir falta",
    "seria melhor se eu não estivesse aqui",
    "tô cansado de tentar",
    "já deu pra mim",
    "não consigo mais continuar",
    "quero desligar tudo",
    "vou sair desse mundo",
    "não quero mais estar aqui",
    "tô no limite",
    "não aguento mais isso",
    "vou desaparecer hoje",
    "não tenho mais forças",
    "já aceitei que acabou",
    "isso termina hoje",
    "vou encerrar tudo agora",
    

)

# Casos de urgência explícita que justificam bloqueio de publicação.
CRITICAL_PATTERNS = (
    r"\b(vou|irei)\s+me\s+matar\s+(agora|hoje|nesta\s+noite)\b",
    r"\b(ja\s+tenho|peguei)\s+(corda|veneno|remedio|arma)\b",
    r"\b(hoje)\s+eu\s+(me\s+mato|acabo\s+com\s+a\s+minha\s+vida)\b",
)


def _normalize_text(text):
    normalized = unicodedata.normalize("NFKD", text or "")
    without_accents = "".join(char for char in normalized if not unicodedata.combining(char))
    return without_accents.lower()


def evaluate_post_content(text):
    """
    Retorna metadados para decisão de UX e segurança.
    Estrutura:
      {
        "risk_level": "LOW|MEDIUM|HIGH",
        "should_block": bool,
        "matched_terms": list[str],
      }
    """
    normalized_text = _normalize_text(text)
    matched_terms = []
    score = 0

    for keyword in LOW_KEYWORDS:
        if keyword in normalized_text:
            matched_terms.append(keyword)
            score += 1

    for keyword in MEDIUM_KEYWORDS:
        if keyword in normalized_text:
            matched_terms.append(keyword)
            score += 2

    for keyword in HIGH_KEYWORDS:
        if keyword in normalized_text:
            matched_terms.append(keyword)
            score += 4

    should_block = any(re.search(pattern, normalized_text) for pattern in CRITICAL_PATTERNS)

    if score >= 4:
        risk_level = RISK_HIGH
    elif score >= 2:
        risk_level = RISK_MEDIUM
    else:
        risk_level = RISK_LOW

    return {
        "risk_level": risk_level,
        "should_block": should_block,
        "matched_terms": matched_terms,
    }


def analyze_post_content(text):
    """API principal requisitada: retorna apenas o nível de risco."""
    return evaluate_post_content(text)["risk_level"]