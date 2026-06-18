"""Filtro sensível do EntreLinhas.

Cobre dois eixos independentes de conteúdo:

1. Risco emocional (ideação suicida, automutilação, overdose, sofrimento extremo).
   Resposta = acolhimento. Nunca bloqueia de forma dura; oferece ajuda real.

2. Discurso de ódio (gordofobia, LGBTfobia, racismo, capacitismo, misoginia,
   xenofobia). Resposta = moderação. Ataques diretos são bloqueados; xingamentos
   isolados recebem um aviso e ficam sinalizados para revisão.

Ambos os eixos passam por uma normalização resistente a ofuscação, para que
tentativas como ``G0RD0``, ``g.o.r.d.o``, ``g o r d o`` ou ``gooordo`` não
escapem do filtro.

Proteção à vítima: textos que relatam ter sofrido a ofensa ("me chamaram de…")
nunca são bloqueados — quem desabafa sobre uma agressão é vítima, não agressor.
"""

import re
import unicodedata

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

# Ações possíveis para o eixo de ódio.
HATE_ACTION_NONE = "none"
HATE_ACTION_WARN = "warn"   # xingamento isolado: avisa e sinaliza, mas deixa publicar
HATE_ACTION_BLOCK = "block"  # ataque direto: impede a publicação


# ---------------------------------------------------------------------------
# Normalização resistente a ofuscação
# ---------------------------------------------------------------------------

# Substituições leet conservadoras, aplicadas inclusive na visão "espaçada".
# Mantemos só o que raramente corrompe o português normal (dígitos comuns + @ $).
_LEET_BASIC = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
}

# Visão "condensada" é mais agressiva: como removemos tudo que não é letra,
# podemos folddar também símbolos que viram letra com frequência.
_LEET_FULL = dict(_LEET_BASIC)
_LEET_FULL.update({"!": "i", "|": "i", "+": "t", "(": "c", "€": "e", "*": "", "2": "z"})

_LEET_BASIC_TABLE = str.maketrans(_LEET_BASIC)
_LEET_FULL_TABLE = str.maketrans(_LEET_FULL)


def _strip_accents(text):
    nfkd = unicodedata.normalize("NFKD", text or "")
    return "".join(char for char in nfkd if not unicodedata.combining(char))


def normalize_spaced(text):
    """Texto sem acento, minúsculo, com leet básico e palavras preservadas.

    Mantém os limites de palavra (espaços), então serve para casar frases e
    termos com ``\\b…\\b``. Defende contra acentos, caixa e leet de dígitos.
    """
    base = _strip_accents(text).lower().translate(_LEET_BASIC_TABLE)
    base = re.sub(r"[^a-z\s]", " ", base)
    # Colapsa alongamentos (3+ letras iguais) sem tocar em letras dobradas
    # normais do português ("passar", "terra", "nossa").
    base = re.sub(r"(.)\1{2,}", r"\1", base)
    return re.sub(r"\s+", " ", base).strip()


def normalize_condensed(text):
    """Texto reduzido a uma sequência contínua de letras.

    Remove espaços, pontuação e dígitos e colapsa repetições, derrubando
    ofuscações por separadores (``g.o.r.d.o``), espaçamento (``g o r d o``)
    e alongamento (``gooordo``).
    """
    base = _strip_accents(text).lower().translate(_LEET_FULL_TABLE)
    base = re.sub(r"[^a-z]", "", base)
    return re.sub(r"(.)\1+", r"\1", base)


# Mantido por compatibilidade com chamadas antigas.
normalize_sensitive_text = normalize_spaced


def _condense_term(term):
    """Aplica a mesma redução de ``normalize_condensed`` a um termo do léxico."""
    base = _strip_accents(term).lower().translate(_LEET_FULL_TABLE)
    base = re.sub(r"[^a-z]", "", base)
    return re.sub(r"(.)\1+", r"\1", base)


def _matches_term(term, spaced_text, condensed_text):
    """Casa um termo contra as duas visões normalizadas.

    - Visão espaçada: casamento por limite de palavra (seguro, preserva contexto).
    - Visão condensada: substring, mas só para termos distintos (>= 5 letras),
      para não gerar falso positivo colado entre palavras.
    """
    spaced_term = normalize_spaced(term)
    if spaced_term:
        pattern = r"\b" + re.escape(spaced_term).replace(r"\ ", r"\s+") + r"\b"
        if re.search(pattern, spaced_text):
            return True
    condensed_term = _condense_term(term)
    if len(condensed_term) >= 5 and condensed_term in condensed_text:
        return True
    return False


# ---------------------------------------------------------------------------
# Eixo 1 — Risco emocional
# ---------------------------------------------------------------------------

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
            "carta de despedida", "ultimo adeus", "nao vejo saida",
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


def evaluate_emotional_risk(spaced_text):
    """Avalia o eixo de risco emocional sobre o texto já normalizado."""
    matched_terms = []
    matched_category = None
    risk_level = RISK_LOW

    for category, config in SENSITIVE_CATEGORIES.items():
        category_matches = [term for term in config["terms"] if term in spaced_text]
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

    should_block = any(re.search(pattern, spaced_text) for pattern in CRITICAL_PATTERNS)
    if should_block:
        risk_level = RISK_HIGH
        matched_category = matched_category or "suicide_ideation"

    return {
        "category": matched_category,
        "risk_level": risk_level,
        "should_block": should_block,
        "matched_terms": sorted(set(matched_terms)),
    }


# ---------------------------------------------------------------------------
# Eixo 2 — Discurso de ódio
# ---------------------------------------------------------------------------

# `slurs`  → tokens inerentemente ofensivos (casados nas duas visões).
# `phrases`→ construções que já são, por si, um ataque (sempre bloqueiam).
HATE_CATEGORIES = {
    "lgbtfobia": {
        "label": "LGBTfobia",
        "slurs": [
            "viado", "viadinho", "veado", "veadinho", "boiola", "baitola",
            "bichinha", "sapatao", "sapatona", "fanchona", "traveco", "traveca",
        ],
        "phrases": [
            "viado nojento", "morte aos gays", "cura gay", "gay tem que morrer",
            "veado nojento", "sapatao nojenta",
        ],
    },
    "racismo": {
        "label": "racismo",
        "slurs": ["crioulo", "criolo", "macaca", "negreiro"],
        "phrases": [
            "volta pra senzala", "volta pro mato", "macaco preto", "preto fedido",
            "negro fedido", "raca inferior", "white power", "heil hitler",
            "judeu safado", "queimar judeu", "preto fede", "negro fede",
        ],
    },
    "gordofobia": {
        "label": "gordofobia",
        "slurs": ["baleia", "baleote", "balofa", "balofo"],
        "phrases": [
            "bola de banha", "monte de banha", "gorda nojenta", "gordo nojento",
            "porca gorda", "porco gordo", "vai emagrecer", "rolha de poco",
            "gorda nojenta", "vaca gorda", "elefante gorda",
        ],
    },
    "capacitismo": {
        "label": "capacitismo",
        "slurs": ["retardado", "retardada", "mongoloide", "debiloide", "aleijado", "aleijada"],
        "phrases": ["debil mental", "doente mental nojento", "vai pro hospicio", "autista de merda"],
    },
    "misoginia": {
        "label": "misoginia",
        "slurs": ["vagabunda", "vadia", "piranha", "rapariga", "puteira", "biscate"],
        "phrases": [
            "sua puta", "lugar de mulher", "volta pra cozinha", "cala boca mulher",
            "mulher burra", "vai lavar louca",
        ],
    },
    "xenofobia": {
        "label": "xenofobia",
        "slurs": [],
        "phrases": [
            "volta pro seu pais", "nordestino burro", "paraiba burro",
            "baiano preguicoso", "volta pra sua terra", "nordestino fede",
        ],
    },
}

# Termos ambíguos: neutros no uso normal ("me sinto gordo" é desabafo, não ataque),
# mas suspeitos quando vêm OFUSCADOS — ninguém escreve "G0RD0" sem querer driblar
# o filtro. Só acusamos esses quando aparecem ofuscados; a grafia limpa segue livre.
OBFUSCATED_ONLY_TERMS = {
    "gordo": "gordofobia",
    "gorda": "gordofobia",
    "gordao": "gordofobia",
    "obeso": "gordofobia",
    "obesa": "gordofobia",
}

# Marcadores de que o autor está RELATANDO ter sofrido a ofensa (vítima).
# Se presentes, nunca bloqueamos de forma dura — no máximo avisamos.
VICTIM_CONTEXT_MARKERS = (
    "me chamaram de", "me chamou de", "me chamavam de", "me xingaram",
    "me xingou", "fui chamad", "fui xingad", "disseram que eu", "gritaram comigo",
    "me humilharam", "me ofenderam", "sofri bullying", "sofro bullying",
    "me chamam de", "vivem me chamando", "ja me chamaram", "ouvi que eu",
    "falaram que eu", "me trataram como", "apelido de",
)

# Conectores de agressão que, junto de um xingamento, caracterizam ataque direto.
_SLUR_INSULT_SUFFIX = r"(?:nojent[oa]s?|imund[oa]s?|de\s+merda|fdp|filho\s+da\s+puta|lixo|escroto|imundo)"
_AGGRESSION_LEAD = r"(?:morr[ae]m?|some|sai\s+daqui|cai\s+fora|volta\s+pra|odeio|detesto|mata|matem|some\s+daqui)"


def _build_hate_index():
    slurs = []
    phrases = []
    slur_to_category = {}
    phrase_to_category = {}
    for category, config in HATE_CATEGORIES.items():
        for slur in config.get("slurs", []):
            slurs.append(slur)
            slur_to_category[slur] = category
        for phrase in config.get("phrases", []):
            phrases.append(phrase)
            phrase_to_category[phrase] = category
    return slurs, phrases, slur_to_category, phrase_to_category


_HATE_SLURS, _HATE_PHRASES, _SLUR_CATEGORY, _PHRASE_CATEGORY = _build_hate_index()

# Alternância de xingamentos (em forma espaçada) para os padrões de ataque.
_SLUR_ALTERNATION = "|".join(
    sorted((re.escape(normalize_spaced(s)).replace(r"\ ", r"\s+") for s in _HATE_SLURS if normalize_spaced(s)),
           key=len, reverse=True)
)

_ATTACK_PATTERNS = []
if _SLUR_ALTERNATION:
    _slur_group = r"(?:" + _SLUR_ALTERNATION + r")"
    _ATTACK_PATTERNS = [
        re.compile(r"\bseus?\s+" + _slur_group + r"\b"),
        re.compile(r"\b" + _slur_group + r"s?\s+" + _SLUR_INSULT_SUFFIX + r"\b"),
        re.compile(r"\b" + _AGGRESSION_LEAD + r"\b.{0,25}\b" + _slur_group + r"s?\b"),
        re.compile(r"\b" + _slur_group + r"s?\b.{0,20}\b(?:tem|tinha|deveria|devia|merec[ei]a?)\b.{0,20}\bmorrer\b"),
    ]


def _appears_clean(term, clean_text):
    """Verdadeiro se o termo aparece em grafia limpa (sem ofuscação)."""
    return re.search(r"\b" + re.escape(term) + r"\b", clean_text) is not None


def evaluate_hate_speech(text, spaced_text, condensed_text, clean_text=""):
    """Avalia o eixo de discurso de ódio."""
    categories = set()
    terms = []

    for slur in _HATE_SLURS:
        if _matches_term(slur, spaced_text, condensed_text):
            categories.add(_SLUR_CATEGORY[slur])
            terms.append(slur)

    phrase_attack = False
    for phrase in _HATE_PHRASES:
        if _matches_term(phrase, spaced_text, condensed_text):
            categories.add(_PHRASE_CATEGORY[phrase])
            terms.append(phrase)
            phrase_attack = True

    # Termos ambíguos só contam quando aparecem ofuscados (e não em grafia limpa).
    for term, category in OBFUSCATED_ONLY_TERMS.items():
        if term in terms:
            continue
        if _matches_term(term, spaced_text, condensed_text) and not _appears_clean(term, clean_text):
            categories.add(category)
            terms.append(term)

    is_hate = bool(categories)
    pattern_attack = any(pattern.search(spaced_text) for pattern in _ATTACK_PATTERNS)
    is_attack = phrase_attack or pattern_attack

    is_victim = any(marker in spaced_text for marker in VICTIM_CONTEXT_MARKERS)

    if not is_hate:
        action = HATE_ACTION_NONE
    elif is_attack and not is_victim:
        action = HATE_ACTION_BLOCK
    else:
        action = HATE_ACTION_WARN

    return {
        "is_hate_speech": is_hate,
        "hate_categories": sorted(categories),
        "hate_category_labels": [HATE_CATEGORIES[c]["label"] for c in sorted(categories)],
        "hate_terms": sorted(set(terms)),
        "hate_action": action,
        "is_victim_report": is_victim,
    }


# ---------------------------------------------------------------------------
# Avaliação combinada
# ---------------------------------------------------------------------------

def evaluate_sensitive_content(text):
    """Avalia os dois eixos e devolve um resultado unificado.

    Mantém as chaves antigas (``risk_level``, ``should_block``, ``is_sensitive``,
    ``category``, ``matched_terms``) e adiciona o eixo de ódio.
    """
    spaced_text = normalize_spaced(text)
    condensed_text = normalize_condensed(text)
    clean_text = _strip_accents(text).lower()

    emotional = evaluate_emotional_risk(spaced_text)
    hate = evaluate_hate_speech(text, spaced_text, condensed_text, clean_text=clean_text)

    result = {
        "is_sensitive": emotional["risk_level"] in (RISK_MEDIUM, RISK_HIGH),
        "category": emotional["category"],
        "risk_level": emotional["risk_level"],
        "should_block": emotional["should_block"],
        "matched_terms": emotional["matched_terms"],
    }
    result.update(hate)
    result["block_publication"] = hate["hate_action"] == HATE_ACTION_BLOCK
    return result
