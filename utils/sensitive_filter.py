"""Filtro sensível do EntreLinhas.

Cobre dois eixos independentes de conteúdo:

1. Risco emocional (ideação suicida, automutilação, overdose, sofrimento extremo).
   Resposta = acolhimento. Nunca bloqueia de forma dura; oferece ajuda real.

2. Discurso de ódio / discriminação (racismo, LGBTfobia, gordofobia,
   capacitismo, misoginia, xenofobia, intolerância religiosa). Resposta =
   moderação. Ataques são bloqueados com aviso de violação das diretrizes.

────────────────────────────────────────────────────────────────────────────
COMO O EIXO DE ÓDIO FUNCIONA (e por que é difícil de burlar)
────────────────────────────────────────────────────────────────────────────

O erro do filtro antigo era depender de uma LISTA DE FRASES EXATAS: tinha
``preto fedido`` mas não ``preto fudido``, então qualquer variação passava.

Agora a detecção é COMPOSICIONAL, em cima de três léxicos:

* ``SLURS``       — termos que já são, por si, ofensa (viado, crioulo, retardado…).
* ``IDENTITY``    — referências a grupos protegidos (preto, negro, gay, trans,
                    nordestino, judeu, gordo, deficiente, mulher…). Neutros
                    sozinhos: "sou preto", "sou gay" são desabafo legítimo.
* ``INSULTS``     — xingamentos/agressão (fudido, merda, nojento, lixo, "tem que
                    morrer", "some daqui"…). Sozinhos, são só desabafo (a pessoa
                    está extravasando). NÃO bloqueiam por si.

A regra central:  IDENTIDADE (ou slur)  +  INSULTO por perto  =  ATAQUE.
Assim ``preto fudido``, ``negro de merda``, ``gay nojento``, ``nordestino
burro``, ``trans imundo`` são todos pegos sem precisar listar cada combinação.

Tudo passa por DUAS normalizações resistentes a ofuscação:
  - "espaçada": preserva palavras (defende acento, caixa, leet, separadores,
    espaçamento e alongamento) → ``g0rd0``, ``g.o.r.d.o``, ``g o r d o`` e
    ``gooordo`` viram ``gordo``.
  - "condensada": vira uma sequência contínua de letras por palavra → pega
    ofuscação colada (``pretofudido``).

PROTEÇÃO À VÍTIMA / AUTO-RELATO: quem RELATA ter sofrido a ofensa
("me chamaram de…") ou fala da PRÓPRIA identidade ("eu sou preto e…") nunca é
bloqueado — é vítima/desabafo, não agressor. Só ataques diretos e inequívocos
(frases supremacistas, "seus <slur>", "morram <slur>") bloqueiam mesmo nesse
contexto. Tudo o que é sinalizado fica marcado para revisão da moderação.

Para campos de IDENTIDADE (nome, @usuário, bio) não existe contexto de
desabafo — lá ``contains_hate_speech`` aplica tolerância zero.
"""

import re
import unicodedata

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"

# Ações possíveis para o eixo de ódio.
HATE_ACTION_NONE = "none"
HATE_ACTION_WARN = "warn"   # sinaliza e avisa, mas deixa publicar (com ciência)
HATE_ACTION_BLOCK = "block"  # ataque: impede a publicação


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

# Caracteres invisíveis / de largura zero usados para "cortar" palavras e furar
# o filtro (ex.: "pre​to"). São removidos antes de qualquer análise.
_INVISIBLE_RE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠎"
    "​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤⁪⁫⁬⁭⁮⁯"
    "ㅤ﻿ﾠ\U0001d173-\U0001d17a]"
)

# Homóglifos: letras de outros alfabetos (cirílico, grego) e símbolos que se
# parecem com letras latinas, usados para escrever slurs driblando o filtro
# (ex.: "рrеtо" com р/е cirílicos). Mapeamos para o latim correspondente.
# Largura total (ｐｒｅｔｏ) já é resolvida pelo NFKD.
_HOMOGLYPHS = {
    # cirílico
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
    "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "е": "e", "г": "r", "л": "n",
    "и": "u", "п": "n", "ц": "u",
    # grego
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "ν": "v", "υ": "u",
    "τ": "t", "κ": "k", "χ": "x", "μ": "m", "η": "n", "β": "b", "γ": "y",
    "σ": "o", "θ": "o",
    # latim estendido / símbolos comuns
    "ɑ": "a", "ı": "i", "ʟ": "l", "ɴ": "n", "ʀ": "r", "ѵ": "v", "ϲ": "c",
}
_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


import functools

_LATIN_NAME_RE = re.compile(r"LATIN (?:SMALL|CAPITAL) LETTER ([A-Z])(?:\b|WITH)")
_ANY_LETTER_NAME_RE = re.compile(r"\bLETTER ([A-Z])\b")


@functools.lru_cache(maxsize=4096)
def _fold_unicode_letter(ch):
    """Dobra QUALQUER caractere que 'seja' uma letra latina disfarçada.

    Em vez de uma tabela fixa, usamos o nome Unicode do caractere. Assim
    pegamos genericamente latim estendido / IPA (ʋ→v, ɗ→d, ɠ→g, ɭ→l),
    letras cercadas/quadradas (🅐→a, 🅥→v) e variações que o NFKD não desfaz —
    fechando a porta de ofuscação por homóglifo de forma ampla.
    """
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ch
    match = _LATIN_NAME_RE.search(name) or _ANY_LETTER_NAME_RE.search(name)
    if match:
        return match.group(1).lower()
    return ch


def _fold_confusables(text):
    """Remove invisíveis e converte homóglifos unicode para latim."""
    text = _INVISIBLE_RE.sub("", text or "")
    text = text.translate(_HOMOGLYPH_TABLE)
    if any(ord(c) > 0x7F for c in text):
        text = "".join(_fold_unicode_letter(c) if ord(c) > 0x7F else c for c in text)
    return text


def _strip_accents(text):
    folded = _fold_confusables(text)
    nfkd = unicodedata.normalize("NFKD", folded)
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


def _condensed_words(text):
    """Cada palavra do texto reduzida à forma condensada (uma por token).

    Diferente de ``normalize_condensed`` (que cola o texto TODO), aqui
    preservamos as fronteiras de espaço: assim ``pretofudido`` (uma palavra
    ofuscada) é pego, mas ``gay. merda`` (duas palavras distantes) não vira
    falso positivo ``gaymerda``.
    """
    words = []
    for raw in re.split(r"\s+", _strip_accents(text).lower()):
        cond = re.sub(r"[^a-z]", "", raw.translate(_LEET_FULL_TABLE))
        cond = re.sub(r"(.)\1+", r"\1", cond)
        if cond:
            words.append(cond)
    return words


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
# Eixo 2 — Discurso de ódio / discriminação
# ---------------------------------------------------------------------------

CATEGORY_LABELS = {
    "racismo": "racismo",
    "lgbtfobia": "LGBTfobia",
    "gordofobia": "gordofobia",
    "capacitismo": "capacitismo",
    "misoginia": "misoginia",
    "xenofobia": "xenofobia",
    "intolerancia_religiosa": "intolerância religiosa",
}

# ── SLURS: termos que já são ofensa por si. Casados nas duas visões. ─────────
# Só entram aqui termos de baixa ambiguidade no PT-BR cotidiano. Palavras com
# sentido inocente comum (baleia/animal, macaco/animal, rapariga/PT-PT) ficam
# em CODED_TARGETS: só viram ataque com insulto por perto.
SLURS = {
    "racismo": [
        "crioulo", "criolo", "negreiro", "preto fedido", "neguinho de senzala",
    ],
    "lgbtfobia": [
        "viado", "viadinho", "viadao", "veado", "veadinho", "boiola", "baitola",
        "sapatao", "sapatona", "fanchona", "traveco", "traveca", "bichona",
        "bichinha", "viadagem", "sodomita", "gayzao",
    ],
    "gordofobia": [
        "balofa", "balofo",
    ],
    "capacitismo": [
        "retardado", "retardada", "mongoloide", "debiloide",
        "aleijado", "aleijada", "tapado mental",
    ],
    "misoginia": [
        "vagabunda", "vadia", "piranha", "puteira", "biscate", "vaca safada",
    ],
    "intolerancia_religiosa": [
        "macumbeiro", "macumbeira", "comedor de hostia",
    ],
}

# ── CODED_TARGETS: têm sentido inocente comum, então NÃO bloqueiam sozinhos.
# Funcionam como alvo: "sua baleia", "macaco nojento" bloqueiam; "vi uma baleia",
# "imperio mongol" passam. Resolve falsos positivos sem abrir o ataque.
CODED_TARGETS = {
    "racismo": ["macaco", "macaca", "macacos", "bugre", "caboclo", "curiboca", "calon"],
    "gordofobia": ["baleia", "baleote", "jamanta", "bucha"],
    "lgbtfobia": ["bicha", "frutinha", "florzinha", "fruta"],
    "capacitismo": ["mongol", "manco"],
    "misoginia": ["rapariga"],
    "xenofobia": ["cabeca chata", "pau de arara", "portuga"],
}

# ── IDENTITY: referências a grupos protegidos. NEUTRAS sozinhas. ────────────
# Só viram ataque quando aparecem perto de um insulto (composição) ou
# ofuscadas sem motivo. "sou preto", "amo ser gay", "luta trans" passam livres.
IDENTITY = {
    "racismo": [
        "preto", "preta", "pretinho", "pretinha", "negro", "negra", "neguinho",
        "neguinha", "nego", "pardo", "parda", "africano", "africana",
        "judeu", "judia", "judaico", "indio", "india", "indigena", "cigano",
        "cigana", "mulato", "mulata", "cor de pele", "raca negra",
        "chines", "chinesa", "japones", "japonesa", "japa", "coreano", "coreana",
        "asiatico", "asiatica", "oriental", "amarelo", "amarela",
    ],
    "lgbtfobia": [
        "gay", "gays", "gayzinho", "lesbica", "lesbicas", "bissexual",
        "homossexual", "homosexual", "trans", "transexual", "transgenero",
        "transgeneros", "travesti", "nao binario", "nao binarie", "queer",
        "lgbt", "lgbtqia", "drag", "homossexualismo", "transexualismo",
        "transgenerismo", "lesbianismo", "ideologia de genero", "nao binarismo",
    ],
    "gordofobia": [
        "gordo", "gorda", "gordao", "gordona", "gordinho", "gordinha",
        "obeso", "obesa", "acima do peso", "plus size",
    ],
    "capacitismo": [
        "deficiente", "deficiencia", "autista", "autismo", "cadeirante", "surdo",
        "surda", "cego", "cega", "mudo", "muda", "sindrome de down", "down",
        "paralitico", "paralitica", "nanico", "anao",
    ],
    "misoginia": [
        "mulher", "mulheres", "mulherzinha", "mina", "garota", "menina",
        "feminista", "feministas", "feminina",
    ],
    "xenofobia": [
        "nordestino", "nordestina", "baiano", "baiana", "paraiba", "nortista",
        "venezuelano", "venezuelana", "boliviano", "boliviana", "haitiano",
        "haitiana", "imigrante", "refugiado", "refugiada", "estrangeiro", "gringo",
    ],
    "intolerancia_religiosa": [
        "judeu", "muculmano", "muculmana", "islamico", "umbandista",
        "candomblecista", "candomble", "umbanda", "macumba", "espirita",
        "evangelico", "evangelica", "catolico", "ateu", "crente",
    ],
}

# ── INSULTS: xingamento / agressão. Sozinhos NÃO bloqueiam (é desabafo). ─────
# Bloqueiam quando colados a uma identidade/slur (composição = ataque dirigido).
INSULTS = [
    # xingamentos diretos
    "fudido", "fodido", "fudida", "fodida", "fdp", "filho da puta",
    "filha da puta", "merda", "bosta", "lixo", "escroto", "escrota",
    "nojento", "nojenta", "imundo", "imunda", "asqueroso", "asquerosa",
    "desgracado", "desgracada", "desgraca", "maldito", "maldita", "ridiculo",
    "ridicula", "idiota", "imbecil", "otario", "otaria", "babaca", "cuzao",
    "corno", "corna", "porco", "porca", "arrombado", "arrombada", "verme",
    "parasita", "aberracao", "anormal", "monstro", "monstrengo", "horroroso",
    "horrorosa", "fedido", "fedida", "fedorento", "fede", "fedem", "safado",
    "safada", "nojeira", "nojo", "praga", "escoria", "vermes", "asco", "sujo",
    "suja", "imprestavel", "inutil", "patetico", "patetica", "repugnante",
    "vagabundo", "lazarento", "esquisito", "aberrante", "degenerado",
    "degenerada", "doente mental", "doentes mentais",
    # estereótipos desumanizantes
    "ladrao", "ladra", "ladroes", "preguicoso", "preguicosa", "atrasado",
    "atrasada", "sovina", "ganancioso", "gananciosa", "interesseiro",
    "selvagem", "primitivo", "primitiva", "burro", "burra", "cancer",
    "um cancer", "um peso", "um fardo", "fardo pra", "peso pra",
    "trambiqueiro", "trambiqueira", "agiota", "come cachorro", "nao trabalha",
    "so quer terra", "so querem terra", "nao sabe trabalhar", "nao servem",
    "nao servem pra nada",
    # servidão / controle / desumanização dirigida
    "so serve pra", "so servem pra", "so serve", "so servem", "so sabe",
    "so sabem", "nao serve pra nada", "nao presta", "nao prestam",
    "tem que obedecer", "feita pra servir", "feito pra servir",
    "so precisa de um homem", "nasceu homem", "nasceu mulher", "homem confuso",
    "mulher confusa", "na verdade um homem", "na verdade uma mulher",
    # patologização (LGBT/capacitismo)
    "e doenca", "e uma doenca", "uma doenca", "e transtorno", "transtorno mental",
    "uma aberracao", "precisa de cura", "tem cura", "precisa de tratamento",
    "internar", "internado", "internada", "internacao", "ser internad",
    "sao doentes", "todos doentes", "e doente", "de doente", "gente doente",
    "ideologia doente", "frescura", "firula", "modinha", "mimimi", "palhacada",
    "histerica", "histerico", "transtorno de genero", "nao deveria ter",
    "nao pode ter filho", "nao entende nada", "nao serve pra sociedade",
    "peso pra sociedade", "fardo pra familia", "fardo pra sociedade",
    # nazismo / negacionismo (composição com 'judeu' e afins)
    "gaseado", "gasear", "no forno", "forno pra", "vira sabao", "sabao",
    "camara de gas", "limpar a raca",
    # estereótipo religioso
    "demonio", "e demonio", "sao demonio", "um demonio", "tudo demonio",
    "adora o capeta", "filho do capeta",
    # misoginia (estereótipo / apologia)
    "dirige mal", "nao sabe dirigir", "ta pedindo", "tava pedindo",
    # xenofobia (estereótipos)
    "vieram roubar", "veio roubar", "veio tomar", "tomar nosso", "tomar nossos",
    "trouxeram doenca", "tudo bandido", "e bandido", "tudo ladrao", "tudo igual",
    "so vem roubar", "vem roubar", "so traz problema", "so trouxe problema",
    # religiosa
    "do diabo", "do demonio", "do capeta", "do capiroto", "coisa do diabo",
    "seita do demonio", "adora o demonio", "conversa com demonio",
    # agressão / desumanização (frases)
    "tem que morrer", "tem que sumir", "tinha que sumir", "deveria morrer",
    "devia morrer", "vai morrer", "merece morrer", "nao merece viver",
    "tinha que morrer", "some daqui", "sai daqui", "cai fora", "vai pro inferno",
    "queima no inferno", "te odeio", "odeio", "deviam matar", "deviam sumir",
    "exterminar", "nao deveria existir", "nao deveriam existir", "lugar de",
    "volta pra", "volta pro", "fora daqui", "praga de", "nasceu errado",
    "erro da natureza", "tem que apanhar", "merece apanhar",
]

# ── FRASES SEMPRE BLOQUEADAS: ataque inequívoco, ignora contexto de vítima. ──
# Supremacismo, apologia genocida e dog whistles. (Removemos "camara de gas"
# isolado — bloqueava aula/memorial do Holocausto; a apologia é pega por
# composição/frase com enquadramento de ataque.)
HARD_PHRASES = {
    "racismo": [
        "volta pra senzala", "volta pro tronco", "volta pra africa",
        "volta pra arvore", "raca inferior", "raca superior", "raca ariana",
        "white power", "poder branco", "supremacia branca", "heil hitler",
        "sieg heil", "queimar judeu", "queimar judeus", "judeu safado",
        "morte aos judeus", "macaco preto", "volta pro mato",
        "senzala e seu lugar", "pra senzala", "voltar pra senzala",
        "catorze palavras", "14 words", "14 palavras", "judeu vira sabao",
        "virar sabao", "judeu no forno", "forno pra judeu", "forno pra essa raca",
        "mais forno pra", "holocausto e farsa", "holocausto e mentira",
        "holocausto nunca existiu", "holocausto e a maior farsa",
        "maior farsa da historia", "judeu nenhum morreu", "nenhum judeu morreu",
        "6 milhoes de judeus", "seis milhoes de judeus", "hitler tinha razao",
        "hitler estava certo", "hitler tivesse ganhado", "limpar a raca",
        "fuhrer tinha", "planos certos pros judeus", "judeu gaseado",
        "camara de gas pra", "merecia camara de gas",
    ],
    "lgbtfobia": [
        "morte aos gays", "morte aos viados", "cura gay", "gay tem que morrer",
        "viado tem que morrer", "viado nojento", "veado nojento",
        "sapatao nojenta", "gay e doenca", "gayzismo", "matem os gays",
        "internar todo gay", "deveria ser internada", "lgbt e ideologia",
        "ideologia de genero e", "ideologia doente", "bicha louca",
        "bicha nojenta", "nome verdadeiro dela", "nome verdadeiro dele",
        "nasceu homem e", "na verdade um homem chamado", "modinha de doente",
        "transtorno de genero", "transgenerismo e", "nao binarismo e",
    ],
    "gordofobia": [
        "bola de banha", "monte de banha", "rolha de poco",
    ],
    "capacitismo": [
        "deveria ter sido abortado", "erro genetico", "vai pro hospicio",
    ],
    "misoginia": [
        "lugar de mulher e na cozinha", "volta pra cozinha", "mulher burra",
        "cala boca mulher", "vai lavar louca", "mulher nao presta",
        "mulher foi feita pra", "mulher tem que obedecer",
    ],
    "xenofobia": [
        "nordestino burro", "paraiba burro", "baiano preguicoso",
        "nordestino fede", "volta pro seu pais", "volta pra sua terra",
        "fora imigrantes", "fora estrangeiros",
    ],
    "intolerancia_religiosa": [
        "macumba e coisa do diabo", "macumba e do diabo", "religiao do capeta",
        "adorador do demonio", "fora macumbeiro", "candomble e do demonio",
        "candomble e seita",
    ],
}

# Marcadores de VÍTIMA, checados COLADOS antes do alvo (~30 chars à esquerda).
# Local = não é burlável: prefixar "me chamaram de" longe do ataque não protege.
VICTIM_BEFORE_MARKERS = (
    "me chamaram de", "me chamou de", "me chamavam de", "me chamam de",
    "me chamavam", "vivem me chamando de", "ja me chamaram de", "fui chamado de",
    "fui chamada de", "fui xingado de", "fui xingada de", "me xingaram de",
    "me xingou de", "apelido de", "apelidaram de", "apelidaram me de",
    "chamaram de", "chamam de", "chamou de", "chamava de", "disseram que sou",
    "disseram que eu sou", "falaram que sou", "me reduziram a", "me tratam como",
    "me trataram como",
)

# Marcadores de CONDENAÇÃO / denúncia (texto antirracista, antimachista...).
# Checados numa janela em torno do alvo: protegem quem CITA a ofensa pra
# condená-la (a menos que haja marcador de 3ª pessoa = ataque).
CONDEMNATION_MARKERS = (
    "e racismo", "e homofobia", "e transfobia", "e gordofobia", "e misoginia",
    "e xenofobia", "e capacitismo", "e intolerancia", "e preconceito",
    "e crime", "e inaceitavel", "e errado", "e absurdo", "e revoltante",
    "parem de", "pare de", "denuncio", "combater", "luta contra",
    "contra o racismo", "contra a homofobia", "contra o preconceito",
    "tratam", "tratar", "tratado como", "tratada como", "como tratam",
    "sofre preconceito", "ninguem merece", "quem chama", "que chama",
    "chamar de", "quem fala que", "quem diz que", "merece cadeia",
)

# 3ª pessoa = ataque a um GRUPO/terceiro. Bloqueia mesmo com vítima/self noutro
# ponto do texto (mata o contrabando "sou gay mas esses preto sao lixo").
# Demonstrativos só contam COLADOS ao alvo (à esquerda: "esses viado"; à direita:
# "viado tudo") — assim "essa merda toda" num desabafo NÃO é lido como ataque.
_TP_LEFT_RE = re.compile(
    r"\b(?:esses|essas|esse|essa|aqueles|aquelas|aquele|aquela|todo|toda|"
    r"todos|todas|uns|umas)\s*$"
)
_TP_RIGHT_RE = re.compile(r"^\s*(?:tudo|mesmo|mesma|todos|todas|sao\b)")
# Verbos/quantificadores que já caracterizam ataque a grupo, em qualquer lado.
_TP_VERB_RE = re.compile(
    r"\b(?:deviam|devia|deveria|sao tudo|so serve|so servem|"
    r"so sabe|so sabem|nao presta|nao prestam|tem que obedecer)\b".replace(" ", r"\s+")
)

# Frases de AUTO-RELATO (a pessoa fala da própria dor/condição), checadas à
# esquerda do alvo. Complementam a cópula ("sou/estou/ser…") logo abaixo.
SELF_PHRASE_MARKERS = (
    "na minha pele", "no meu corpo", "meu corpo", "minha condicao",
    "minha vida de", "vida de", "odeio ser", "odeio minha", "odeio meu",
    "odeio essa vida", "odeio minha vida", "cansei de ser", "cansado de ser",
    "cansada de ser", "vergonha de ser", "tenho vergonha de ser", "medo de ser",
    "sofro por ser", "sofro sendo", "dificil ser", "dificil de ser",
    "duro ser", "chato ser", "queria nao ser", "nao queria ser", "nasci",
    "me identifico como", "me assumi", "minha identidade",
)

# Cópula logo antes do alvo: "sou preto", "to gorda", "odeio ser gay",
# "me sinto um lixo"... → auto-referência (a própria identidade/condição).
_SELF_COPULA_RE = re.compile(
    r"(?:^|\b)(?:eu\s+)?(?:sou|to|tou|estou|fui|era|nasci|virei|sendo|ser|"
    r"me\s+sinto|me\s+senti|me\s+sentia|me\s+acho|me\s+achei|me\s+assumi|"
    r"me\s+torno|me\s+tornei|me\s+identifico\s+como|por\s+ser|enquanto|como)\s+"
    r"(?:um|uma|o|a|uns|umas|tao|muito|meio|super|bem)?\s*$"
)

# Distância máxima (em caracteres da visão espaçada) para considerar que um
# insulto está "perto" de uma identidade/slur — ~3 a 4 palavras.
_PROXIMITY_WINDOW = 22


# --- Pré-cálculo dos índices (uma vez, no import) ---------------------------

def _target_pattern(spaced_term):
    """Regex de palavra inteira, tolerante a espaçamento interno e a plural
    ('chines'→'chineses', 'viadinho'→'viadinhos', 'venezuelano'→'venezuelanos')."""
    return r"\b" + re.escape(spaced_term).replace(r"\ ", r"\s+") + r"(?:s|es)?\b"


def _build_index(category_map):
    """[(spaced, condensed, category, pattern)] a partir de {categoria: [termos]}."""
    index = []
    for category, terms in category_map.items():
        for term in terms:
            spaced = normalize_spaced(term)
            if not spaced:
                continue
            index.append((spaced, _condense_term(term), category,
                          re.compile(_target_pattern(spaced))))
    return index


def _build_flat_index(terms):
    index = []
    for term in terms:
        spaced = normalize_spaced(term)
        if not spaced:
            continue
        index.append((spaced, _condense_term(term), re.compile(_target_pattern(spaced))))
    return index


_SLUR_INDEX = _build_index(SLURS)
_CODED_INDEX = _build_index(CODED_TARGETS)
_IDENTITY_INDEX = _build_index(IDENTITY)
_INSULT_INDEX = _build_flat_index(INSULTS)
_HARD_PHRASE_INDEX = _build_index(HARD_PHRASES)

# Alvos = slurs ∪ coded ∪ identidades (o que um insulto pode estar atacando).
_TARGET_INDEX = _SLUR_INDEX + _CODED_INDEX + _IDENTITY_INDEX

# Padrões de ataque direto (2ª/3ª pessoa) montados sobre os ALVOS.
_TARGET_ALT = "|".join(
    sorted((re.escape(spaced).replace(r"\ ", r"\s+") for spaced, *_ in _TARGET_INDEX),
           key=len, reverse=True)
)
_ATTACK_PATTERNS = []
if _TARGET_ALT:
    _grp = r"(?:" + _TARGET_ALT + r")"
    _pl = r"(?:s|es)?\b"
    _ATTACK_PATTERNS = [
        re.compile(r"\bseus?\s+" + _grp + _pl),                       # "seus viado", "seu preto"
        re.compile(r"\bvoces?\s+" + _grp + _pl + r".{0,18}\b(?:nojent|merda|lixo|imund|fud)"),
        re.compile(r"\b(?:morr[ae]m?|matem?|exterminar|sumam?)\b.{0,22}\b" + _grp + _pl),
        re.compile(r"\bmorte\s+aos?\s+" + _grp + _pl),                # "morte aos chineses"
        re.compile(r"\b" + _grp + _pl + r".{0,18}\b(?:tem|tinha|deveria|devia|merec[ei]a?)\b.{0,12}\b(?:morrer|sumir|internad)"),
    ]

_SLUR_CONDENSED_CAT = [(cond, cat) for _, cond, cat, _ in _SLUR_INDEX if len(cond) >= 4]
_TARGET_CONDENSED = [(cond, cat) for spaced, cond, cat, _ in _TARGET_INDEX if len(cond) >= 3]
_INSULT_CONDENSED = [cond for _, cond, _ in _INSULT_INDEX if len(cond) >= 4]

# Pré-filtro: regex única com todos os alvos condensados. Numa palavra de prosa
# normal ("exausto") falha numa só busca, evitando o laço por ~200 termos.
_TARGET_CONDENSED_RE = re.compile(
    "|".join(sorted((re.escape(c) for c, _ in _TARGET_CONDENSED), key=len, reverse=True))
) if _TARGET_CONDENSED else None


# Perf: em vez de uma regex por termo (centenas de buscas no texto inteiro a cada
# análise), compilamos UMA regex por categoria. ~22 buscas em vez de ~600.
def _category_regex(index):
    by_cat = {}
    for spaced, _cond, cat, _pat in index:
        by_cat.setdefault(cat, []).append(spaced)
    out = {}
    for cat, spaceds in by_cat.items():
        alt = "|".join(sorted((re.escape(s).replace(r"\ ", r"\s+") for s in spaceds),
                              key=len, reverse=True))
        out[cat] = re.compile(r"\b(?:" + alt + r")(?:s|es)?\b")
    return out


_TARGET_CAT_RE = _category_regex(_TARGET_INDEX)
_SLUR_CAT_RE = _category_regex(_SLUR_INDEX)
_HARD_CAT_RE = _category_regex(_HARD_PHRASE_INDEX)
_INSULT_RE = re.compile(
    r"\b(?:" + "|".join(sorted((re.escape(s).replace(r"\ ", r"\s+")
                                for s, _, _ in _INSULT_INDEX), key=len, reverse=True))
    + r")(?:s|es)?\b"
)
_HARD_PHRASE_CONDS = [(cond, cat) for _s, cond, cat, _p in _HARD_PHRASE_INDEX if len(cond) >= 5]


def _scan(cat_regexes, text):
    """[(start, end, category)] varrendo uma regex combinada por categoria."""
    found = []
    for cat, rx in cat_regexes.items():
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), cat))
    return found

# Ofuscação por caractere: runs de letras isoladas separadas por pontuação ou
# espaço ("p.r.e.t.o", "p r e t o"). Prosa normal não tem 4+ chars isolados
# seguidos, então isso NÃO dispara em "gay merda" (palavras inteiras).
_OBFUSCATION_RUN = re.compile(r"(?:[a-z0-9]\W+){3,}[a-z0-9]")

# Inserção de 1 caractere "intruso" no meio do termo ("pretko", "negxro", "gaxy")
# sobrevivia às normalizações (o colapso só junta 3+ letras iguais) e quebrava o
# match de palavra inteira. Defesa: palavras que viram um ALVO conhecido ao
# remover UMA letra de {x,k,w,q,y} (raras no PT nativo) ou uma letra DOBRADA.
# Assim "minha"→"mina", "transa"→"trans", "carro"→"caro" NÃO viram alvo (a letra
# removida não é intrusa nem dobrada), evitando falso positivo.
_INTRUSIVE_CHARS = set("xkwqy")
_TARGET_PLAIN_CAT = {}
_SLUR_PLAIN = set()
for _sp, _cd, _cat, _pt in _TARGET_INDEX:
    # >=3 para alcançar alvos curtos como "gay" ("gaxy"→"gay"); a exigência de
    # letra intrusa/dobrada evita falso positivo em palavras comuns de 4 letras.
    if " " not in _sp and len(_sp) >= 3:
        _TARGET_PLAIN_CAT.setdefault(_sp, _cat)
for _sp, _cd, _cat, _pt in _SLUR_INDEX:
    if " " not in _sp and len(_sp) >= 4:
        _SLUR_PLAIN.add(_sp)


def _insertion_signals(spaced_text):
    """[(start,end,cat)] de alvos e de slurs recuperados removendo 1 letra intrusa
    ou dobrada de cada palavra. Desfaz 'pretko'→'preto', 'preeto'→'preto'."""
    targets, slurs = [], []
    for m in re.finditer(r"[a-z]{4,}", spaced_text):
        word = m.group()
        n = len(word)
        for i in range(n):
            ch = word[i]
            doubled = (i > 0 and word[i - 1] == ch) or (i + 1 < n and word[i + 1] == ch)
            if ch not in _INTRUSIVE_CHARS and not doubled:
                continue
            cand = word[:i] + word[i + 1:]
            cat = _TARGET_PLAIN_CAT.get(cand)
            if cat:
                targets.append((m.start(), m.end(), cat))
                if cand in _SLUR_PLAIN:
                    slurs.append((m.start(), m.end(), cat))
                break
    return targets, slurs


# --- Detecção ---------------------------------------------------------------

def _gap(a, b):
    """Distância (em caracteres) entre dois spans; 0 se sobrepõem/encostam."""
    return max(b[0] - a[1], a[0] - b[1], 0)


def _classify_signal(spaced_text, start, end):
    """Classifica um sinal de ódio pelo CONTEXTO LOCAL ao redor do alvo.

    Retorna:
    - 'hard'        → ataque a grupo/terceiro (marcador de 3ª pessoa por perto):
                      bloqueia mesmo com vítima/self em outro ponto do texto
                      (mata o contrabando "sou gay mas esses preto sao lixo").
    - 'protected'   → auto-relato/vítima/denúncia COLADOS ao alvo: deixa publicar.
    - 'unprotected' → sem contexto: trata como ataque (ex.: "preto fudido").
    """
    left_self = spaced_text[max(0, start - 22):start]
    left_phrase = spaced_text[max(0, start - 20):start]
    left_victim = spaced_text[max(0, start - 30):start]
    right = spaced_text[end:end + 14]
    around = spaced_text[max(0, start - 22):min(len(spaced_text), end + 22)]

    # 3ª pessoa (ataque a grupo) → bloqueia, ignorando vítima/self alhures.
    if _TP_LEFT_RE.search(left_self) or _TP_RIGHT_RE.search(right) or _TP_VERB_RE.search(around):
        return "hard"
    # auto-relato / vítima / denúncia COLADOS ao alvo → deixa publicar.
    if _SELF_COPULA_RE.search(left_self):
        return "protected"
    if any(m in left_phrase for m in SELF_PHRASE_MARKERS):
        return "protected"
    if any(m in left_victim for m in VICTIM_BEFORE_MARKERS):
        return "protected"
    if any(m in around for m in CONDEMNATION_MARKERS):
        return "protected"
    return "unprotected"


def evaluate_hate_speech(text, spaced_text, condensed_text, clean_text=""):
    """Avalia o eixo de discurso de ódio sobre o texto já normalizado."""
    categories = set()
    terms = []
    signals = []  # (start, end) de cada sinal localizável, p/ classificação local

    target_spans = _scan(_TARGET_CAT_RE, spaced_text)
    insult_spans = [(m.start(), m.end()) for m in _INSULT_RE.finditer(spaced_text)]
    slur_spans = _scan(_SLUR_CAT_RE, spaced_text)

    # Defesa contra inserção de 1 letra intrusa/dobrada ("pretko", "negxro").
    _ins_targets, _ins_slurs = _insertion_signals(spaced_text)
    target_spans += _ins_targets
    slur_spans += _ins_slurs

    # 1) Slur presente em grafia/leet → sinal de ódio localizável.
    for start, end, category in slur_spans:
        categories.add(category)
        terms.append(spaced_text[start:end])
        signals.append((start, end))

    # 2) Composição ALVO + INSULTO por perto (na visão espaçada).
    for t_start, t_end, t_cat in target_spans:
        for i_span in insult_spans:
            if _gap((t_start, t_end), i_span) <= _PROXIMITY_WINDOW:
                categories.add(t_cat)
                signals.append((t_start, t_end))
                break

    # Sinais sem posição localizável (ofuscação pesada): bloqueiam sempre, pois
    # não há contexto legítimo de vítima quando se ofusca de propósito.
    force_block = False

    # 3) Composição colada numa única palavra ofuscada (``pretofudido``).
    for word in _condensed_words(text):
        if len(word) < 6 or (_TARGET_CONDENSED_RE and not _TARGET_CONDENSED_RE.search(word)):
            continue
        for t_cond, t_cat in _TARGET_CONDENSED:
            if t_cond not in word:
                continue
            for i_cond in _INSULT_CONDENSED:
                if (t_cond + i_cond) in word or (i_cond + t_cond) in word:
                    categories.add(t_cat)
                    force_block = True
                    break

    # 3b) Ofuscação por caractere ("p.r.e.t.o f.u.d.i.d.o", "p r e t o ..."):
    # só quando há run de letras isoladas, olhamos a visão totalmente colada.
    if _OBFUSCATION_RUN.search(clean_text):
        for s_cond, s_cat in _SLUR_CONDENSED_CAT:
            if s_cond in condensed_text:
                categories.add(s_cat)
                terms.append(s_cond)
                force_block = True
        for t_cond, t_cat in _TARGET_CONDENSED:
            if t_cond not in condensed_text:
                continue
            for i_cond in _INSULT_CONDENSED:
                if (t_cond + i_cond) in condensed_text or (i_cond + t_cond) in condensed_text:
                    categories.add(t_cat)
                    force_block = True
                    break

    # 4) Identidade ofuscada SEM aparecer em grafia limpa: tentativa de driblar.
    # Versão "limpa": pontuação/underscore/dígitos viram espaço, sem leet — assim
    # "trans" em "sou_trans" é grafia normal, mas "g0rd0" conta como ofuscado.
    # Só pode haver identidade "leet-ofuscada" se houver dígito/símbolo leet no
    # texto; sem isso, a identidade apareceria em grafia limpa. Pula ~140 buscas.
    if re.search(r"[0-9@$]", clean_text):
        plain_spaced = re.sub(r"[^a-z\s]", " ", clean_text)
        for spaced, cond, category, pattern in _IDENTITY_INDEX:
            match = pattern.search(spaced_text)
            if match and not pattern.search(plain_spaced):
                categories.add(category)
                signals.append((match.start(), match.end()))

    # 5) Frases sempre bloqueadas (supremacismo / apologia) e padrões de ataque.
    hard_phrase = False
    for category, rx in _HARD_CAT_RE.items():
        if rx.search(spaced_text):
            categories.add(category)
            hard_phrase = True
    if not hard_phrase:
        for cond, category in _HARD_PHRASE_CONDS:
            if cond in condensed_text:
                categories.add(category)
                hard_phrase = True
                break

    pattern_attack = any(p.search(spaced_text) for p in _ATTACK_PATTERNS)
    if pattern_attack:
        # O ataque ("morte aos X", "seus X") é sobre os alvos presentes no texto:
        # registra a(s) categoria(s) para que conte como ódio e bloqueie.
        for _ts, _te, _tcat in target_spans:
            categories.add(_tcat)

    is_hate = bool(categories)

    # Classificação LOCAL de cada sinal: ataque a grupo (hard) vs vítima/self
    # (protected) vs sem-contexto (unprotected). Decisão final:
    instance_hard = False
    instance_unprotected = False
    instance_protected = False
    for start, end in signals:
        verdict = _classify_signal(spaced_text, start, end)
        if verdict == "hard":
            instance_hard = True
        elif verdict == "unprotected":
            instance_unprotected = True
        else:
            instance_protected = True

    block = (
        hard_phrase or pattern_attack or force_block
        or instance_hard or instance_unprotected
    )

    if not is_hate:
        action = HATE_ACTION_NONE
    elif block:
        action = HATE_ACTION_BLOCK
    elif instance_protected:
        # Vítima/auto-relato/denúncia: deixa publicar, mas avisa e sinaliza.
        action = HATE_ACTION_WARN
    else:
        action = HATE_ACTION_WARN

    return {
        "is_hate_speech": is_hate,
        "hate_categories": sorted(categories),
        "hate_category_labels": [CATEGORY_LABELS.get(c, c) for c in sorted(categories)],
        "hate_terms": sorted(set(terms)),
        "hate_action": action,
        "is_victim_report": instance_protected,
        "is_self_report": instance_protected,
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
    clean_text = _strip_accents(text or "").lower()

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


def contains_hate_speech(text):
    """True se o texto carrega qualquer discurso de ódio.

    Para campos de IDENTIDADE (nome, apelido, @username, bio) não existe o
    contexto de desabafo/vítima que existe num post — ninguém "relata uma
    agressão sofrida" no próprio nome. Então aqui qualquer sinal de ódio
    (slur, identidade+insulto, identidade ofuscada ou frase de ataque) é
    barrado, independente de contexto.
    """
    if not text or not text.strip():
        return False
    spaced_text = normalize_spaced(text)
    condensed_text = normalize_condensed(text)
    clean_text = _strip_accents(text).lower()
    return evaluate_hate_speech(
        text, spaced_text, condensed_text, clean_text=clean_text
    )["is_hate_speech"]
