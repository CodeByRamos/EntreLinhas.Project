"""Opcoes emocionais controladas para posts e avatares do EntreLinhas."""

EMOTIONAL_TAGS = [
    {"valor": "tristeza", "nome": "Tristeza", "mood_class": "mood-tristeza"},
    {"valor": "saudade", "nome": "Saudade", "mood_class": "mood-saudade"},
    {"valor": "raiva", "nome": "Raiva", "mood_class": "mood-raiva"},
    {"valor": "vazio", "nome": "Vazio", "mood_class": "mood-vazio"},
    {"valor": "amor", "nome": "Amor", "mood_class": "mood-amor"},
    {"valor": "culpa", "nome": "Culpa", "mood_class": "mood-culpa"},
    {"valor": "medo", "nome": "Medo", "mood_class": "mood-medo"},
    {"valor": "esperanca", "nome": "Esperança", "mood_class": "mood-esperanca"},
    {"valor": "confusao", "nome": "Confusão", "mood_class": "mood-confusao"},
    {"valor": "cansaco", "nome": "Cansaço", "mood_class": "mood-cansaco"},
    {"valor": "ansiedade", "nome": "Ansiedade", "mood_class": "mood-ansiedade"},
    {"valor": "gratidao", "nome": "Gratidão", "mood_class": "mood-gratidao"},
    {"valor": "solidao", "nome": "Solidão", "mood_class": "mood-solidao"},
    {"valor": "luto", "nome": "Luto", "mood_class": "mood-luto"},
    {"valor": "recomeco", "nome": "Recomeço", "mood_class": "mood-recomeco"},
]

EMOTIONAL_TAG_VALUES = {tag["valor"] for tag in EMOTIONAL_TAGS}
EMOTIONAL_TAG_LABELS = {tag["valor"]: tag["nome"] for tag in EMOTIONAL_TAGS}
DEFAULT_EMOTIONAL_TAG = "vazio"

DEFAULT_AVATARS = [
    {"valor": "vazio", "nome": "Vazio"},
    {"valor": "eco", "nome": "Eco"},
    {"valor": "noite", "nome": "Noite"},
    {"valor": "mare", "nome": "Maré"},
    {"valor": "neblina", "nome": "Neblina"},
    {"valor": "carta", "nome": "Carta"},
]

DEFAULT_AVATAR_VALUES = {avatar["valor"] for avatar in DEFAULT_AVATARS}
DEFAULT_AVATAR = "vazio"


def normalize_emotional_tag(value):
    value = (value or "").strip().lower()
    return value if value in EMOTIONAL_TAG_VALUES else DEFAULT_EMOTIONAL_TAG


def is_valid_emotional_tag(value):
    return (value or "").strip().lower() in EMOTIONAL_TAG_VALUES


def mood_class(value):
    return f"mood-{normalize_emotional_tag(value)}"


def normalize_default_avatar(value):
    value = (value or "").strip().lower()
    return value if value in DEFAULT_AVATAR_VALUES else DEFAULT_AVATAR


def dominant_mood(posts):
    counts = {}
    for post in posts or []:
        tag = normalize_emotional_tag(post["emotional_tag"] if "emotional_tag" in post.keys() else None)
        counts[tag] = counts.get(tag, 0) + 1
    if not counts:
        return DEFAULT_EMOTIONAL_TAG
    return max(counts.items(), key=lambda item: item[1])[0]
