"""Filtro de discurso de ódio: precisa barrar ataques em qualquer campo,
resistir a ofuscação e, ao mesmo tempo, proteger quem desabafa a própria dor.

Inclui o caso EXATO reportado em produção ("preto fudido" + "poorra"), que o
filtro antigo (baseado em frases exatas) deixou passar.
"""

import pytest

from utils.sensitive_filter import (
    evaluate_sensitive_content,
    contains_hate_speech,
    HATE_ACTION_BLOCK,
    HATE_ACTION_WARN,
)


def _blocks(text):
    return evaluate_sensitive_content(text)["block_publication"] is True


def _action(text):
    return evaluate_sensitive_content(text)["hate_action"]


# ---------------------------------------------------------------------------
# O caso reportado e suas variações
# ---------------------------------------------------------------------------

def test_reported_case_blocks():
    # Título "preto fudido" + corpo "poorra" — exatamente o que passou antes.
    assert _blocks("preto fudido poorra")


@pytest.mark.parametrize("text", [
    "preto fudido",
    "PRETO FUDIDO",
    "preto fodido",
    "preeeto fudiiido",          # alongamento
    "pr3t0 fud1d0",              # leet
    "preto.fudido",              # separador
    "p.r.e.t.o f.u.d.i.d.o",     # ofuscação por caractere
    "p r e t o f u d i d o",     # letras espaçadas
    "pretofudido",               # colado
    "pr3t0fud1d0",               # colado + leet
])
def test_racist_attack_variants_block(text):
    assert _blocks(text), f"deveria bloquear: {text!r}"


# ---------------------------------------------------------------------------
# Composição identidade + insulto (o coração da correção)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "negro de merda",
    "esse gay nojento",
    "trans imundo",
    "nordestino burro demais",
    "judeu safado",
    "essa mulher nojenta",
    "gordo asqueroso",
    "deficiente que nao deveria existir",
    "macumbeiro do capeta",
])
def test_identity_plus_insult_blocks(text):
    assert _blocks(text), f"deveria bloquear: {text!r}"


@pytest.mark.parametrize("text", [
    "volta pra senzala",
    "morte aos gays",
    "cura gay",
    "white power",
    "heil hitler",
    "raca inferior",
    "seus viado",
    "seu retardado",
])
def test_hard_attacks_always_block(text):
    assert _blocks(text), f"deveria bloquear: {text!r}"


# ---------------------------------------------------------------------------
# Slurs puros
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "voce e um retardado",
    "que crioulo",
    "olha o v-i-a-d-o",   # slur ofuscado
    "r3t4rd4d0",          # slur em leet
])
def test_bare_slur_blocks_without_context(text):
    assert _blocks(text), f"deveria bloquear: {text!r}"


# ---------------------------------------------------------------------------
# Proteção à vítima e ao auto-relato: NUNCA bloquear quem desabafa a própria dor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "me chamaram de preto fudido e eu chorei",
    "fui chamado de viado a vida toda",
    "sofri racismo no trabalho hoje",
    "vivem me chamando de gorda nojenta e doi",
])
def test_victim_reports_are_not_blocked(text):
    # Quem RELATA a agressão sofrida nunca é barrado (no máximo recebe um aviso).
    assert not _blocks(text), f"NÃO deveria bloquear (vítima): {text!r}"
    assert _action(text) != HATE_ACTION_BLOCK


def test_victim_quoting_slur_is_warned_not_blocked():
    # Caso clássico de vítima citando a ofensa que recebeu → aviso, não bloqueio.
    assert _action("vivem me chamando de gorda nojenta e doi") == HATE_ACTION_WARN


@pytest.mark.parametrize("text", [
    "eu sou preto e to fudido nessa vida",
    "sou gay e to puto da vida com meu chefe",
    "sou gorda e me sinto um lixo hoje",
    "por ser trans eu sofro todo dia",
])
def test_self_reports_are_not_blocked(text):
    assert not _blocks(text), f"NÃO deveria bloquear (auto-relato): {text!r}"


# ---------------------------------------------------------------------------
# Falsos positivos: desabafo comum, profanidade sem alvo, identidade neutra
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "hoje foi um dia muito dificil no trabalho",
    "que dia de merda, to exausto",          # profanidade sem alvo
    "amo minha pele negra e meu cabelo",     # identidade afirmativa
    "sou trans e tenho muito orgulho disso",
    "trabalho com pessoas trans incriveis",
    "sonho em ser aviador um dia",           # "aviador" contém "viado"
    "comprei um sapato novo",
    "comecei terapia essa semana e ajudou",
    "minha mae faz uma comida maravilhosa",
])
def test_legitimate_text_is_not_hate(text):
    result = evaluate_sensitive_content(text)
    assert result["block_publication"] is False, f"bloqueou indevidamente: {text!r}"


# ---------------------------------------------------------------------------
# Ofuscação avançada: homóglifos unicode e caracteres invisíveis
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "рreto fudido",                 # 'р' cirílico no lugar de 'p'
    "prеtо fudido",            # 'е' e 'о' cirílicos
    "seu criоulо",             # 'o' cirílico em crioulo
    "mаcаcа nojenta",     # 'a' cirílico em macaca
    "ｐｒｅｔｏ fudido",                       # largura total (fullwidth)
])
def test_homoglyph_attacks_block(text):
    assert _blocks(text), f"homóglifo deveria bloquear: {text!r}"


@pytest.mark.parametrize("text", [
    "pre​to fudido",   # zero-width space cortando a palavra
    "pre­to fudido",   # soft hyphen
    "p‍reto fudido",   # zero-width joiner
])
def test_invisible_char_attacks_block(text):
    assert _blocks(text), f"caractere invisível deveria bloquear: {text!r}"


# ---------------------------------------------------------------------------
# Campos de identidade (nome, @usuário, bio): tolerância zero, sem contexto
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "pretofudido",
    "preto_fudido",
    "pr3t0fud1d0",
    "viadonojento",
    "gay nojento",
    "retardado",
    "crioulo",
])
def test_identity_fields_reject_hate(value):
    assert contains_hate_speech(value) is True, f"deveria rejeitar no campo: {value!r}"


@pytest.mark.parametrize("value", [
    "joaosilva",
    "amante_da_vida",
    "maria.flor",
    "aviador123",
    "sou_trans_e_orgulhosa",
    "pretinho_do_coracao",   # afetivo, sem insulto
])
def test_identity_fields_allow_clean_names(value):
    assert contains_hate_speech(value) is False, f"rejeitou indevidamente: {value!r}"


# ---------------------------------------------------------------------------
# Regressão da auditoria adversarial (bypasses confirmados que foram corrigidos)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    # identidades antes ausentes (asiáticos, macaco)
    "chines nojento", "japa fudido", "esse japa imundo", "asiatico merda",
    "macaco nojento", "macaco tem que morrer", "morte aos chineses",
    # estereótipos desumanizantes
    "judeu ganancioso", "cigano ladrao", "indio preguicoso e atrasado",
    "negro fede", "esses preto so servem pra roubar",
    # LGBT: patologização e deadnaming
    "homossexualismo e uma doenca que precisa de cura",
    "transexualismo e transtorno mental", "esses gays sao todos doentes",
    "devia internar todo gay", "bicha nojenta", "transtorno de genero e frescura",
    "esse trans ai e na verdade um homem chamado Carlos",
    # plurais e demonstrativos
    "esses viadinhos de hoje em dia", "esses venezuelanos vieram roubar nossos empregos",
    "esses candomblecistas sao tudo demonio",
    # capacitismo / misoginia / xenofobia / religião
    "autista nao deveria ter filho", "down nao serve pra nada",
    "mulher tem que obedecer o marido", "essas feministas sao um cancer",
    "refugiado e tudo bandido", "macumba e do diabo",
    # dog whistles / apologia nazista
    "raca ariana e superior", "sieg heil, gloria ao reich",
    "o holocausto e a maior farsa da historia, judeu nenhum morreu",
    "queria que o hitler tivesse ganhado pra limpar a raca",
    # contrabando via contexto de vítima/self (ataque a OUTRO grupo)
    "eu sou preto e esses viado tudo nojento",
    "sofri racismo, mas viado mesmo tinha que sumir",
    "eu sou lesbica e acho viado um nojo",
])
def test_audit_bypasses_now_blocked(text):
    assert _blocks(text), f"bypass da auditoria deveria bloquear: {text!r}"


@pytest.mark.parametrize("text", [
    # auto-ódio / sofrimento de pessoas marginalizadas (NÃO pode bloquear)
    "sou gorda e me odeio", "odeio ser negro", "odeio ser gay", "odeio ser gorda",
    "to gordo e me odeio", "odeio ser trans", "sou negro e odeio isso",
    "sou gay e to deprimido odeio minha vida", "sou gorda e me acho um lixo",
    "a vida de gay nesse pais e uma merda", "ser mulher nesse mundo e uma merda",
    "ser preto nesse pais e uma merda", "minha vida de gordo e uma merda",
    "cansei de ser gay e essa merda toda",
    # história / educação (Holocausto)
    "meu trabalho de historia e sobre as camaras de gas de auschwitz",
    "sou neta de sobrevivente da camara de gas",
    # palavras inocentes (regionais / animais / objetos)
    "a baleia azul e o maior animal", "ele ficou manco depois do acidente no joelho",
    "imperio mongol dominou a asia", "a rapariga portuguesa chegou",
    "comprei uma bucha pra lavar louca",
    # discurso antirracista / de denúncia
    "odeio o racismo, tratam preto como lixo nesse pais",
    "parem de tratar gordo como lixo, isso e gordofobia",
    "quem fala que viado e nojento merece cadeia",
])
def test_audit_false_positives_now_pass(text):
    assert not _blocks(text), f"texto legítimo NÃO deveria bloquear: {text!r}"


# ---------------------------------------------------------------------------
# Auditoria adversarial — 2ª rodada (inserção de 1 letra + slurs regionais)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    # inserção de 1 caractere intruso/dobrado (sobrevivia às normalizações)
    "pretko fudido", "negxro nojento", "gxordo de merda", "transx nojento",
    "gaxy nojento", "obxeso nojento", "preeto fudido", "viaado nojento",
    "gorrdo de merda",
    # slurs / estereótipos regionais antes ausentes
    "esses bugre nao servem pra nada", "morte aos bugre", "curiboca burro",
    "esses cabeca chata tudo vagabundo", "esses pau de arara fede",
    "esses portuga ladrao", "japa come cachorro", "esses indio so querem terra",
    "esses judeu agiota", "esses cigano trambiqueiro",
    "venezuelano so vem roubar emprego",
])
def test_audit_round2_bypasses_now_blocked(text):
    assert _blocks(text), f"bypass (2ª rodada) deveria bloquear: {text!r}"


@pytest.mark.parametrize("text", [
    # a defesa de inserção NÃO pode ferir palavras comuns próximas de palavrão
    "minha vida e uma merda", "essa transa foi uma merda", "meu carro e uma merda",
    "meu portugues ta uma merda", "que saco esse dia de hoje",
    # termos CODED com sentido inocente comum
    "comprei uma frutinha no mercado", "que florzinha mais linda",
    "o caboclo das matas e uma entidade", "meu amigo gay ta doente hoje",
])
def test_round2_guards_no_false_positive(text):
    assert not _blocks(text), f"NÃO deveria bloquear (guard 2ª rodada): {text!r}"


# ---------------------------------------------------------------------------
# Ataques INDIRETOS (sem demonstrativo de 3ª pessoa) — red-team manual
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "lugar de viado e no inferno",
    "todo gay deveria sumir",
    "gay nao deveria existir",
    "queria que todo viado sumisse",
    "lugar de preto e na senzala",
    "mundo melhor sem viado",
])
def test_indirect_attacks_block(text):
    assert _blocks(text), f"ataque indireto deveria bloquear: {text!r}"


@pytest.mark.parametrize("value,expected", [
    ("viadko", True),       # slur ofuscado por inserção → rejeita
    ("pretolixo", True),    # identidade + insulto colados → rejeita
    ("orgulho_gay", False),  # afirmativo → permite
    ("preto_e_lindo", False),
    ("trans_e_feliz", False),
])
def test_identity_field_obfuscation_and_affirmation(value, expected):
    assert contains_hate_speech(value) is expected, f"{value!r} deveria ser {expected}"


# ---------------------------------------------------------------------------
# O eixo emocional continua intacto
# ---------------------------------------------------------------------------

def test_emotional_axis_still_works():
    result = evaluate_sensitive_content("nao aguento mais, penso em me matar")
    assert result["risk_level"] == "HIGH"
    # risco emocional NÃO é discurso de ódio
    assert result["is_hate_speech"] is False
    assert result["block_publication"] is False
