"""Cargos oficiais da equipe EntreLinhas.

Um cargo é só um selo de confiança ao lado do nome — quem é da equipe aparece
identificado em desabafos, respostas e no perfil. Usuários comuns não recebem
selo: continuam sendo "uma voz entre as linhas".

A fonte da verdade é a coluna ``users.role`` (texto, minúsculo). Só admin pode
atribuir cargos (ver ``routes/admin.py``).
"""

# Ordem de hierarquia, do mais comum ao mais alto. Usada na tela de gestão.
ROLE_ORDER = ['user', 'collaborator', 'ceo', 'admin']

# Selos visíveis. 'user' não tem selo de propósito (mantém o anonimato comum).
ROLE_BADGES = {
    'collaborator': {'label': 'Colaborador', 'slug': 'collaborator', 'title': 'Pessoa colaboradora do EntreLinhas'},
    'ceo': {'label': 'CEO', 'slug': 'ceo', 'title': 'Fundador e CEO do EntreLinhas'},
    'admin': {'label': 'Equipe', 'slug': 'admin', 'title': 'Equipe de moderação do EntreLinhas'},
}

# Rótulos legíveis para todos os cargos (inclui o comum), usados na gestão.
ROLE_LABELS = {
    'user': 'Usuário',
    'collaborator': 'Colaborador',
    'ceo': 'CEO',
    'admin': 'Equipe',
}


def normalize_role(role):
    """Devolve um cargo válido em minúsculo; cargo desconhecido vira 'user'."""
    value = (str(role).strip().lower() if role else 'user')
    return value if value in ROLE_ORDER else 'user'


def get_role_badge(role):
    """Selo para exibir ao lado do nome, ou ``None`` para usuário comum.

    Pensado para ser chamado direto no template: ``{% set rb = role_badge(...) %}``.
    """
    if not role:
        return None
    return ROLE_BADGES.get(str(role).strip().lower())


def is_official_role(role):
    """True quando o cargo merece selo (qualquer coisa além de usuário comum)."""
    return get_role_badge(role) is not None
