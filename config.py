import os

# Configurações básicas
SECRET_KEY = 'chave-secreta-segura'  # Em produção, usar uma chave segura e armazenada em variável de ambiente
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'entrelinhas.db')

# Configurações de categorias
CATEGORIAS = [
    {'valor': 'estudo', 'nome': 'Estudo'},
    {'valor': 'família', 'nome': 'Família'},
    {'valor': 'trabalho', 'nome': 'Trabalho'},
    {'valor': 'amizade', 'nome': 'Amizade'},
    {'valor': 'relacionamento', 'nome': 'Relacionamento'},
    {'valor': 'saúde', 'nome': 'Saúde'},
    {'valor': 'outros', 'nome': 'Outros'}
]

# Configurações de reações
REACOES = [
    {'valor': 'te_entendo', 'nome': 'Te entendo', 'emoji': '🤝'},
    {'valor': 'forca', 'nome': 'Força!', 'emoji': '💪'},
    {'valor': 'abraco', 'nome': 'Abraço virtual', 'emoji': '🫂'},
    {'valor': 'coracao', 'nome': 'Coração', 'emoji': '❤️'},
    {'valor': 'inspirador', 'nome': 'Inspirador', 'emoji': '✨'}
]

