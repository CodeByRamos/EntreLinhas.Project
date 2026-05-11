"""Compatibilidade para uploads de perfil.

As rotas continuam importando `save_profile_photo` daqui, mas a gravação real
passa pela camada de storage configurável em `utils.storage`.
"""

from utils.storage import save_profile_photo
