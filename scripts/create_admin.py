"""Cria ou reseta o administrador do EntreLinhas via variaveis de ambiente."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.admin_setup import AdminSetupError, create_or_reset_admin_from_env


def main():
    try:
        result = create_or_reset_admin_from_env()
    except AdminSetupError as exc:
        raise SystemExit(f"Não foi possível configurar o admin: {exc}") from exc

    print(result["message"])
    print(f"E-mail: {result['email']}")
    print(f"Username: {result['username']}")
    print(f"Banco: {result['database']}")
    print("Agora entre em /admin/login com o e-mail e a senha definidos no ambiente.")


if __name__ == "__main__":
    main()
