"""Script utilitário para criar/promover usuário administrador."""

import argparse
import getpass

import database as db


def main():
    parser = argparse.ArgumentParser(description="Cria ou promove um usuário admin no EntreLinhas.")
    parser.add_argument("--username", required=True, help="Username do admin")
    parser.add_argument("--password", help="Senha do admin (se omitido, será solicitada)")
    parser.add_argument("--nickname", help="Apelido exibido")
    parser.add_argument("--email", help="Email opcional")
    parser.add_argument("--bio", help="Bio opcional")

    args = parser.parse_args()
    password = args.password or getpass.getpass("Senha do administrador: ")

    if len(password) < 6:
        raise SystemExit("A senha precisa ter pelo menos 6 caracteres.")

    db.init_db()
    success, message = db.ensure_admin_user(
        username=args.username,
        password=password,
        nickname=args.nickname,
        bio=args.bio,
        email=args.email,
    )

    if not success:
        raise SystemExit(message)

    print(message)
    print("Agora faça login em /admin/login com essas credenciais.")


if __name__ == "__main__":
    main()