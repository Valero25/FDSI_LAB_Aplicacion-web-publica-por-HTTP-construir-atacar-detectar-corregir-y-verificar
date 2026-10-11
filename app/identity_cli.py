"""Administracion de identidades. El alta de usuarios NO es un endpoint: solo se hace aqui, en el
servidor, por quien tiene acceso al host (no existe usuario por defecto ni registro abierto).

    python -m app.identity_cli gen-keys
    python -m app.identity_cli create-user USUARIO --role lector|respondedor
    python -m app.identity_cli set-password USUARIO
    python -m app.identity_cli enroll-totp USUARIO     # secreto nuevo (reinicia el segundo factor)
    python -m app.identity_cli disable-user USUARIO
    python -m app.identity_cli list-users

La contrasena se pide por terminal sin eco (nunca como argumento: quedaria en el historial y en
`ps`). Ejecutar como el usuario del servicio con deploy/identity-admin.sh.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import sqlite3
import sys
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import identity


def _db_path() -> Path:
    return Path(os.environ.get("MUV_DATA_DIR") or Path(__file__).resolve().parent) / "alerts.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    identity.init_schema(conn)
    return conn


def _ask_password(ask=getpass.getpass) -> str:
    first = ask("Contrasena: ")
    if first != ask("Repita la contrasena: "):
        raise ValueError("las contrasenas no coinciden")
    return first


def _show_totp(username: str, secret: str, out) -> None:
    print("Segundo factor (TOTP). Este secreto se muestra UNA sola vez; entreguelo por un canal seguro.", file=out)
    print(f"  Secreto : {secret}", file=out)
    print(f"  URI     : {identity.provisioning_uri(username, secret)}", file=out)


def main(argv=None, ask_password=getpass.getpass, out=sys.stdout) -> int:
    ap = argparse.ArgumentParser(description="Administracion de identidades de MuvAutomation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-keys", help="genera MUV_JWT_PRIVATE_KEY y MUV_TOTP_KEY para /etc/muvautomation.env")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("--role", required=True, choices=identity.ROLES)
    for name in ("set-password", "enroll-totp", "disable-user"):
        sub.add_parser(name).add_argument("username")
    sub.add_parser("list-users")
    args = ap.parse_args(argv)

    if args.cmd == "gen-keys":
        seed = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        print(f"MUV_JWT_PRIVATE_KEY={base64.b64encode(seed).decode()}", file=out)
        print(f"MUV_TOTP_KEY={Fernet.generate_key().decode()}", file=out)
        return 0

    try:
        with _connect() as conn:
            if args.cmd == "create-user":
                secret = identity.create_user(conn, args.username, _ask_password(ask_password), args.role)
                print(f"Usuario {args.username.lower()} creado con rol {args.role}.", file=out)
                if secret:
                    _show_totp(args.username, secret, out)
            elif args.cmd == "set-password":
                identity.set_password(conn, args.username, _ask_password(ask_password))
                print("Contrasena actualizada; las sesiones abiertas de ese usuario quedaron cerradas.", file=out)
            elif args.cmd == "enroll-totp":
                _show_totp(args.username, identity.enroll_totp(conn, args.username), out)
            elif args.cmd == "disable-user":
                identity.disable_user(conn, args.username)
                print("Usuario deshabilitado y sesiones cerradas.", file=out)
            elif args.cmd == "list-users":
                for u in identity.list_users(conn):
                    state = "deshabilitado" if u["disabled"] else "activo"
                    print(f"{u['username']:<20} {u['role']:<12} {state:<14} totp={'si' if u['totp'] else 'no'}", file=out)
    except (ValueError, identity.IdentityError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
