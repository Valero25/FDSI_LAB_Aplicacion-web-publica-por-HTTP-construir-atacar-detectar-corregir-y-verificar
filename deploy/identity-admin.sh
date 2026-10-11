#!/usr/bin/env bash
# Administracion de identidades en el servidor (alta de usuarios, TOTP, baja). Ejecutar con sudo:
#   sudo bash deploy/identity-admin.sh create-user marta --role lector
#   sudo bash deploy/identity-admin.sh create-user rosa --role respondedor   # imprime el secreto TOTP una vez
#   sudo bash deploy/identity-admin.sh list-users
# Corre como el usuario del servicio (muvapi) con las claves de /etc/muvautomation.env, para que la
# base conserve su dueno y los secretos no pasen por la linea de comandos.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecutar con sudo"; exit 1; }
REPO=/opt/fdsi-lab3
set -a; . /etc/muvautomation.env; set +a
export MUV_DATA_DIR=/var/lib/muvautomation
cd "$REPO"
exec runuser -u muvapi -- "$REPO/.venv/bin/python" -I -m app.identity_cli "$@"
