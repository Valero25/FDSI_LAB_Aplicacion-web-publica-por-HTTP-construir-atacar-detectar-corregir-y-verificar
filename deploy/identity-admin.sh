#!/usr/bin/env bash
# Administracion de identidades en el servidor (alta de usuarios, TOTP, baja). Ejecutar con sudo:
#   sudo bash deploy/identity-admin.sh gen-keys | sudo tee -a /etc/muvautomation.env >/dev/null
#   sudo bash deploy/identity-admin.sh create-user marta --role lector
#   sudo bash deploy/identity-admin.sh create-user rosa --role respondedor   # imprime el secreto TOTP una vez
#   sudo bash deploy/identity-admin.sh list-users
# Corre como el usuario del servicio (muvapi) para que la base conserve su dueno. El archivo de
# secretos NO se ejecuta como shell (un ";" en MUV_ANALYSTS separaria comandos y mostraria claves):
# solo se leen, como texto, las dos variables que la CLI necesita.
# Variables de prueba (no se usan en produccion): MUV_REPO, MUV_ENV_FILE, MUV_PYTHON,
# MUV_ADMIN_ALLOW_NONROOT=1.
set -euo pipefail
REPO="${MUV_REPO:-/opt/fdsi-lab3}"
ENV_FILE="${MUV_ENV_FILE:-/etc/muvautomation.env}"
PYTHON="${MUV_PYTHON:-$REPO/.venv/bin/python}"
if [ "$(id -u)" -ne 0 ] && [ "${MUV_ADMIN_ALLOW_NONROOT:-}" != "1" ]; then
  echo "Ejecutar con sudo"; exit 1
fi

# Lee NOMBRE=valor del archivo como texto (primera aparicion; quita comillas envolventes).
read_var() {
  [ -r "$ENV_FILE" ] || return 0
  awk -v k="$1" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); exit }' "$ENV_FILE" \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
for name in MUV_JWT_PRIVATE_KEY MUV_TOTP_KEY; do
  value="$(read_var "$name")"
  if [ -n "$value" ]; then export "$name=$value"; fi   # por entorno: no aparece en `ps`
done
export MUV_DATA_DIR="${MUV_DATA_DIR:-/var/lib/muvautomation}"

# -E ignora PYTHON*; -s ignora el site del usuario. NO se usa -I: ignora el directorio actual
# y entonces "-m app.identity_cli" no encuentra el paquete.
cd "$REPO"
if [ "$(id -u)" -eq 0 ] && [ "${MUV_ADMIN_ALLOW_NONROOT:-}" != "1" ]; then
  exec runuser -u muvapi -- "$PYTHON" -E -s -m app.identity_cli "$@"
fi
exec "$PYTHON" -E -s -m app.identity_cli "$@"   # solo pruebas: sin cambio de usuario
