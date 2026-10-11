#!/usr/bin/env bash
# Administracion de identidades en el servidor (alta de usuarios, TOTP, baja). Ejecutar con sudo:
#   sudo bash deploy/identity-admin.sh gen-keys | sudo tee -a /etc/muvautomation.env >/dev/null
#   sudo bash deploy/identity-admin.sh create-user marta --role lector
#   sudo bash deploy/identity-admin.sh create-user rosa --role respondedor   # imprime el secreto TOTP una vez
#   sudo bash deploy/identity-admin.sh list-users
#   sudo bash deploy/identity-admin.sh static-keys off    # apaga las claves X-Analyst-Key (agrega o reemplaza la linea)
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

# Lee NOMBRE=valor del archivo como texto. Si la variable esta repetida vale la ULTIMA aparicion:
# es lo que hace systemd con EnvironmentFile, asi script y servicio ven siempre el mismo valor.
read_var() {
  [ -r "$ENV_FILE" ] || return 0
  awk -v k="$1" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2); found = 1 } END { if (found) print v }' "$ENV_FILE" \
    | sed -e 's/\r$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# Deja UNA sola linea NOMBRE=valor en el archivo: la agrega si no existe y la reemplaza si existe.
set_env_var() {
  local tmp
  tmp="$(mktemp)"
  { grep -v "^$1=" "$ENV_FILE" 2>/dev/null || true; } > "$tmp"
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  install -m 600 "$tmp" "$ENV_FILE"
  rm -f "$tmp"
}

case "${1:-}" in
  gen-keys)
    # Generar claves nuevas sobre unas existentes dejaria usuarios enrolados con una clave de TOTP
    # y un servicio que descifra con otra: se rechaza. Rotarlas es una decision manual.
    if [ -n "$(read_var MUV_JWT_PRIVATE_KEY)" ] || [ -n "$(read_var MUV_TOTP_KEY)" ]; then
      echo "ERROR: $ENV_FILE ya tiene MUV_JWT_PRIVATE_KEY o MUV_TOTP_KEY. Rotarlas invalida todas las sesiones y los secretos TOTP enrolados; si es lo que busca, borre esas lineas a mano y vuelva a ejecutar." >&2
      exit 1
    fi
    ;;
  static-keys)
    case "${2:-}" in
      off) value=no ;;
      on) value=yes ;;
      *) echo "Uso: static-keys on|off" >&2; exit 2 ;;
    esac
    set_env_var MUV_ALLOW_ANALYST_STATIC_KEYS "$value"
    echo "MUV_ALLOW_ANALYST_STATIC_KEYS=$value (lineas en el archivo: $(grep -c '^MUV_ALLOW_ANALYST_STATIC_KEYS=' "$ENV_FILE")). Reinicie: sudo systemctl restart muvautomation-api"
    exit 0
    ;;
esac

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
