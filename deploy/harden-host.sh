#!/usr/bin/env bash
# Endurecimiento del host (V2, V3, V9, V10, V12, V14, V15). Idempotente. Ejecutar en el servidor:
#   sudo LAB_CIDR=192.168.61.0/24 ADMIN_USER=<usuario_ssh> bash deploy/harden-host.sh
# Orden seguro (leccion del incidente de ufw): primero se crean los allow, luego se cierra el resto.
set -euo pipefail

: "${LAB_CIDR:?Defina LAB_CIDR, p. ej. 192.168.61.0/24}"
: "${ADMIN_USER:?Defina ADMIN_USER (usuario que administra por SSH)}"
REPO=/opt/fdsi-lab3
[ "$(id -u)" -eq 0 ] || { echo "Ejecutar con sudo"; exit 1; }

echo "[1] Usuario de sistema dedicado (V3)"
id muvapi >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin muvapi

echo "[2] Migrar DB y logs fuera del codigo (V2)"
install -d -m 750 -o muvapi -g muvapi /var/lib/muvautomation /var/log/muvautomation
if [ -f "$REPO/app/alerts.db" ] && [ ! -f /var/lib/muvautomation/alerts.db ]; then
  systemctl stop muvautomation-api 2>/dev/null || true
  cp -a "$REPO"/app/alerts.db* /var/lib/muvautomation/
  [ -d "$REPO/logs" ] && cp -a "$REPO/logs/." /var/log/muvautomation/
  chown -R muvapi:muvapi /var/lib/muvautomation /var/log/muvautomation
  chmod 600 /var/lib/muvautomation/alerts.db*
fi
# El codigo pasa a root: el servicio solo puede leerlo.
chown -R root:root "$REPO"
chmod -R go-w "$REPO"

echo "[3] Permisos de secretos (V9, V15)"
if [ -f /etc/muvautomation.env ]; then
  chown root:root /etc/muvautomation.env
  chmod 600 /etc/muvautomation.env
fi
if [ -f /etc/ssl/private/lab3-server.key ]; then
  chown root:ssl-cert /etc/ssl/private/lab3-server.key
  chmod 640 /etc/ssl/private/lab3-server.key
fi

echo "[4] Firewall: primero allow, luego deny (V14)"
ufw allow from "$LAB_CIDR" to any port 22 proto tcp
ufw allow from "$LAB_CIDR" to any port 443 proto tcp
ufw allow from "$LAB_CIDR" to any port 80 proto tcp
ufw default deny incoming
ufw status numbered

echo "[5] SSH solo con llave (V14), con proteccion contra autobloqueo"
KEYS="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
[ -s "$KEYS" ] || { echo "ABORTO: $KEYS esta vacio. Instale su llave publica antes de cerrar PasswordAuthentication."; exit 1; }
install -m 644 "$REPO/deploy/sshd-hardening.conf" /etc/ssh/sshd_config.d/99-lab3.conf
sshd -t
systemctl reload ssh

echo "[6] Rotacion de logs (V10) y fail2ban (V12)"
install -m 644 "$REPO/deploy/logrotate-muvautomation" /etc/logrotate.d/muvautomation
if command -v fail2ban-client >/dev/null; then
  install -m 644 "$REPO/deploy/fail2ban/muvautomation.conf" /etc/fail2ban/filter.d/muvautomation.conf
  install -m 644 "$REPO/deploy/fail2ban/jail-muvautomation.local" /etc/fail2ban/jail.d/muvautomation.local
  systemctl restart fail2ban
else
  echo "   fail2ban no esta instalado: sudo apt install -y fail2ban y repita"
fi

echo "[7] Servicio"
install -m 644 "$REPO/deploy/muvautomation-api.service" /etc/systemd/system/muvautomation-api.service
systemctl daemon-reload
systemctl enable --now muvautomation-api
systemd-analyze security muvautomation-api --no-pager | tail -3
echo "Listo. Verifique: systemctl status muvautomation-api; sudo ufw status verbose; sudo sshd -T | grep -Ei 'passwordauth|permitroot'"
