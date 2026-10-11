#!/usr/bin/env bash
# Endurecimiento del host (V2, V3, V9, V10, V12, V14, V15). Idempotente. Ejecutar en el servidor:
#   sudo LAB_CIDR=192.168.61.0/24 ADMIN_USER=<usuario_ssh> SSH_CLIENT="$SSH_CLIENT" bash deploy/harden-host.sh
# (sudo suele eliminar SSH_CLIENT: se pasa a mano; si llega vacio se intenta obtener con `who -m`.)
# Orden seguro (leccion del incidente de ufw): primero se crean los allow, luego se cierra el resto.
set -euo pipefail

: "${LAB_CIDR:?Defina LAB_CIDR, p. ej. 192.168.61.0/24}"
: "${ADMIN_USER:?Defina ADMIN_USER (usuario que administra por SSH)}"
REPO=/opt/fdsi-lab3
[ "$(id -u)" -eq 0 ] || { echo "Ejecutar con sudo"; exit 1; }

# IP de la sesion SSH: la usan la comprobacion contra LAB_CIDR y el ignoreip de fail2ban.
if [ -z "${SSH_CLIENT:-}" ]; then
  WHO_IP="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F:.]*\)).*//p' | head -n1)"
  if [ -n "$WHO_IP" ]; then SSH_CLIENT="$WHO_IP 0 22"; fi
fi
[ -n "${SSH_CLIENT:-}" ] || echo "AVISO: no se pudo determinar su IP SSH; no se valida contra LAB_CIDR ni se agrega a ignoreip de fail2ban."

# Primero las comprobaciones que evitan quedar fuera del servidor: no se toca nada si fallan.
KEYS="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
[ -s "$KEYS" ] || { echo "ABORTO (sin cambios): $KEYS esta vacio o no existe. Instale su llave publica y pruebe el acceso con llave antes de ejecutar este script."; exit 1; }

# La sesion SSH actual debe quedar dentro de las reglas allow que se van a crear.
if [ -n "${SSH_CLIENT:-}" ] && command -v python3 >/dev/null; then
  python3 - "${SSH_CLIENT%% *}" "$LAB_CIDR" <<'PY' || { echo "ABORTO (sin cambios): su IP SSH (${SSH_CLIENT%% *}) no pertenece a LAB_CIDR=$LAB_CIDR; ufw le cortaria la sesion."; exit 1; }
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False) else 1)
PY
fi

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
# Tras migrar, la copia vieja no debe quedar dentro del directorio del codigo (datos duplicados).
if [ -f /var/lib/muvautomation/alerts.db ]; then
  rm -f "$REPO"/app/alerts.db "$REPO"/app/alerts.db-wal "$REPO"/app/alerts.db-shm
  # Los logs solo se borran si ya existen en el destino (nunca se pierde lo no copiado).
  if [ -f /var/log/muvautomation/actions.log ]; then rm -rf "$REPO/logs"; fi
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
  # Nginx lee la llave con su proceso maestro (root): ningun otro usuario o grupo la necesita.
  chown root:root /etc/ssl/private/lab3-server.key
  chmod 600 /etc/ssl/private/lab3-server.key
fi

echo "[4] Firewall: primero allow, luego deny, y se activa (V14)"
# "limit": ufw rechaza una IP con 6 o mas conexiones SSH en 30 s (frena la fuerza bruta antes de sshd).
ufw limit from "$LAB_CIDR" to any port 22 proto tcp
ufw allow from "$LAB_CIDR" to any port 443 proto tcp
ufw allow from "$LAB_CIDR" to any port 80 proto tcp
ufw default deny incoming
# Sin "enable" las reglas anteriores quedan guardadas pero no se aplican.
ufw --force enable
ufw status verbose | grep -q "^Status: active" || { echo "ERROR: ufw no quedo activo"; exit 1; }
# Las reglas antiguas "OpenSSH ALLOW Anywhere" se evaluan ANTES que el limit y dejan SSH abierto a todos.
# Ya existen los allow restringidos al CIDR (arriba), asi que borrarlas no deja sin acceso.
ufw --force delete allow OpenSSH >/dev/null 2>&1 || true
ufw --force delete allow 22/tcp >/dev/null 2>&1 || true
ufw --force delete allow 22 >/dev/null 2>&1 || true
ufw --force delete allow 80/tcp >/dev/null 2>&1 || true
ufw --force delete allow 443/tcp >/dev/null 2>&1 || true
ufw --force delete allow "Nginx Full" >/dev/null 2>&1 || true
if ufw status | grep -E "^(22(/tcp)?|OpenSSH)( \(v6\))? +(ALLOW|LIMIT) +Anywhere" >/dev/null; then
  echo "AVISO: queda una regla de SSH abierta a Anywhere; revise: sudo ufw status numbered"
fi
# Filtrado de salida (G15): primero los allow out, despues el default deny. DNS, NTP, apt/HTTPS y DHCP.
if [ "${EGRESS_FILTER:-yes}" = "yes" ]; then
  ufw allow out 53
  ufw allow out 123/udp
  ufw allow out 80/tcp
  ufw allow out 443/tcp
  ufw allow out 67/udp
  ufw default deny outgoing
fi
# Registra los bloqueos en /var/log/ufw.log: es la unica fuente de un escaneo SYN (regla R4 de detect.py).
ufw logging medium
ufw status numbered

echo "[5] SSH solo con llave (V14), con proteccion contra autobloqueo"
# sshd usa el PRIMER valor que encuentra: el prefijo 00- hace que gane sobre 50-cloud-init.conf
# y cualquier otro fragmento que active PasswordAuthentication.
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-lab3.conf
SSHD_BACKUP="$(mktemp)"
[ -f "$SSHD_DROPIN" ] && cp -a "$SSHD_DROPIN" "$SSHD_BACKUP" || : > "$SSHD_BACKUP"
rm -f /etc/ssh/sshd_config.d/99-lab3.conf   # nombre usado por versiones anteriores del script
install -m 644 "$REPO/deploy/sshd-hardening.conf" "$SSHD_DROPIN"
# Oculta el sufijo de distribucion/paquete del banner SSH (solo si esta version de sshd lo soporta).
SSHD_PROBE="$(sshd -T 2>/dev/null || true)"   # en variable: con pipefail, "grep -q" cortaria la tuberia (SIGPIPE)
if grep -qi '^debianbanner' <<<"$SSHD_PROBE"; then echo "DebianBanner no" >> "$SSHD_DROPIN"; fi
if ! sshd -t; then
  # Configuracion invalida: se restaura lo anterior para que un reinicio de sshd no falle.
  if [ -s "$SSHD_BACKUP" ]; then install -m 644 "$SSHD_BACKUP" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
  rm -f "$SSHD_BACKUP"
  echo "ERROR: sshd -t rechazo la configuracion; se restauro el estado anterior."; exit 1
fi
rm -f "$SSHD_BACKUP"
systemctl reload ssh
# La configuracion efectiva (no solo el archivo) debe cerrar las contrasenas.
SSHD_EFFECTIVE="$(sshd -T)"   # en variable: con pipefail, "grep -q" cortaria la tuberia (SIGPIPE)
grep -qi '^passwordauthentication no' <<<"$SSHD_EFFECTIVE" \
  || echo "ADVERTENCIA: PasswordAuthentication sigue activo; otro fragmento de sshd_config lo define antes (revise: sshd -T | grep -i passwordauthentication)"
if grep -qi '^debianbanner yes' <<<"$SSHD_EFFECTIVE"; then
  echo "ADVERTENCIA: DebianBanner sigue en yes; el banner SSH aun revela la distribucion (revise: sshd -T | grep -i debianbanner)"
fi

echo "[6] Rotacion de logs (V10), fail2ban (V12) y deteccion periodica (V-06)"
install -m 644 "$REPO/deploy/logrotate-muvautomation" /etc/logrotate.d/muvautomation
if command -v fail2ban-client >/dev/null; then
  install -m 644 "$REPO/deploy/fail2ban/muvautomation.conf" /etc/fail2ban/filter.d/muvautomation.conf
  install -m 644 "$REPO/deploy/fail2ban/jail-muvautomation.local" /etc/fail2ban/jail.d/muvautomation.local
  install -m 644 "$REPO/deploy/fail2ban/jail-sshd.local" /etc/fail2ban/jail.d/sshd-lab3.local
  # La IP del administrador no debe poder autobloquearse (3 llaves erroneas = ban de 1 h).
  if [ -n "${SSH_CLIENT:-}" ]; then
    ADMIN_IP="${SSH_CLIENT%% *}"
    sed -i "s|^ignoreip.*|ignoreip  = 127.0.0.1/8 ::1 ${ADMIN_IP}|"       /etc/fail2ban/jail.d/muvautomation.local /etc/fail2ban/jail.d/sshd-lab3.local
  fi
  systemctl restart fail2ban
else
  echo "   fail2ban no esta instalado: sudo apt install -y fail2ban y repita"
fi
install -m 644 "$REPO/deploy/muvautomation-detect.service" /etc/systemd/system/muvautomation-detect.service
install -m 644 "$REPO/deploy/muvautomation-detect.timer" /etc/systemd/system/muvautomation-detect.timer

echo "[8] Endurecimiento de kernel/red, auditoria y Nginx (best effort: un fallo aqui no deja el host inseguro)"
install -m 644 "$REPO/deploy/sysctl-hardening.conf" /etc/sysctl.d/99-lab3.conf
sysctl --system >/dev/null 2>&1 || echo "   AVISO: sysctl reporto parametros no soportados por este kernel (el resto se aplico)"
if command -v augenrules >/dev/null; then
  install -m 640 "$REPO/deploy/audit/lab3.rules" /etc/audit/rules.d/lab3.rules
  augenrules --load >/dev/null 2>&1 || echo "   AVISO: no se pudieron cargar las reglas de auditd (reglas inmutables? requiere reinicio)"
else
  echo "   auditd no esta instalado: sudo apt install -y auditd y repita"
fi
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
else
  echo "   unattended-upgrades no esta instalado: sudo apt install -y unattended-upgrades (parches de seguridad automaticos)"
fi
if systemctl cat nginx >/dev/null 2>&1; then
  NGX_DROPIN=/etc/systemd/system/nginx.service.d/hardening.conf
  install -D -m 644 "$REPO/deploy/nginx-hardening.conf" "$NGX_DROPIN"
  systemctl daemon-reload
  if nginx -t >/dev/null 2>&1 && systemctl restart nginx && sleep 1 && systemctl is-active --quiet nginx; then
    echo "   nginx activo con el sandbox de systemd"
  else
    # Reversion: si nginx no vuelve a levantar con el sandbox, se retira el drop-in.
    rm -f "$NGX_DROPIN"; systemctl daemon-reload; systemctl restart nginx || true
    echo "   AVISO: nginx no arranco con el sandbox; se revirtio el drop-in (revise: journalctl -u nginx)"
  fi
fi

echo "[7] Servicio"
install -m 644 "$REPO/deploy/muvautomation-api.service" /etc/systemd/system/muvautomation-api.service
systemctl daemon-reload
systemctl enable muvautomation-api muvautomation-detect.timer
# restart (no "enable --now"): tras un git pull, el codigo nuevo se carga aunque la API ya estuviera activa.
systemctl restart muvautomation-api
systemctl restart muvautomation-detect.timer
systemd-analyze security muvautomation-api --no-pager | tail -3
echo "Listo. Verifique: systemctl status muvautomation-api; sudo ufw status verbose; sudo sshd -T | grep -Ei 'passwordauth|permitroot'; systemctl list-timers muvautomation-detect.timer; sudo fail2ban-client status; sudo auditctl -l | head"
