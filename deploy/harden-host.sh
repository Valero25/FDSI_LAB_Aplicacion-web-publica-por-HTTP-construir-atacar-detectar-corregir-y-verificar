#!/usr/bin/env bash
# Endurecimiento del host (V2, V3, V9, V10, V12, V14, V15). Idempotente. Ejecutar en el servidor:
#   sudo LAB_CIDR=192.168.61.0/24 ADMIN_USER=<usuario_ssh> SSH_CLIENT="$SSH_CLIENT" bash deploy/harden-host.sh
# (sudo suele eliminar SSH_CLIENT: se pasa a mano; si llega vacio se intenta obtener con `who -m`.)
# Orden seguro (leccion del incidente de ufw): primero se crean los allow, luego se cierra el resto.
set -euo pipefail
# Nada de este script debe leer de la terminal: ejecutado como "sudo ... | tee", un comando que la abre
# (apt/debconf, needrestart, un paginador) queda DETENIDO (estado T) esperando una respuesta invisible.
exec </dev/null
export SYSTEMD_PAGER=""

: "${LAB_CIDR:?Defina LAB_CIDR, p. ej. 192.168.61.0/24}"
: "${ADMIN_USER:?Defina ADMIN_USER (usuario que administra por SSH)}"
REPO=/opt/fdsi-lab3

# Unidades de systemd: se instalan solo si cambiaron y se hace un unico daemon-reload (evita el aviso
# NeedDaemonReload y recargas innecesarias en cada ejecucion).
UNITS_CHANGED=no
install_unit() {
  if ! cmp -s "$1" "$2"; then install -D -m 644 "$1" "$2"; UNITS_CHANGED=yes; fi
}
reload_units_once() {
  if [ "$UNITS_CHANGED" = yes ]; then systemctl daemon-reload; UNITS_CHANGED=no; fi
}
[ "$(id -u)" -eq 0 ] || { echo "Ejecutar con sudo"; exit 1; }

# IP de la sesion SSH: la usan la comprobacion contra LAB_CIDR y el ignoreip de fail2ban.
if [ -z "${SSH_CLIENT:-}" ]; then
  WHO_IP="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F:.]*\)).*/\1/p' | head -n1)"
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
  # chrony usa NTS: primero intercambia claves por TCP 4460 con los servidores de Canonical y luego
  # consulta por 123/udp. Sin esto el reloj no sincroniza, y de la hora dependen la caducidad de los
  # JWT y de los tokens de renovacion y la ventana de TOTP. Solo esos rangos (no 4460 a todo internet);
  # si Canonical los cambia, R5 vera los bloqueos y "chronyc -N authdata" mostrara el fallo.
  ufw allow out to 185.125.190.0/24 port 4460 proto tcp comment 'NTS Ubuntu'
  ufw allow out to 91.189.91.0/24 port 4460 proto tcp comment 'NTS Ubuntu'
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
install -m 644 "$REPO/deploy/logrotate-modsecurity" /etc/logrotate.d/fdsi-lab3-modsecurity
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
install_unit "$REPO/deploy/muvautomation-detect.service" /etc/systemd/system/muvautomation-detect.service
install_unit "$REPO/deploy/muvautomation-detect.timer" /etc/systemd/system/muvautomation-detect.timer
install_unit "$REPO/deploy/muvautomation-api.service" /etc/systemd/system/muvautomation-api.service

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
  # Virtual host del repo (rate limit muv_auth, cabeceras, TLS). Antes se copiaba a mano y en la VM
  # quedo una version vieja sin el limite del login. Los certificados que referencia no se generan aqui.
  NGX_SITE=/etc/nginx/sites-available/fdsi-lab3
  NGX_LINK=/etc/nginx/sites-enabled/fdsi-lab3
  NGX_SITE_CHANGED=no
  NGX_SITE_BACKUP=""
  NGX_LINK_CREATED=no
  if ! cmp -s "$REPO/nginx/muvautomation.conf" "$NGX_SITE"; then
    if [ -f "$NGX_SITE" ]; then
      NGX_SITE_BACKUP="/root/fdsi-lab3.nginx.$(date +%Y%m%d-%H%M%S).bak"
      cp -a "$NGX_SITE" "$NGX_SITE_BACKUP"
    fi
    install -m 644 "$REPO/nginx/muvautomation.conf" "$NGX_SITE"
    NGX_SITE_CHANGED=yes
  fi
  if [ ! -e "$NGX_LINK" ]; then
    ln -sfn "$NGX_SITE" "$NGX_LINK"   # -f: reemplaza un enlace roto que haya quedado
    NGX_LINK_CREATED=yes
    NGX_SITE_CHANGED=yes
  fi
  if [ "$NGX_SITE_CHANGED" = yes ]; then
    if NGX_TEST="$(nginx -t 2>&1)"; then
      # Se aplica abajo: con el reinicio si cambia el sandbox y, si no, con reload (nunca las dos cosas).
      echo "   configuracion de Nginx instalada en $NGX_SITE${NGX_SITE_BACKUP:+ (respaldo: $NGX_SITE_BACKUP)}"
    else
      # Configuracion invalida: se restaura lo anterior para que nginx siga sirviendo con ella.
      if [ -n "$NGX_SITE_BACKUP" ]; then install -m 644 "$NGX_SITE_BACKUP" "$NGX_SITE"; else rm -f "$NGX_SITE"; fi
      if [ "$NGX_LINK_CREATED" = yes ]; then rm -f "$NGX_LINK"; fi
      if nginx -t >/dev/null 2>&1; then systemctl reload nginx || true; fi
      NGX_SITE_CHANGED=no
      echo "   AVISO: nginx -t rechazo nginx/muvautomation.conf; se restauro la configuracion anterior (el limite del login puede no estar activo)."
      echo "   Salida de nginx -t:"; printf '%s\n' "$NGX_TEST" | sed 's/^/     /'
      echo "   Revise certificados TLS y sitios duplicados en /etc/nginx/sites-enabled (p. ej. default o muvautomation)."
    fi
  fi

  # Etapa G: frontend estatico del analista (frontend/ -> /var/www/fdsi-lab3, servido en /app/).
  # root:root, directorio 755 y archivos 644: www-data (Nginx) solo puede leerlo. Se arma aparte y se
  # cambia de una vez, para que Nginx nunca sirva una mezcla de version vieja y nueva.
  WEB_DIR=/var/www/fdsi-lab3
  if ! diff -rq "$REPO/frontend" "$WEB_DIR" >/dev/null 2>&1; then
    WEB_BACKUP=""
    install -d -m 755 -o root -g root /var/www
    if [ -d "$WEB_DIR" ]; then
      WEB_BACKUP="/root/fdsi-lab3-www.$(date +%Y%m%d-%H%M%S).bak"
      cp -a "$WEB_DIR" "$WEB_BACKUP"
    fi
    WEB_NEW="$(mktemp -d /var/www/.fdsi-lab3.XXXXXX)"
    # Solo HTML, JS y CSS (lo que comprueba tests/test_frontend.py): nada oculto ni de otro tipo.
    install -m 644 -o root -g root "$REPO"/frontend/*.html "$REPO"/frontend/*.js "$REPO"/frontend/*.css "$WEB_NEW"/
    chmod 755 "$WEB_NEW"
    rm -rf "$WEB_DIR"
    mv "$WEB_NEW" "$WEB_DIR"
    if NGX_TEST="$(nginx -t 2>&1)"; then
      echo "   frontend instalado en $WEB_DIR${WEB_BACKUP:+ (respaldo: $WEB_BACKUP)}"
    else
      # Los estaticos no cambian la configuracion, pero se sigue el mismo patron: si algo falla, se
      # vuelve a la version anterior.
      rm -rf "$WEB_DIR"
      if [ -n "$WEB_BACKUP" ]; then cp -a "$WEB_BACKUP" "$WEB_DIR"; fi
      echo "   AVISO: nginx -t fallo tras instalar el frontend; se restauro la version anterior."
      echo "   Salida de nginx -t:"; printf '%s\n' "$NGX_TEST" | sed 's/^/     /'
    fi
  fi

  # Etapa F: WAF ModSecurity v3 + OWASP CRS en modo solo deteccion. El sitio lo carga con
  # "include /etc/nginx/fdsi-lab3-waf.d/*.conf": sin ese archivo, el sitio sirve igual pero sin WAF.
  # WAF_ENABLE=no lo retira. Rutas de los paquetes de Ubuntu: comprobarlas en la VM antes (ver README).
  WAF_SRC="$REPO/nginx/modsecurity"
  WAF_DIR=/etc/nginx/fdsi-lab3-modsecurity
  WAF_SNIPPET=/etc/nginx/fdsi-lab3-waf.d/waf.conf
  WAF_FILES="modsecurity.conf crs-setup.conf privacidad.conf exclusiones.conf main.conf"
  CRS_RULES=/usr/share/modsecurity-crs/rules
  NGX_WAF_CHANGED=no
  if [ "${WAF_ENABLE:-yes}" != yes ]; then
    if [ -f "$WAF_SNIPPET" ]; then rm -f "$WAF_SNIPPET"; NGX_WAF_CHANGED=yes; echo "   WAF retirado (WAF_ENABLE=no)"; fi
  else
    WAF_PKGS=""
    for p in libnginx-mod-http-modsecurity modsecurity-crs; do
      dpkg -s "$p" >/dev/null 2>&1 || WAF_PKGS="$WAF_PKGS $p"
    done
    if [ -n "$WAF_PKGS" ]; then
      echo "   instalando paquetes del WAF (puede tardar):$WAF_PKGS"
      # --no-install-recommends: modsecurity-crs no debe arrastrar el modulo de Apache (ni Apache).
      # Sin terminal (D-7): debconf no pregunta, dpkg conserva los archivos de configuracion locales,
      # needrestart reinicia servicios sin preguntar y apt-listchanges no abre un paginador.
      # shellcheck disable=SC2086 # lista de paquetes separada por espacios a proposito
      DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none \
        apt-get install -y -q --no-install-recommends \
          -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
          $WAF_PKGS </dev/null >/dev/null \
        || echo "   AVISO: no se pudieron instalar:$WAF_PKGS"
    fi
    # Audit log: solo root y el grupo adm (el de los logs de Nginx; detect.py lo lee con ese grupo).
    # El archivo se crea de antemano para www-data por si lo abre un worker y no el proceso maestro.
    install -d -m 750 -o root -g adm /var/log/modsecurity
    [ -e /var/log/modsecurity/audit.json ] || install -m 640 -o www-data -g adm /dev/null /var/log/modsecurity/audit.json
    if ! compgen -G "/etc/nginx/modules-enabled/*modsecurity*" >/dev/null || [ ! -f "$CRS_RULES/REQUEST-901-INITIALIZATION.conf" ]; then
      echo "   AVISO: falta el modulo ModSecurity de Nginx (modules-enabled) o las reglas CRS en $CRS_RULES; el sitio sigue sin WAF."
    else
      for f in $WAF_FILES; do cmp -s "$WAF_SRC/$f" "$WAF_DIR/$f" || NGX_WAF_CHANGED=yes; done
      cmp -s "$WAF_SRC/waf.conf" "$WAF_SNIPPET" || NGX_WAF_CHANGED=yes
    fi
    if [ "$NGX_WAF_CHANGED" = yes ]; then
      WAF_BACKUP=""
      if [ -f "$WAF_SNIPPET" ] && [ -d "$WAF_DIR" ]; then
        WAF_BACKUP="/root/fdsi-lab3-waf.$(date +%Y%m%d-%H%M%S).bak"
        cp -a "$WAF_DIR" "$WAF_BACKUP"
        cp -a "$WAF_SNIPPET" "$WAF_BACKUP/waf.conf.snippet"
      fi
      install -d -m 755 "$WAF_DIR" "$(dirname "$WAF_SNIPPET")"
      for f in $WAF_FILES; do install -m 644 "$WAF_SRC/$f" "$WAF_DIR/$f"; done
      install -m 644 "$WAF_SRC/waf.conf" "$WAF_SNIPPET"
      if NGX_TEST="$(nginx -t 2>&1)"; then
        echo "   WAF instalado en modo DetectionOnly${WAF_BACKUP:+ (respaldo: $WAF_BACKUP)}"
      else
        # Reversion: primero la version anterior del WAF; si no la habia o tampoco valida, sin WAF.
        if [ -n "$WAF_BACKUP" ]; then
          for f in $WAF_FILES; do
            if [ -f "$WAF_BACKUP/$f" ]; then install -m 644 "$WAF_BACKUP/$f" "$WAF_DIR/$f"; fi
          done
          install -m 644 "$WAF_BACKUP/waf.conf.snippet" "$WAF_SNIPPET"
        else
          rm -f "$WAF_SNIPPET"
        fi
        nginx -t >/dev/null 2>&1 || rm -f "$WAF_SNIPPET"
        echo "   AVISO: nginx -t rechazo la configuracion del WAF; se restauro ${WAF_BACKUP:+la version anterior del WAF o }el sitio sin WAF."
        echo "   Salida de nginx -t:"; printf '%s\n' "$NGX_TEST" | sed 's/^/     /'
        if [ ! -f "$WAF_SNIPPET" ]; then
          echo "   El sitio sirve SIN WAF. Revise las rutas: dpkg -L modsecurity-crs libnginx-mod-http-modsecurity"
        fi
      fi
    fi
  fi

  NGX_DROPIN=/etc/systemd/system/nginx.service.d/hardening.conf
  NGX_DROPIN_CHANGED=no
  cmp -s "$REPO/deploy/nginx-hardening.conf" "$NGX_DROPIN" || NGX_DROPIN_CHANGED=yes
  install_unit "$REPO/deploy/nginx-hardening.conf" "$NGX_DROPIN"
  reload_units_once
  if [ "$NGX_DROPIN_CHANGED" = yes ] || ! systemctl is-active --quiet nginx; then
    if nginx -t >/dev/null 2>&1 && systemctl restart nginx && sleep 1 && systemctl is-active --quiet nginx; then
      echo "   nginx activo con el sandbox de systemd"
    else
      # Reversion: si nginx no vuelve a levantar con el sandbox, se retira el drop-in.
      rm -f "$NGX_DROPIN"; systemctl daemon-reload; systemctl restart nginx || true
      echo "   AVISO: nginx no arranco con el sandbox; se revirtio el drop-in (revise: journalctl -u nginx)"
    fi
  elif [ "$NGX_SITE_CHANGED" = yes ] || [ "$NGX_WAF_CHANGED" = yes ]; then
    if systemctl reload nginx; then
      echo "   nginx recargado con la configuracion nueva"
    else
      echo "   AVISO: no se pudo recargar nginx (revise: journalctl -u nginx)"
    fi
  else
    echo "   nginx sin cambios"
  fi
fi

echo "[7] Servicio"
reload_units_once   # no hace nada si ya se recargo en el paso de Nginx o si ninguna unidad cambio
systemctl enable muvautomation-api muvautomation-detect.timer
# restart (no "enable --now"): tras un git pull, el codigo nuevo se carga aunque la API ya estuviera activa.
systemctl restart muvautomation-api
systemctl restart muvautomation-detect.timer
systemd-analyze security muvautomation-api --no-pager | tail -3
# Solo aviso: tras abrir NTS la primera sincronizacion tarda unos segundos.
if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" != "yes" ]; then
  echo "AVISO: el reloj aun no esta sincronizado (JWT, renovacion y TOTP dependen de la hora). Revise en un minuto: timedatectl; sudo chronyc -N authdata"
fi
echo "Listo. Verifique: systemctl status muvautomation-api; sudo ufw status verbose; sudo sshd -T | grep -Ei 'passwordauth|permitroot'; systemctl list-timers muvautomation-detect.timer; sudo fail2ban-client status; sudo auditctl -l | head"
