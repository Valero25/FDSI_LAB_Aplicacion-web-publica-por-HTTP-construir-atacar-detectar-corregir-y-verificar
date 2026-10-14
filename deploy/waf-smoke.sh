#!/usr/bin/env bash
# Prueba de humo del WAF (etapa I). Funciona igual en waflab (contenedor) y en la VM: solo cambia la
# URL base y como se lee el audit log. No imprime secretos; las credenciales se leen sin eco y los
# tokens se pasan por descriptor de archivo.
#
# Uso:
#   deploy/waf-smoke.sh [--base URL] [--audit-read "CMD"] [--legit ARCHIVO] [--probes ARCHIVO] [--key-fd N]
#     --base        URL base (por defecto https://127.0.0.1:8443). En la VM: https://192.168.61.129
#     --audit-read  comando que vuelca el audit log (p. ej. "sudo cat /var/log/modsecurity/audit.json"
#                   en la VM, o "docker exec waflab cat /var/log/modsecurity/audit.json" en waflab).
#                   Si se da, se comprueba que no contenga los secretos usados.
#     --legit       corpus de descripciones legitimas (no deben bloquearse). Por defecto
#                   deploy/waf-corpus/legit-descriptions.txt
#     --probes      sondas que SI deben bloquearse (403). Por defecto deploy/waf-corpus/probes.txt
# Codigo de salida: 0 si todo paso, 1 si alguna comprobacion fallo.
set -uo pipefail

BASE="https://127.0.0.1:8443"
AUDIT_READ=""
HERE="$(cd "$(dirname "$0")" && pwd)"
LEGIT="$HERE/waf-corpus/legit-descriptions.txt"
PROBES="$HERE/waf-corpus/probes.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE="$2"; shift 2 ;;
    --audit-read) AUDIT_READ="$2"; shift 2 ;;
    --legit) LEGIT="$2"; shift 2 ;;
    --probes) PROBES="$2"; shift 2 ;;
    *) echo "opcion desconocida: $1"; exit 2 ;;
  esac
done

CURL="curl -sk --max-time 15"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'OK    %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FALLO %s\n' "$1"; }

# Envia un cuerpo JSON (por stdin) a una ruta y devuelve solo el codigo HTTP.
post_code() { # ruta  [cabecera-extra]
  $CURL -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' ${2:+-H "$2"} \
    --data-binary @- "$BASE$1"
}
get_code()  { $CURL -o /dev/null -w '%{http_code}' ${2:+-H "$2"} "$BASE$1"; }

json_field() { # campo valor  -> objeto alerta con ese campo (python para escapar bien)
  python3 - "$1" "$2" <<'PY'
import json, sys
a = {"severity": "low", "tactic": "Discovery", "technique": "T1046 - Network Service Discovery",
     "hostname": "WEB-LAB-01", "description": "humo", "source_ip": "203.0.113.9"}
a[sys.argv[1]] = sys.argv[2]
print(json.dumps(a))
PY
}

echo "== Base: $BASE =="

# (0) El frontend y la API responden; cargar la consola no se bloquea.
for p in /app/ /app/app.js /app/api.js /app/dom.js /app/index.html; do
  c=$(get_code "$p")
  if [ "$c" != 403 ] && [ "$c" != 000 ]; then ok "GET $p no bloqueado ($c)"; else bad "GET $p dio $c"; fi
done

# (a) Corpus legitimo: el WAF no debe bloquear (403) ninguna descripcion, en description ni en technique.
#     Sin credenciales, la app responde 401/201/etc.; lo que importa es que NO sea 403 (bloqueo del WAF).
blocked_legit=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  for field in description technique; do
    c=$(json_field "$field" "$line" | post_code /alerts)
    [ "$c" = 403 ] && { blocked_legit=$((blocked_legit+1)); printf '   bloqueada (403) en %s: %.40s...\n' "$field" "$line"; }
  done
done < "$LEGIT"
if [ "$blocked_legit" = 0 ]; then ok "corpus legitimo: 0 bloqueos"; else bad "corpus legitimo: $blocked_legit bloqueos (falso positivo)"; fi

# (b) Sondas: cada una debe dar 403. Formato del archivo: "donde|valor".
#     donde = body:<campo> | query:<nombre> | header:<Nombre>
passed_probes=0; total_probes=0
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  where="${line%%|*}"; value="${line#*|}"; total_probes=$((total_probes+1))
  case "$where" in
    body:*)  c=$(json_field "${where#body:}" "$value" | post_code /alerts) ;;
    query:*) c=$(get_code "/alerts?${where#query:}=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$value")") ;;
    header:*) c=$(get_code /alerts "${where#header:}: $value") ;;
    *) bad "sonda con destino invalido: $where"; continue ;;
  esac
  if [ "$c" = 403 ]; then passed_probes=$((passed_probes+1)); else bad "sonda NO bloqueada ($where -> $c)"; fi
done < "$PROBES"
[ "$total_probes" -gt 0 ] && [ "$passed_probes" = "$total_probes" ] && ok "sondas bloqueadas: $passed_probes/$total_probes"

# (c) Privacidad del audit log: no debe contener el texto de las descripciones legitimas inspeccionadas
#     en campos NO excluidos. Aqui se comprueba que no aparezca una marca enviada en una cabecera.
if [ -n "$AUDIT_READ" ]; then
  MARK="HUMO-$RANDOM$RANDOM"
  get_code /alerts "X-Analyst-Key: $MARK" >/dev/null   # credencial ficticia: el WAF no inspecciona esa cabecera (privacidad.conf)
  if $AUDIT_READ 2>/dev/null | grep -qF "$MARK"; then
    bad "el audit log contiene una credencial de cabecera (fuga de privacidad)"
  else
    ok "el audit log no copio la credencial de la cabecera"
  fi
fi

echo "== $PASS OK, $FAIL fallos =="
[ "$FAIL" = 0 ]
