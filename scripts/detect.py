"""Deteccion reproducible sobre el access.log de Nginx (Lab 3, Paso 13).

Reglas (ventana deslizante, por IP de origen):
- R1 enumeracion:  >= UMBRAL respuestas 404 en la ventana (por defecto 5 en 300 s).
- R2 fuerza bruta: >= UMBRAL respuestas 401 o 429 en la ventana. Incluye los 429 del limite de Nginx
  (limit_req/limit_conn): cada rechazo queda en access.log con estado 429. Las lineas "limiting
  requests ... zone" de error.log son el MISMO evento (solo anaden la zona), por eso no se cuentan:
  duplicarian R2. error.log sirve para la investigacion (que zona: muv_api o muv_auth).
- R3 abuso de privilegios: >= UMBRAL respuestas 403 en la ventana (un lector que intenta
  escalate/close, o metodos HTTP no permitidos por Nginx).
- R4 escaneo de puertos: >= UFW_UMBRAL conexiones bloqueadas por ufw ([UFW BLOCK]) desde una
  misma IP en la ventana (por defecto 5 en 300 s). Es la capa HOST: ve lo que Nginx no ve.

- R5 salida bloqueada: >= UFW_UMBRAL paquetes SALIENTES del propio servidor bloqueados por ufw
  ("deny outgoing") en la ventana. Indica que algo del servidor intenta conectarse a un destino
  no permitido (software mal configurado o, en el peor caso, un proceso comprometido).

- R6 punteria contra una cuenta: >= CUENTA_UMBRAL inicios de sesion fallidos (`login_failed` en
  actions.log) contra una MISMA cuenta en una ventana larga (por defecto 10 en 3600 s), vengan de
  una o de muchas IP. Cubre el ataque lento o distribuido que ni el bloqueo por IP ni la espera
  por (cuenta, IP) frenan. Solo alerta: no bloquea la cuenta (bloquearla permitiria dejar fuera
  al titular). En la senal, el campo `ip` lleva la cuenta (`login:<usuario>`).

- R7 WAF: >= WAF_UMBRAL peticiones de una misma IP con al menos una regla de ModSecurity/CRS
  coincidente (audit log JSON) en la ventana. El campo `blocked` cuenta cuantas alcanzaron el umbral
  de bloqueo (regla 949110/959100): en modo bloqueo son 403, en DetectionOnly se habrian bloqueado.
  La senal solo lleva IDs de regla, la ruta (sin query string) y la IP: nunca el texto de la
  coincidencia ni datos de la peticion.
  Nota R3/R7: en modo bloqueo el WAF responde 403, asi que esas peticiones tambien las cuenta R3
  (>=5 respuestas 403 en access.log). Es deliberado: R3 funciona solo con access.log (aunque falte
  el audit log del WAF o este apagado) y R7 anade el detalle del WAF (que reglas, bloqueado o no).
  El access.log no distingue un 403 del WAF de uno de limit_except o de la app, por eso no se separan.

Uso:
    python scripts/detect.py /var/log/nginx/access.log [--ufw-log /var/log/ufw.log]
                             [--audit-log /var/log/muvautomation/actions.log]
                             [--threshold 5] [--ufw-threshold 5] [--state-file F] [--window 300]
                             [--account-threshold 10] [--account-window 3600]
                             [--waf-log /var/log/modsecurity/audit.json] [--waf-threshold 5] [--json]
Codigo de salida: 0 sin senales, 10 con al menos una senal (2 queda para errores de uso).
Requiere `sudo ufw logging medium` para que R4 tenga datos.

Correlacion: el access.log de Nginx (log_format muv_combined) termina en rid=<request_id>; la
app registra el mismo valor en actions.log (campo request_id). Las senales R1-R3 listan
algunos request_id de muestra para buscarlos en ambos logs.

Limitaciones y falsos positivos (documentar en el informe):
- NAT / proxy: varios usuarios detras de una IP suman sus errores (falso positivo).
- Un escaner lento (menos de UMBRAL por ventana) o distribuido entre IPs no se detecta (falso negativo).
- Un enlace roto en el sitio legitimo genera 404 repetidos que no son un ataque.
- Un SYN scan de Nmap no llega a Nginx: no aparece en access.log (R4 lo cubre con ufw.log).
- R4: ufw solo bloquea lo que no tiene regla allow; un escaneo desde el CIDR permitido a los
  puertos 22/80/443 no genera bloqueos. El ruido de multicast/broadcast se descarta, pero un
  servicio legitimo que insista en un puerto cerrado (monitoreo mal configurado) la dispara.
- Un escaneo lento o distribuido entre IPs sigue sin detectarse.
"""
import argparse
import json
import os
import re
import sys
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone

# Formato "combined" de Nginx: IP - user [fecha] "METODO ruta PROTO" status bytes "ref" "UA"
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) \S+'
    r'(?:.*? rid=(?P<rid>[0-9a-f]{32}))?'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# ufw.log (Ubuntu): "2026-10-11T12:00:00.123456+00:00 host kernel: [..] [UFW BLOCK] IN=... SRC=1.2.3.4 ..."
# o, con syslog clasico, "Oct 11 12:00:00 host kernel: ...". La linea es texto del kernel: solo
# se aceptan campos con forma de IP y de puerto.
UFW_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+(?:[+-]\d\d:\d\d|Z)|[A-Z][a-z]{2}\s+\d+ \d\d:\d\d:\d\d)\s.*"
    r"\[UFW BLOCK\]\s+IN=(?P<in>\S*)\s+OUT=(?P<out>\S*).*?\bSRC=(?P<src>[0-9a-fA-F:.]+)\s+DST=(?P<dst>[0-9a-fA-F:.]+).*?"
    r"\bPROTO=(?P<proto>[A-Z0-9]+)(?:.*?\bDPT=(?P<dpt>\d{1,5}))?"
)
UFW_BLOCK = 1000  # pseudo-status: los bloqueos de ufw no tienen codigo HTTP
UFW_OUT_BLOCK = 1001  # bloqueo de un paquete que SALE del servidor
LOGIN_FAILED = 1002  # inicio de sesion fallido (actions.log)
WAF_EVENT = 1003  # peticion con al menos una regla de ModSecurity/CRS coincidente
RULE_ID_RE = re.compile(r"^\d{1,7}$")
RID_RE = re.compile(r"^[0-9a-f]{32}$")
# CRS deniega cuando el puntaje de anomalia supera el umbral: 949110 (entrada) y 959100 (salida). Su
# presencia marca que la transaccion alcanzo el umbral de bloqueo: en modo On se bloqueo (403); en
# DetectionOnly se habria bloqueado. El resto de eventos solo coincidio con alguna regla (detectado).
WAF_BLOCKING_RULE_IDS = {"949110", "959100"}

RULES = {
    "R1-enumeracion-404": {404},
    "R2-fuerza-bruta-401-429": {401, 429},
    "R3-abuso-privilegios-403": {403},
    "R4-escaneo-ufw-block": {UFW_BLOCK},
    "R5-salida-bloqueada-ufw": {UFW_OUT_BLOCK},
    "R6-punteria-contra-cuenta": {LOGIN_FAILED},
    "R7-waf-crs": {WAF_EVENT},
}


def parse(lines):
    """Devuelve (ip, datetime, status, request) por cada linea valida; ignora el resto."""
    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], TS_FORMAT)
        except ValueError:
            continue
        yield m["ip"], ts, int(m["status"]), m["req"], m["rid"]


def _ufw_timestamp(raw: str):
    try:
        if raw[0].isdigit():
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:  # syslog clasico: sin anio; se asume el actual y UTC
            now = datetime.now(timezone.utc)
            ts = datetime.strptime(f"{now.year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_noise(dst: str) -> bool:
    """Multicast y broadcast bloqueados por ufw no son un escaneo."""
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return True
    return ip.is_multicast or (ip.version == 4 and (dst.endswith(".255") or dst == "255.255.255.255"))


def parse_ufw(lines):
    """Devuelve (ip, datetime, UFW_BLOCK, "PROTO/puerto", None) por cada bloqueo valido."""
    for line in lines:
        m = UFW_RE.match(line)
        if not m or _is_noise(m["dst"]):
            continue
        outbound = not m["in"]  # IN= vacio: paquete SALIENTE bloqueado por "deny outgoing"
        if outbound and not m["out"]:
            continue
        try:
            ipaddress.ip_address(m["src"])
        except ValueError:
            continue
        ts = _ufw_timestamp(m["ts"])
        if ts is None:
            continue
        if outbound:  # no es un escaneo contra el servidor: es R5, con el destino como evidencia
            yield m["src"], ts, UFW_OUT_BLOCK, f"{m['proto']}/{m['dpt'] or '-'}->{m['dst']}", None
        else:
            yield m["src"], ts, UFW_BLOCK, f"{m['proto']}/{m['dpt'] or '-'}", None


def parse_audit(lines):
    """Devuelve (cuenta, datetime, LOGIN_FAILED, "ip", None) por cada `login_failed` del audit log."""
    for line in lines:
        try:
            entry = json.loads(line)
            if entry.get("action") != "login_failed":
                continue
            actor = str(entry.get("actor") or "")
            if not actor.startswith("login:"):
                continue
            ts = datetime.fromisoformat(entry["timestamp"])
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        yield actor[:80], ts, LOGIN_FAILED, str(entry.get("client_ip") or "-")[:64], None


def _waf_path(uri) -> str:
    """Solo la ruta, sin query string, acotada y con caracteres imprimibles: nada mas de la peticion."""
    path = str(uri or "-").split("?", 1)[0][:100]
    return "".join(c if 33 <= ord(c) < 127 else "?" for c in path) or "-"


def _waf_rule_ids(messages) -> list[str]:
    """IDs de regla (solo digitos) de los mensajes; se descarta el resto del mensaje (match, data)."""
    ids = set()
    for m in messages if isinstance(messages, list) else []:
        details = m.get("details") if isinstance(m, dict) else None
        rule_id = str(details.get("ruleId", "")) if isinstance(details, dict) else ""
        if RULE_ID_RE.match(rule_id):
            ids.add(rule_id)
    return sorted(ids, key=int)


BLOCKED_TAG = "bloqueado"  # marca de un bloqueo registrado solo por estado (CRS marca sus reglas noauditlog)


def parse_waf(lines):
    """Devuelve (ip, datetime, WAF_EVENT, "ruta [ids]", request_id) por cada transaccion del audit log
    JSON de libmodsecurity que sea un evento del WAF: con reglas coincidentes (modo deteccion) o un
    bloqueo registrado por estado 403 (modo bloqueo; CRS marca sus reglas noauditlog, el detalle de la
    regla queda en error.log, correlacionable por rid). Las transacciones sin reglas ni 403 (p. ej. un
    5xx) se ignoran."""
    for line in lines:
        try:
            tx = json.loads(line)["transaction"]
            ip = str(ipaddress.ip_address(tx["client_ip"]))
            # time_stamp sin zona ("Wed Oct 14 12:00:00 2026"): es la hora local del servidor.
            ts = datetime.strptime(" ".join(str(tx["time_stamp"]).split()), "%a %b %d %H:%M:%S %Y").astimezone()
            ids = _waf_rule_ids(tx.get("messages"))
            request = tx.get("request") if isinstance(tx.get("request"), dict) else {}
            uri = request.get("uri")
            http_code = (tx.get("response") or {}).get("http_code") if isinstance(tx.get("response"), dict) else None
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        blocked = http_code == 403 or bool(set(ids) & WAF_BLOCKING_RULE_IDS)
        if not ids and not blocked:
            continue
        rid = str(tx.get("unique_id") or "")
        if ids:
            # La(s) regla(s) de bloqueo se muestran primero para que no queden fuera del recorte a 5.
            shown = [i for i in ids if i in WAF_BLOCKING_RULE_IDS] + [i for i in ids if i not in WAF_BLOCKING_RULE_IDS]
            tag = ",".join(shown[:5])
            if blocked and not set(ids) & WAF_BLOCKING_RULE_IDS:
                tag += f",{BLOCKED_TAG}"  # bloqueo por estado con reglas detectadas pero sin la de umbral
        else:
            tag = BLOCKED_TAG  # bloqueo sin reglas en el audit (los IDs estan en error.log, por rid)
        yield ip, ts, WAF_EVENT, f"{_waf_path(uri)} [{tag}]", rid if RID_RE.match(rid) else None


def _waf_req_blocked(req: str) -> bool:
    """True si la cadena de un evento R7 indica bloqueo: regla 949110/959100 o la marca BLOCKED_TAG."""
    inside = req[req.find("[") + 1 : req.rfind("]")] if "[" in req and "]" in req else ""
    tokens = {i.strip() for i in inside.split(",")}
    return bool(tokens & WAF_BLOCKING_RULE_IDS) or BLOCKED_TAG in tokens


def detect(
    events,
    threshold: int = 5,
    window_s: int = 300,
    ufw_threshold: int = 5,
    account_threshold: int = 10,
    account_window_s: int = 3600,
    waf_threshold: int = 5,
) -> list[dict]:
    """Aplica las reglas; una senal por (regla, IP) con la ventana de mayor concentracion."""
    by_key: dict[tuple[str, str], list[tuple[datetime, str, object]]] = defaultdict(list)
    for ip, ts, status, req, rid in events:
        for rule, statuses in RULES.items():
            if status in statuses:
                by_key[(rule, ip)].append((ts, req, rid))

    signals = []
    for (rule, ip), hits in by_key.items():
        hits.sort(key=lambda h: h[0])
        best = (0, 0)  # (cantidad, indice inicial) de la ventana mas densa
        start = 0
        span = account_window_s if rule.startswith("R6") else window_s
        for end in range(len(hits)):
            while (hits[end][0] - hits[start][0]).total_seconds() > span:
                start += 1
            if end - start + 1 > best[0]:
                best = (end - start + 1, start)
        count, first = best
        limit = (
            account_threshold if rule.startswith("R6")
            else ufw_threshold if rule.startswith(("R4", "R5"))
            else waf_threshold if rule.startswith("R7")
            else threshold
        )
        if count >= limit:
            window = hits[first : first + count]
            signal = {
                "rule": rule,
                "ip": ip,
                "count": count,
                "first_seen": window[0][0].isoformat(),
                "last_seen": window[-1][0].isoformat(),
                "sample_requests": sorted({r for _, r, _ in window})[:3],
                # Para buscar el mismo evento en actions.log (campo request_id).
                "request_ids": sorted({rid for _, _, rid in window if rid})[:3],
            }
            if rule.startswith("R7"):
                # Cuantas transacciones de la ventana alcanzaron el umbral de bloqueo del WAF.
                signal["blocked"] = sum(1 for _, r, _ in window if _waf_req_blocked(r))
            signals.append(signal)
    return sorted(signals, key=lambda s: (-s["count"], s["ip"]))


def load_state(path: str) -> dict:
    """Estado {"regla|ip": ISO del ultimo evento ya reportado}; ausente o corrupto = vacio."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        out = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, str):
                datetime.fromisoformat(v)  # descarta valores invalidos
                out[k] = v
        return out
    except (OSError, ValueError, AttributeError):
        return {}


def save_state(path: str, state: dict, now: datetime, keep_days: int = 7) -> None:
    keep = {}
    for k, v in state.items():
        try:
            if (now - datetime.fromisoformat(v)).days < keep_days:
                keep[k] = v
        except (ValueError, TypeError):
            continue
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(keep, fh)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[AVISO] no se pudo guardar el estado en {path}: {exc.strerror}", file=sys.stderr)


def drop_reported(events, state: dict):
    """Quita los eventos ya cubiertos por una senal anterior: la misma alerta no se repite."""
    for ev in events:
        ip, ts, status = ev[0], ev[1], ev[2]
        seen = [state.get(f"{rule}|{ip}") for rule, statuses in RULES.items() if status in statuses]
        if any(v and ts <= datetime.fromisoformat(v) for v in seen):
            continue
        yield ev


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile")
    ap.add_argument("--ufw-log", help="ufw.log (activa R4; requiere `ufw logging medium`)")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--ufw-threshold", type=int, default=5)
    ap.add_argument("--state-file", help="JSON con lo ya reportado: la misma senal no se repite en cada ejecucion")
    ap.add_argument("--window", type=int, default=300, help="segundos")
    ap.add_argument("--audit-log", help="actions.log de la app (activa R6: punteria contra una cuenta)")
    ap.add_argument("--account-threshold", type=int, default=10)
    ap.add_argument("--account-window", type=int, default=3600, help="segundos")
    ap.add_argument("--waf-log", help="audit log JSON de ModSecurity (activa R7)")
    ap.add_argument("--waf-threshold", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    with open(args.logfile, encoding="utf-8", errors="replace") as fh:
        events = list(parse(fh))
    if args.ufw_log:
        try:
            with open(args.ufw_log, encoding="utf-8", errors="replace") as fh:
                events += list(parse_ufw(fh))
        except OSError as exc:  # sin ufw.log solo se pierde R4; R1-R3 siguen funcionando
            print(f"[AVISO] R4 omitida: no se pudo leer {args.ufw_log}: {exc.strerror}", file=sys.stderr)
    if args.audit_log:
        try:
            with open(args.audit_log, encoding="utf-8", errors="replace") as fh:
                events += list(parse_audit(fh))
        except OSError as exc:  # sin audit log solo se pierde R6
            print(f"[AVISO] R6 omitida: no se pudo leer {args.audit_log}: {exc.strerror}", file=sys.stderr)
    if args.waf_log:
        try:
            with open(args.waf_log, encoding="utf-8", errors="replace") as fh:
                events += list(parse_waf(fh))
        except OSError as exc:  # sin audit log del WAF (WAF no instalado) solo se pierde R7
            print(f"[AVISO] R7 omitida: no se pudo leer {args.waf_log}: {exc.strerror}", file=sys.stderr)
    state = load_state(args.state_file) if args.state_file else {}
    if state:
        events = list(drop_reported(events, state))
    signals = detect(
        events, args.threshold, args.window, args.ufw_threshold, args.account_threshold, args.account_window,
        args.waf_threshold,
    )
    if args.state_file and signals:
        for s in signals:
            # Todo lo visto hasta ahora para (regla, IP) queda como reportado.
            state[f"{s['rule']}|{s['ip']}"] = max(
                ev[1] for ev in events if ev[0] == s["ip"] and ev[2] in RULES[s["rule"]]
            ).isoformat()
        save_state(args.state_file, state, datetime.now(timezone.utc))

    for s in signals:
        if args.json:
            print(json.dumps(s, ensure_ascii=False))
        else:
            print(
                f"[SENAL] {s['rule']} ip={s['ip']} eventos={s['count']} "
                + (f"bloqueados={s['blocked']} " if "blocked" in s else "")
                + f"{s['first_seen']} -> {s['last_seen']} ej={s['sample_requests']}"
                + (f" request_id={s['request_ids']}" if s["request_ids"] else "")
            )
    if not signals:
        print("Sin senales con el umbral configurado.")
    return 10 if signals else 0


if __name__ == "__main__":
    sys.exit(main())
