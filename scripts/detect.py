"""Deteccion reproducible sobre el access.log de Nginx (Lab 3, Paso 13).

Reglas (ventana deslizante, por IP de origen):
- R1 enumeracion:  >= UMBRAL respuestas 404 en la ventana (por defecto 5 en 300 s).
- R2 fuerza bruta: >= UMBRAL respuestas 401 o 429 en la ventana.
- R3 abuso de privilegios: >= UMBRAL respuestas 403 en la ventana (un lector que intenta
  escalate/close, o metodos HTTP no permitidos por Nginx).
- R4 escaneo de puertos: >= UFW_UMBRAL conexiones bloqueadas por ufw ([UFW BLOCK]) desde una
  misma IP en la ventana (por defecto 5 en 300 s). Es la capa HOST: ve lo que Nginx no ve.

Uso:
    python scripts/detect.py /var/log/nginx/access.log [--ufw-log /var/log/ufw.log]
                             [--threshold 5] [--ufw-threshold 5] [--state-file F] [--window 300] [--json]
Codigo de salida: 0 sin senales, 2 con al menos una senal (util para cron/CI).
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

RULES = {
    "R1-enumeracion-404": {404},
    "R2-fuerza-bruta-401-429": {401, 429},
    "R3-abuso-privilegios-403": {403},
    "R4-escaneo-ufw-block": {UFW_BLOCK},
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
        if not m["in"]:
            # IN= vacio: paquete SALIENTE bloqueado por "deny outgoing" (el propio servidor);
            # no es un escaneo contra el servidor.
            continue
        try:
            ipaddress.ip_address(m["src"])
        except ValueError:
            continue
        ts = _ufw_timestamp(m["ts"])
        if ts is None:
            continue
        yield m["src"], ts, UFW_BLOCK, f"{m['proto']}/{m['dpt'] or '-'}", None


def detect(events, threshold: int = 5, window_s: int = 300, ufw_threshold: int = 5) -> list[dict]:
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
        for end in range(len(hits)):
            while (hits[end][0] - hits[start][0]).total_seconds() > window_s:
                start += 1
            if end - start + 1 > best[0]:
                best = (end - start + 1, start)
        count, first = best
        limit = ufw_threshold if rule.startswith("R4") else threshold
        if count >= limit:
            window = hits[first : first + count]
            signals.append(
                {
                    "rule": rule,
                    "ip": ip,
                    "count": count,
                    "first_seen": window[0][0].isoformat(),
                    "last_seen": window[-1][0].isoformat(),
                    "sample_requests": sorted({r for _, r, _ in window})[:3],
                    # Para buscar el mismo evento en actions.log (campo request_id).
                    "request_ids": sorted({rid for _, _, rid in window if rid})[:3],
                }
            )
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
    state = load_state(args.state_file) if args.state_file else {}
    if state:
        events = list(drop_reported(events, state))
    signals = detect(events, args.threshold, args.window, args.ufw_threshold)
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
                f"{s['first_seen']} -> {s['last_seen']} ej={s['sample_requests']}"
                + (f" request_id={s['request_ids']}" if s["request_ids"] else "")
            )
    if not signals:
        print("Sin senales con el umbral configurado.")
    return 2 if signals else 0


if __name__ == "__main__":
    sys.exit(main())
