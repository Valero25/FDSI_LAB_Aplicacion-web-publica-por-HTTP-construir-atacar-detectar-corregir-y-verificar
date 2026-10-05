"""Deteccion reproducible sobre el access.log de Nginx (Lab 3, Paso 13).

Reglas (ventana deslizante, por IP de origen):
- R1 enumeracion:  >= UMBRAL respuestas 404 en la ventana (por defecto 5 en 300 s).
- R2 fuerza bruta: >= UMBRAL respuestas 401 o 429 en la ventana.

Uso:
    python scripts/detect.py /var/log/nginx/access.log [--threshold 5] [--window 300] [--json]
Codigo de salida: 0 sin senales, 2 con al menos una senal (util para cron/CI).

Limitaciones y falsos positivos (documentar en el informe):
- NAT / proxy: varios usuarios detras de una IP suman sus errores (falso positivo).
- Un escaner lento (menos de UMBRAL por ventana) o distribuido entre IPs no se detecta (falso negativo).
- Un enlace roto en el sitio legitimo genera 404 repetidos que no son un ataque.
- Un SYN scan de Nmap no llega a Nginx: no aparece en access.log (se ve en ufw/PCAP).
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# Formato "combined" de Nginx: IP - user [fecha] "METODO ruta PROTO" status bytes "ref" "UA"
LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) \S+'
)
TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

RULES = {
    "R1-enumeracion-404": {404},
    "R2-fuerza-bruta-401-429": {401, 429},
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
        yield m["ip"], ts, int(m["status"]), m["req"]


def detect(events, threshold: int = 5, window_s: int = 300) -> list[dict]:
    """Aplica las reglas; una senal por (regla, IP) con la ventana de mayor concentracion."""
    by_key: dict[tuple[str, str], list[tuple[datetime, str]]] = defaultdict(list)
    for ip, ts, status, req in events:
        for rule, statuses in RULES.items():
            if status in statuses:
                by_key[(rule, ip)].append((ts, req))

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
        if count >= threshold:
            window = hits[first : first + count]
            signals.append(
                {
                    "rule": rule,
                    "ip": ip,
                    "count": count,
                    "first_seen": window[0][0].isoformat(),
                    "last_seen": window[-1][0].isoformat(),
                    "sample_requests": sorted({r for _, r in window})[:3],
                }
            )
    return sorted(signals, key=lambda s: (-s["count"], s["ip"]))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=300, help="segundos")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    with open(args.logfile, encoding="utf-8", errors="replace") as fh:
        signals = detect(parse(fh), args.threshold, args.window)

    for s in signals:
        if args.json:
            print(json.dumps(s, ensure_ascii=False))
        else:
            print(
                f"[SENAL] {s['rule']} ip={s['ip']} eventos={s['count']} "
                f"{s['first_seen']} -> {s['last_seen']} ej={s['sample_requests']}"
            )
    if not signals:
        print("Sin senales con el umbral configurado.")
    return 2 if signals else 0


if __name__ == "__main__":
    sys.exit(main())
