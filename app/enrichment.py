"""Motor de Clasificacion y Enriquecimiento (DFD: proceso P2).

Fuentes:
- MITRE ATT&CK: indice local app/data/mitre_attack_index.json (generado con
  scripts/build_mitre_index.py). Sin trafico de salida por alerta.
- AbuseIPDB (opcional): reputacion de source_ip. Solo si hay ABUSEIPDB_API_KEY,
  solo para IPs publicas, con timeout, cache y presupuesto diario. Si falla, la
  alerta se clasifica igual (fail soft): la integracion externa nunca bloquea la ingesta.
"""
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

MITRE_INDEX_PATH = Path(__file__).resolve().parent / "data" / "mitre_attack_index.json"
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

SEVERITY_BASE = {"low": 10, "medium": 30, "high": 60, "critical": 80}
HIGH_IMPACT_TACTICS = {
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
}

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT_S = 3
ABUSEIPDB_CACHE_TTL_S = 3600
ABUSEIPDB_MAX_BYTES = 64 * 1024
ABUSEIPDB_CACHE_MAX = 5000

_abuse_cache: dict[str, tuple[float, dict]] = {}
_abuse_budget = {"day": "", "used": 0}
_abuse_lock = threading.Lock()


@lru_cache(maxsize=1)
def mitre_index() -> dict:
    return json.loads(MITRE_INDEX_PATH.read_text(encoding="utf-8"))


def mitre_lookup(technique: str, tactic: str) -> dict:
    match = TECHNIQUE_RE.search(technique)
    if not match:
        return {"status": "technique_id_missing"}
    tid = match.group(0)
    index = mitre_index()
    tech = index["techniques"].get(tid)
    if tech is None:
        return {"status": "technique_unknown", "technique_id": tid}
    return {
        "status": "ok",
        "attack_version": index["attack_version"],
        "technique_id": tid,
        "name": tech["name"],
        "tactics": tech["tactics"],
        "tactic_matches": tactic in tech["tactics"],
        "description": tech["description"],
        "mitigations": tech["mitigations"][:5],
        "url": tech["url"],
    }


def _abuse_budget_ok() -> bool:
    limit = int(os.environ.get("ABUSEIPDB_DAILY_LIMIT", "900"))
    today = datetime.now(timezone.utc).date().isoformat()
    with _abuse_lock:
        if _abuse_budget["day"] != today:
            _abuse_budget.update(day=today, used=0)
        if _abuse_budget["used"] >= limit:
            return False
        _abuse_budget["used"] += 1
        return True


def abuseipdb_check(source_ip: Optional[str]) -> dict:
    if not source_ip:
        return {"status": "skipped_no_ip"}
    ip = ipaddress.ip_address(source_ip)
    if not ip.is_global:
        # IPs privadas/reservadas (las del laboratorio) no se envian a terceros.
        return {"status": "skipped_not_public"}
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"status": "skipped_no_key"}

    cached = _abuse_cache.get(str(ip))
    if cached and time.monotonic() - cached[0] < ABUSEIPDB_CACHE_TTL_S:
        return {**cached[1], "cached": True}
    if not _abuse_budget_ok():
        return {"status": "skipped_quota"}

    query = urllib.parse.urlencode({"ipAddress": str(ip), "maxAgeInDays": 90})
    req = urllib.request.Request(
        f"{ABUSEIPDB_URL}?{query}", headers={"Key": api_key, "Accept": "application/json"}
    )
    try:
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=ABUSEIPDB_TIMEOUT_S) as resp:  # nosec B310  # esquema https fijo en la constante de AbuseIPDB
            data = json.loads(resp.read(ABUSEIPDB_MAX_BYTES))["data"]
        score = data["abuseConfidenceScore"]
        reports = data.get("totalReports", 0)
        country = data.get("countryCode")
        # La respuesta externa no es confiable: solo se guardan campos validados.
        if not (isinstance(score, int) and 0 <= score <= 100 and isinstance(reports, int)):
            return {"status": "error", "reason": "invalid_response"}
        if not (isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country)):
            country = None
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError) as exc:
        return {"status": "error", "reason": type(exc).__name__}

    result = {
        "status": "ok",
        "abuse_confidence_score": score,
        "total_reports": reports,
        "country_code": country,
    }
    with _abuse_lock:
        if len(_abuse_cache) >= ABUSEIPDB_CACHE_MAX:
            # Acotada: primero se descartan las expiradas y, si no basta, la mas antigua.
            now = time.monotonic()
            for key in [k for k, (t, _) in _abuse_cache.items() if now - t >= ABUSEIPDB_CACHE_TTL_S]:
                del _abuse_cache[key]
            if len(_abuse_cache) >= ABUSEIPDB_CACHE_MAX:
                _abuse_cache.pop(next(iter(_abuse_cache)))
        _abuse_cache[str(ip)] = (time.monotonic(), result)
    return result


def classify(alert: dict) -> tuple[int, str, dict]:
    """Devuelve (risk_score 0-100, clasificacion, enriquecimiento)."""
    mitre = mitre_lookup(alert["technique"], alert["tactic"])
    abuse = abuseipdb_check(alert.get("source_ip"))

    score = SEVERITY_BASE.get(alert["severity"], 30)
    reasons = [f"severity={alert['severity']} (+{score})"]
    flags = []

    if alert["tactic"] in HIGH_IMPACT_TACTICS:
        score += 10
        reasons.append(f"tactica de alto impacto {alert['tactic']} (+10)")
    if mitre["status"] != "ok":
        flags.append(mitre["status"])
    elif not mitre["tactic_matches"]:
        # La tactica declarada no corresponde a la tecnica: posible alerta mal
        # formada o manipulada. No sube el score, pero queda marcada.
        flags.append("tactic_mismatch")
    if abuse["status"] == "ok":
        bonus = min(20, round(abuse["abuse_confidence_score"] * 0.2))
        if bonus:
            score += bonus
            reasons.append(f"AbuseIPDB score {abuse['abuse_confidence_score']} (+{bonus})")
        if abuse["abuse_confidence_score"] >= 75:
            flags.append("ip_maliciosa")

    score = min(score, 100)
    classification = "alta" if score >= 70 else "media" if score >= 40 else "baja"
    enrichment = {"mitre": mitre, "abuseipdb": abuse, "score_reasons": reasons, "flags": flags}
    return score, classification, enrichment
