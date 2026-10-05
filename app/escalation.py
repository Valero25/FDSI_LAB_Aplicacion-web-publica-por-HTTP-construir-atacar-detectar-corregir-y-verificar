"""Motor de Escalamiento (DFD: proceso P3).

Escala automaticamente las alertas con risk_score >= MUV_ESCALATION_THRESHOLD y
notifica al Analista SOC. En el laboratorio el canal de notificacion es
logs/escalations.log (JSON por linea); en produccion seria correo/Slack/ticket.
El escalamiento manual lo decide main.py segun el rol del analista.
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(os.environ.get("MUV_LOG_DIR") or Path(__file__).resolve().parent.parent / "logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

notify_logger = logging.getLogger("escalations")
notify_logger.setLevel(logging.INFO)
if not notify_logger.handlers:
    _handler = logging.FileHandler(LOG_DIR / "escalations.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    notify_logger.addHandler(_handler)


def threshold() -> int:
    return int(os.environ.get("MUV_ESCALATION_THRESHOLD", "70"))


def should_escalate(risk_score: int) -> bool:
    return risk_score >= threshold()


def notify(alert: dict, reason: str) -> None:
    notify_logger.info(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "alert_escalated",
                "reason": reason,
                "alert_id": alert["id"],
                "severity": alert["severity"],
                "risk_score": alert.get("risk_score"),
                "classification": alert.get("classification"),
                "technique": alert["technique"],
                "hostname": alert["hostname"],
            },
            ensure_ascii=False,
        )
    )
