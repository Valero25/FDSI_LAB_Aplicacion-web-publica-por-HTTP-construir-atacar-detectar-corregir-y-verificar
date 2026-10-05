"""MuvAutomation - Falcon Incident Lab API.

Prototipo del Lab 3 (Secure Product Challenge): recibe alertas ficticias de
CrowdStrike Falcon, las clasifica/enriquece, escala las criticas y registra las
acciones de los analistas.

Parte 1 (Entrega 1): HTTP sin autenticacion ni cifrado, a proposito.
Parte 2 (Entrega 2): el cifrado lo hace Nginx (TLS); aqui se agregan:
- API key del emisor en POST /alerts y claves de analista con rol (lector /
  respondedor) para consultar y actuar sobre alertas;
- validacion estricta de entrada; docs/OpenAPI desactivados;
- Motor de Clasificacion y Enriquecimiento (MITRE ATT&CK + AbuseIPDB) y
  Motor de Escalamiento;
- audit log con actor y resultado de autenticacion.

Ejecutar desde la raiz del repositorio: uvicorn app.main:app
"""
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, IPvAnyAddress

from app import enrichment, escalation

BASE_DIR = Path(__file__).resolve().parent.parent
# En el servidor, systemd define MUV_DATA_DIR / MUV_LOG_DIR (StateDirectory / LogsDirectory)
# para que el codigo de la app quede de solo lectura. Sin ellas se usan las rutas del repo.
DATA_DIR = Path(os.environ.get("MUV_DATA_DIR") or Path(__file__).resolve().parent)
DB_PATH = DATA_DIR / "alerts.db"
LOG_DIR = Path(os.environ.get("MUV_LOG_DIR") or BASE_DIR / "logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Topes contra agotamiento de disco (una clave de emisor filtrada no puede llenar el servidor).
MAX_ALERTS = int(os.environ.get("MUV_MAX_ALERTS", "50000"))
MAX_ACTIONS_PER_ALERT = 200

action_logger = logging.getLogger("actions")
action_logger.setLevel(logging.INFO)
if not action_logger.handlers:
    _handler = logging.FileHandler(LOG_DIR / "actions.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    action_logger.addHandler(_handler)

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["new", "classified", "escalated", "acknowledged", "closed"]
ActionName = Literal["acknowledge", "comment", "escalate", "close"]

AlertId = Annotated[str, PathParam(pattern=r"^[0-9a-fA-F-]{36}$")]

ROLE_ACTIONS: dict[str, set[str]] = {
    "lector": {"acknowledge", "comment"},
    "respondedor": {"acknowledge", "comment", "escalate", "close"},
}
ACTION_STATUS = {"acknowledge": "acknowledged", "escalate": "escalated", "close": "closed"}

SEED_ALERTS = [
    {
        "severity": "high",
        "tactic": "Initial Access",
        "technique": "T1078 - Valid Accounts",
        "hostname": "WEB-LAB-01",
        "description": "Inicio de sesion desde ubicacion inusual (dato ficticio de laboratorio).",
    },
    {
        "severity": "medium",
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "hostname": "API-LAB-01",
        "description": "Escaneo de puertos detectado contra host de laboratorio (dato ficticio).",
    },
    {
        "severity": "critical",
        "tactic": "Exfiltration",
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "hostname": "DB-LAB-01",
        "description": "Transferencia de datos anomala hacia destino externo (dato ficticio).",
    },
]

# --- Identidades ---------------------------------------------------------------
# Todas se leen del entorno (EnvironmentFile de systemd), nunca del repositorio.
# Si no estan definidas, los endpoints protegidos rechazan todo (fail closed).


@dataclass(frozen=True)
class Analyst:
    name: str
    role: str


def usable_secret(value: str) -> bool:
    # Rechaza claves cortas y los valores de ejemplo de deploy/muvautomation.env.example.
    return len(value) >= 16 and not value.startswith("CAMBIAR")


def load_analysts(raw: str) -> dict[str, Analyst]:
    """MUV_ANALYSTS='ana:respondedor:<clave>;juan:lector:<clave>' -> {clave: Analyst}."""
    analysts = {}
    for entry in filter(None, (e.strip() for e in raw.split(";"))):
        name, role, key = entry.split(":", 2)
        if role not in ROLE_ACTIONS or not usable_secret(key):
            raise ValueError(f"MUV_ANALYSTS: entrada invalida para '{name}'")
        if key in analysts:
            # Una misma clave para dos analistas anularia la atribucion y los roles.
            raise ValueError(f"MUV_ANALYSTS: clave repetida para '{name}'")
        analysts[key] = Analyst(name=name, role=role)
    return analysts


API_KEY = os.environ.get("MUV_API_KEY", "")
if not usable_secret(API_KEY):
    API_KEY = ""
ANALYSTS = load_analysts(os.environ.get("MUV_ANALYSTS", ""))
if API_KEY in ANALYSTS:
    raise ValueError("MUV_API_KEY no puede coincidir con la clave de un analista")

# --- Base de datos -------------------------------------------------------------

NEW_COLUMNS = {
    "source_ip": "TEXT",
    "risk_score": "INTEGER",
    "classification": "TEXT",
    "enrichment": "TEXT",
    "updated_at": "TEXT",
}


def connect() -> sqlite3.Connection:
    # timeout = busy_timeout: las escrituras concurrentes esperan en vez de fallar con "database is locked".
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")  # los lectores no bloquean al escritor
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                tactic TEXT NOT NULL,
                technique TEXT NOT NULL,
                hostname TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        # Migracion de la DB de la Parte 1 (ya desplegada) sin perder datos.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        for column, sql_type in NEW_COLUMNS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {sql_type}")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL REFERENCES alerts(id),
                created_at TEXT NOT NULL,
                analyst TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                note TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if count == 0:
            for seed in SEED_ALERTS:
                conn.execute(
                    "INSERT INTO alerts (id, created_at, severity, tactic, technique, "
                    "hostname, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        datetime.now(timezone.utc).isoformat(),
                        seed["severity"],
                        seed["tactic"],
                        seed["technique"],
                        seed["hostname"],
                        seed["description"],
                        "new",
                    ),
                )
        conn.commit()
    try:
        os.chmod(DB_PATH, 0o600)  # solo el usuario del servicio (no-op en Windows)
    except OSError:
        pass


@contextmanager
def get_db():
    conn = connect()
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def row_to_alert(row: sqlite3.Row) -> dict:
    alert = dict(row)
    alert["enrichment"] = json.loads(alert["enrichment"]) if alert.get("enrichment") else None
    return alert


# --- Modelos -------------------------------------------------------------------


class AlertIn(BaseModel):
    model_config = {"extra": "forbid"}

    severity: Severity
    tactic: str = Field(..., min_length=1, max_length=64, examples=["Initial Access"])
    technique: str = Field(..., min_length=1, max_length=128, examples=["T1078 - Valid Accounts"])
    hostname: str = Field(
        ..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$", examples=["WEB-LAB-01"]
    )
    description: str = Field(..., min_length=1, max_length=1000)
    source_ip: Optional[IPvAnyAddress] = None


class AlertOut(BaseModel):
    id: str
    created_at: str
    status: str
    severity: str
    tactic: str
    technique: str
    hostname: str
    description: str
    source_ip: Optional[str] = None
    risk_score: Optional[int] = None
    classification: Optional[str] = None
    enrichment: Optional[dict] = None
    updated_at: Optional[str] = None


class ActionIn(BaseModel):
    model_config = {"extra": "forbid"}

    action: ActionName
    note: str = Field(default="", max_length=500)


class ActionOut(BaseModel):
    alert_id: str
    created_at: str
    analyst: str
    role: str
    action: str
    note: str


class AlertDetail(AlertOut):
    actions: list[ActionOut]


app = FastAPI(
    title="MuvAutomation - Falcon Incident Lab API",
    description="Prototipo de laboratorio. Datos ficticios.",
    version="0.3.0",
    # Sin /docs, /redoc ni /openapi.json: no se publica el mapa de la API.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# --- Registro de acciones (audit log) --------------------------------------------


def write_log(action: str, **fields) -> None:
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, **fields}
    action_logger.info(json.dumps(entry, ensure_ascii=False))


def log_action(
    request: Request,
    action: str,
    alert_id: Optional[str] = None,
    actor: Optional[str] = None,
    result: str = "ok",
) -> None:
    write_log(
        action,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else None,
        alert_id=alert_id,
        actor=actor,
        result=result,
    )


# --- Autenticacion / autorizacion ---------------------------------------------


# Anti fuerza bruta: tras MAX_AUTH_FAILURES claves invalidas en AUTH_WINDOW_S desde una
# misma IP, esa IP recibe 429 durante AUTH_WINDOW_S aunque presente una clave valida.
# Estado en memoria (un solo worker de uvicorn); Nginx aporta el limite por tasa.
MAX_AUTH_FAILURES = 5
AUTH_WINDOW_S = 300
_auth_failures: dict[str, list[float]] = {}
_auth_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_not_locked(request: Request, action: str) -> None:
    ip, now = _client_ip(request), time.monotonic()
    with _auth_lock:
        recent = [t for t in _auth_failures.get(ip, []) if now - t < AUTH_WINDOW_S]
        if recent:
            _auth_failures[ip] = recent
        else:
            _auth_failures.pop(ip, None)
        locked = len(recent) >= MAX_AUTH_FAILURES
    if locked:
        log_action(request, action, result="locked_out")
        raise HTTPException(
            status_code=429, detail="Too many failed attempts", headers={"Retry-After": str(AUTH_WINDOW_S)}
        )


def _register_failure(request: Request) -> None:
    ip = _client_ip(request)
    with _auth_lock:
        if ip not in _auth_failures and len(_auth_failures) >= 10_000:
            # Tope de memoria: se descarta la IP mas antigua, sin borrar los bloqueos activos del resto.
            _auth_failures.pop(next(iter(_auth_failures)))
        _auth_failures.setdefault(ip, []).append(time.monotonic())


def require_api_key(
    request: Request, x_api_key: Optional[str] = Header(default=None, max_length=256)
) -> None:
    _check_not_locked(request, "create_alert_locked_out")
    if not API_KEY or x_api_key is None or not secrets.compare_digest(
        x_api_key.encode(), API_KEY.encode()
    ):
        _register_failure(request)
        log_action(request, "create_alert_unauthorized", result="unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_analyst(
    request: Request, x_analyst_key: Optional[str] = Header(default=None, max_length=256)
) -> Analyst:
    _check_not_locked(request, "analyst_locked_out")
    if x_analyst_key is not None:
        # Se recorren todas las claves sin cortar antes: tiempo constante respecto a cual acierta.
        found = None
        for key, analyst in ANALYSTS.items():
            if secrets.compare_digest(x_analyst_key.encode(), key.encode()):
                found = analyst
        if found:
            return found
    _register_failure(request)
    log_action(request, "analyst_unauthorized", result="unauthorized")
    raise HTTPException(status_code=401, detail="Invalid or missing analyst key")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Defensa en profundidad: aunque Nginx se omita, la app no sirve respuestas cacheables
    # ni embebibles. Las respuestas contienen datos de alertas: nunca deben cachearse.
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# --- Motores (clasificacion + escalamiento) -----------------------------------


def process_alert(alert_id: str) -> None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            return
        alert = row_to_alert(row)
        score, classification, enriched = enrichment.classify(alert)
        status = "escalated" if escalation.should_escalate(score) else "classified"
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE alerts SET risk_score = ?, classification = ?, enrichment = ?, "
            "status = ?, updated_at = ? WHERE id = ?",
            (score, classification, json.dumps(enriched, ensure_ascii=False), status, now, alert_id),
        )
        conn.commit()
    alert.update(risk_score=score, classification=classification)
    write_log(
        "alert_classified",
        alert_id=alert_id,
        actor="system:motor-clasificacion",
        result=f"{classification} ({score})",
    )
    if status == "escalated":
        escalation.notify(alert, reason=f"auto: risk_score {score} >= {escalation.threshold()}")
        write_log("alert_escalated", alert_id=alert_id, actor="system:motor-escalamiento", result="auto")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    with get_db() as conn:
        pending = conn.execute("SELECT id FROM alerts WHERE risk_score IS NULL").fetchall()
    for row in pending:
        process_alert(row["id"])


# --- Endpoints -----------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    log_action(request, "view_root")
    return """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>MuvAutomation Falcon Lab</title></head>
<body>
  <h1>MuvAutomation - Falcon Incident Automation (LAB)</h1>
  <p>Environment: LAB</p>
  <p>Owner: Blue Team</p>
  <p>Datos ficticios. Acceso restringido: requiere credenciales de emisor o de analista.</p>
</body>
</html>"""


@app.post(
    "/alerts",
    response_model=AlertOut,
    status_code=201,
    dependencies=[Depends(require_api_key)],
)
def create_alert(alert: AlertIn, request: Request, background_tasks: BackgroundTasks):
    alert_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    source_ip = str(alert.source_ip) if alert.source_ip else None
    with get_db() as conn:
        if conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] >= MAX_ALERTS:
            log_action(request, "create_alert_quota", actor="emisor:falcon-api-key", result="quota_exceeded")
            raise HTTPException(status_code=507, detail="Alert storage quota reached")
        conn.execute(
            "INSERT INTO alerts (id, created_at, severity, tactic, technique, "
            "hostname, description, status, source_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert_id,
                created_at,
                alert.severity,
                alert.tactic,
                alert.technique,
                alert.hostname,
                alert.description,
                "new",
                source_ip,
            ),
        )
        conn.commit()
    log_action(request, "create_alert", alert_id, actor="emisor:falcon-api-key")
    # La clasificacion (que puede consultar AbuseIPDB) corre despues de responder:
    # una API externa lenta o caida nunca bloquea la ingesta.
    background_tasks.add_task(process_alert, alert_id)
    return AlertOut(
        id=alert_id,
        created_at=created_at,
        status="new",
        source_ip=source_ip,
        **alert.model_dump(exclude={"source_ip"}),
    )


@app.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    request: Request,
    analyst: Analyst = Depends(require_analyst),
    severity: Optional[Severity] = None,
    status: Optional[Status] = None,
    min_score: Optional[int] = Query(default=None, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=200),
):
    sql, params = "SELECT * FROM alerts WHERE 1=1", []
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if min_score is not None:
        sql += " AND risk_score >= ?"
        params.append(min_score)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
    log_action(request, "list_alerts", actor=f"analyst:{analyst.name}")
    return [AlertOut(**row_to_alert(row)) for row in rows]


@app.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: AlertId, request: Request, analyst: Analyst = Depends(require_analyst)):
    actor = f"analyst:{analyst.name}"
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        actions = conn.execute(
            "SELECT alert_id, created_at, analyst, role, action, note FROM alert_actions "
            "WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
    if row is None:
        log_action(request, "get_alert_not_found", alert_id, actor=actor, result="not_found")
        raise HTTPException(status_code=404, detail="Alert not found")
    log_action(request, "get_alert", alert_id, actor=actor)
    return AlertDetail(**row_to_alert(row), actions=[ActionOut(**dict(a)) for a in actions])


@app.post("/alerts/{alert_id}/actions", response_model=ActionOut, status_code=201)
def register_action(
    alert_id: AlertId,
    body: ActionIn,
    request: Request,
    analyst: Analyst = Depends(require_analyst),
):
    actor = f"analyst:{analyst.name}"
    if body.action not in ROLE_ACTIONS[analyst.role]:
        log_action(request, f"action_{body.action}_forbidden", alert_id, actor=actor, result="forbidden")
        raise HTTPException(status_code=403, detail="Role not allowed to perform this action")

    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            log_action(request, f"action_{body.action}", alert_id, actor=actor, result="not_found")
            raise HTTPException(status_code=404, detail="Alert not found")
        if row["status"] == "closed" and body.action != "comment":
            log_action(request, f"action_{body.action}", alert_id, actor=actor, result="conflict")
            raise HTTPException(status_code=409, detail="Alert is closed")
        n_actions = conn.execute(
            "SELECT COUNT(*) FROM alert_actions WHERE alert_id = ?", (alert_id,)
        ).fetchone()[0]
        if n_actions >= MAX_ACTIONS_PER_ALERT:
            log_action(request, f"action_{body.action}", alert_id, actor=actor, result="quota_exceeded")
            raise HTTPException(status_code=409, detail="Action limit reached for this alert")
        conn.execute(
            "INSERT INTO alert_actions (alert_id, created_at, analyst, role, action, note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (alert_id, now, analyst.name, analyst.role, body.action, body.note),
        )
        # Un acknowledge no puede degradar una alerta ya escalada (la escalacion
        # solo termina con close, que exige rol respondedor).
        downgrade = body.action == "acknowledge" and row["status"] == "escalated"
        if body.action in ACTION_STATUS and not downgrade:
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                (ACTION_STATUS[body.action], now, alert_id),
            )
        conn.commit()
    if body.action == "escalate":
        escalation.notify(row_to_alert(row), reason=f"manual: {actor} ({analyst.role})")
    log_action(request, f"action_{body.action}", alert_id, actor=actor)
    return ActionOut(
        alert_id=alert_id,
        created_at=now,
        analyst=analyst.name,
        role=analyst.role,
        action=body.action,
        note=body.note,
    )
