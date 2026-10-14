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
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.routing import APIRoute
from starlette.routing import Match
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

from app import enrichment, escalation, identity, inventory

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
# Tope de ingesta por minuto (global: hay un solo emisor). Una clave de emisor filtrada no puede
# llenar la cuota de MAX_ALERTS en minutos y dejar sin servicio al emisor legitimo.
MAX_INGEST_PER_MIN = int(os.environ.get("MUV_MAX_INGEST_PER_MIN", "300"))
_ingest_times: deque = deque()
_ingest_lock = threading.Lock()

action_logger = logging.getLogger("actions")
action_logger.setLevel(logging.INFO)
if not action_logger.handlers:
    _handler = logging.FileHandler(LOG_DIR / "actions.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    action_logger.addHandler(_handler)

# Texto libre que termina en logs, notificaciones y consolas de analistas: sin caracteres de
# control (secuencias ANSI, NUL, saltos que falsifican lineas) ni de direccion de texto (U+202E
# y similares, "trojan source"). En descripcion y notas se permiten saltos de linea y tabulador.
_BIDI_AND_INVISIBLE = "\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff"
_STRICT_TEXT_FORBIDDEN = re.compile(f"[\\x00-\\x1f\\x7f-\\x9f{_BIDI_AND_INVISIBLE}]")
_MULTILINE_TEXT_FORBIDDEN = re.compile(f"[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f{_BIDI_AND_INVISIBLE}]")


def _clean(value: str, pattern: re.Pattern) -> str:
    if pattern.search(value):
        raise ValueError("caracteres de control o de direccion de texto no permitidos")
    return value


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


# Valores de ejemplo de la documentacion: nunca deben aceptarse en un despliegue real.
EXAMPLE_SECRETS = {
    "clave-emisor-local-123456",
    "clave-ana-local-123456",
    "clave-juan-local-123456",
}


def usable_secret(value: str) -> bool:
    # Rechaza claves cortas, de baja variedad y los valores de ejemplo (env.example y README).
    return (
        len(value) >= 16
        and len(set(value)) >= 8
        and not value.startswith("CAMBIAR")
        and value not in EXAMPLE_SECRETS
    )


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
        identity.init_schema(conn)
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

    @field_validator("tactic", "technique", "hostname")
    @classmethod
    def _strict(cls, v: str) -> str:
        return _clean(v, _STRICT_TEXT_FORBIDDEN)

    @field_validator("description")
    @classmethod
    def _multiline(cls, v: str) -> str:
        return _clean(v, _MULTILINE_TEXT_FORBIDDEN)


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

    @field_validator("note")
    @classmethod
    def _multiline(cls, v: str) -> str:
        return _clean(v, _MULTILINE_TEXT_FORBIDDEN)


class ActionOut(BaseModel):
    alert_id: str
    created_at: str
    analyst: str
    role: str
    action: str
    note: str


class AlertDetail(AlertOut):
    actions: list[ActionOut]


class NetworkDevice(BaseModel):
    id: str
    hostname: str
    type: Literal["firewall", "router", "switch"]
    vendor: str
    model: str
    location: str
    zone: str
    mgmt_ip: Optional[str] = None  # solo se entrega al rol respondedor
    criticality: Literal["low", "medium", "high"]
    owner: str
    status: str


DeviceId = Annotated[str, PathParam(pattern=r"^[A-Z0-9-]{3,32}$")]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _on_startup()  # el cierre no necesita limpieza: el hilo de reprocesado es daemon
    yield


app = FastAPI(
    lifespan=lifespan,
    title="MuvAutomation - Falcon Incident Lab API",
    description="Prototipo de laboratorio. Datos ficticios.",
    version="0.3.0",
    # Sin /docs, /redoc ni /openapi.json: no se publica el mapa de la API.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    # /alerts/ -> 404 en vez de un 307 cuyo Location se construye con el header Host del cliente.
    redirect_slashes=False,
)



@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # El 422 por defecto de FastAPI devuelve el valor enviado ("input"): una clave casi correcta o
    # un dato sensible quedaria reflejado. Solo se informa donde y por que falla.
    errors = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
    # FastAPI analiza el cuerpo ANTES de ejecutar las dependencias de autenticacion: un JSON roto
    # llegaria aqui sin credencial. Un anonimo no debe obtener un 422 ni escribir en el audit log:
    # se trata como cualquier otro intento sin credencial valida (401, mismo contador y bloqueo).
    scope = _auth_scope(request)
    if scope is not None:
        actor = _authenticate_or_reject(request, scope)
        if isinstance(actor, JSONResponse):
            return actor
    else:
        actor = None
    # Rastro de auditoria: ruta, IP, request_id, actor y QUE campos fallaron (loc/type). Nunca el
    # valor enviado. loc puede contener nombres de campo elegidos por el cliente: se acotan.
    failed = [
        {"loc": [str(part)[:64] for part in e["loc"][:6]], "type": str(e["type"])[:64]} for e in errors[:10]
    ]
    write_log(
        "validation_error",
        method=request.method,
        path=request.url.path[:256],
        client_ip=request.client.host if request.client else None,
        actor=actor,
        result="validation_error",
        request_id=getattr(request.state, "request_id", None),
        errors=failed,
    )
    return JSONResponse(status_code=422, content={"detail": errors})


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
        path=request.url.path[:256],  # un URL de 8 KB repetido no debe inflar el log
        client_ip=request.client.host if request.client else None,
        alert_id=alert_id,
        actor=actor,
        result=result,
        # Mismo valor que Nginx registra como rid=<...> en access.log: correlacion exacta.
        request_id=getattr(request.state, "request_id", None),
    )


# --- Autenticacion / autorizacion ---------------------------------------------


# Anti fuerza bruta: tras MAX_AUTH_FAILURES credenciales invalidas en AUTH_WINDOW_S desde una
# misma IP, esa IP recibe 429 durante AUTH_WINDOW_S aunque presente una credencial valida.
# El estado vive en SQLite (tabla auth_failures): sobrevive a un reinicio de la aplicacion.
MAX_AUTH_FAILURES = 5
AUTH_WINDOW_S = 300
AUTH_FAILURES_MAX_ROWS = 10_000

# Interruptor de las claves estaticas de analista (X-Analyst-Key). Con "no" solo se aceptan tokens
# de identidad (Authorization: Bearer). La clave del emisor (maquina) no se ve afectada.
ALLOW_STATIC_ANALYST_KEYS = os.environ.get("MUV_ALLOW_ANALYST_STATIC_KEYS", "yes").strip().lower() in (
    "1",
    "true",
    "yes",
    "si",
)


def _client_ip(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        # Un atacante IPv6 suele controlar un /64 completo: se agrupa por prefijo.
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return host


def _lock_key(request: Request, scope: str) -> str:
    # Emisor y analistas llevan contadores separados: fallos en uno no bloquean al otro.
    return f"{scope}:{_client_ip(request)}"


def _check_not_locked(request: Request, action: str, scope: str) -> None:
    key, now = _lock_key(request, scope), time.time()
    with get_db() as conn:
        locked = (
            conn.execute(
                "SELECT COUNT(*) FROM auth_failures WHERE key = ? AND ts >= ?", (key, now - AUTH_WINDOW_S)
            ).fetchone()[0]
            >= MAX_AUTH_FAILURES
        )
    if locked:
        log_action(request, action, result="locked_out")
        raise HTTPException(
            status_code=429, detail="Too many failed attempts", headers={"Retry-After": str(AUTH_WINDOW_S)}
        )


def _register_failure(request: Request, scope: str = "analyst") -> None:
    key, now = _lock_key(request, scope), time.time()
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM auth_failures WHERE ts < ?", (now - AUTH_WINDOW_S,))
        total = conn.execute("SELECT COUNT(*) FROM auth_failures").fetchone()[0]
        if total >= AUTH_FAILURES_MAX_ROWS:
            # Tope de tamano: se descartan los registros mas antiguos, no todo el estado.
            conn.execute(
                "DELETE FROM auth_failures WHERE rowid IN (SELECT rowid FROM auth_failures ORDER BY ts LIMIT 100)"
            )
        conn.execute("INSERT INTO auth_failures (key, ts) VALUES (?, ?)", (key, now))
        conn.commit()


EMITTER_ACTOR = "emisor:falcon-api-key"


def _emitter_key_ok(key: Optional[str]) -> bool:
    return bool(API_KEY) and key is not None and secrets.compare_digest(key.encode(), API_KEY.encode())


def _find_analyst(key: Optional[str]) -> Optional[Analyst]:
    if key is None:
        return None
    # Se recorren todas las claves sin cortar antes: tiempo constante respecto a cual acierta.
    found = None
    for known, analyst in ANALYSTS.items():
        if secrets.compare_digest(key.encode(), known.encode()):
            found = analyst
    return found


def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("authorization")
    if header and header[:7].lower() == "bearer ":
        return header[7:].strip()
    return None


def _resolve_analyst(request: Request) -> Optional[Analyst]:
    """Analista autenticado por token de identidad o, si esta permitido, por clave estatica."""
    token = _bearer_token(request)
    if token is not None:  # con Bearer presente no se cae a la clave estatica
        try:
            with get_db() as conn:
                principal = identity.verify_access_token(conn, token)
        except identity.IdentityError:
            return None
        request.state.principal = principal
        return Analyst(principal.username, principal.role)
    key = request.headers.get("x-analyst-key")
    if ALLOW_STATIC_ANALYST_KEYS and key is not None and len(key) <= 256:
        return _find_analyst(key)
    return None


def _matched_route(request: Request) -> Optional[APIRoute]:
    """Ruta que coincide por completo (ruta y metodo); None si no hay (404/405 siguen su camino)."""
    for route in request.app.router.routes:
        if isinstance(route, APIRoute) and route.matches(request.scope)[0] == Match.FULL:
            return route
    return None


def _auth_scope(request: Request) -> Optional[str]:
    """Que credencial exige la ruta (None = ruta publica), segun la ruta que coincide y sus
    dependencias: no depende del texto de la URL ni de mantener una lista aparte."""
    route = _matched_route(request)
    if route is None:
        return None
    if route.endpoint in LOGIN_ENDPOINTS:
        return "login"
    calls = {dep.call for dep in route.dependant.dependencies}
    if require_api_key in calls:
        return "emitter"
    if require_analyst in calls:
        return "analyst"
    return None


def _authenticate_or_reject(request: Request, scope: str):
    """Para el handler de 422: devuelve el actor si la credencial es valida, o una respuesta 429/401."""
    lock_action = {
        "emitter": "create_alert_locked_out",
        "login": "login_locked_out",
    }.get(scope, "analyst_locked_out")
    try:
        _check_not_locked(request, lock_action, scope)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
    # Las cabeceras de mas de 256 caracteres ya son invalidas (mismo limite que las dependencias).
    if scope == "emitter":
        key = request.headers.get("x-api-key")
        if key is not None and len(key) <= 256 and _emitter_key_ok(key):
            return EMITTER_ACTOR
        _register_failure(request, "emitter")
        log_action(request, "create_alert_unauthorized", result="unauthorized")
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})
    if scope == "login":
        # Cuerpo mal formado en login/refresh: cuenta como un intento fallido mas (mismo contador).
        _register_failure(request, "login")
        action = "refresh_failed" if request.url.path == "/auth/refresh" else "login_failed"
        log_action(request, action, result="unauthorized")
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})
    analyst = _resolve_analyst(request)
    if analyst:
        return f"analyst:{analyst.name}"
    _register_failure(request)
    log_action(request, "analyst_unauthorized", result="unauthorized")
    return JSONResponse(status_code=401, content={"detail": "Invalid or missing credentials"})


def require_api_key(
    request: Request, x_api_key: Optional[str] = Header(default=None, max_length=256)
) -> None:
    _check_not_locked(request, "create_alert_locked_out", "emitter")
    if not _emitter_key_ok(x_api_key):
        _register_failure(request, "emitter")
        log_action(request, "create_alert_unauthorized", result="unauthorized")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_analyst(
    request: Request,
    x_analyst_key: Optional[str] = Header(default=None, max_length=256),
    authorization: Optional[str] = Header(default=None, max_length=2100),
) -> Analyst:
    _check_not_locked(request, "analyst_locked_out", "analyst")
    found = _resolve_analyst(request)
    if found:
        return found
    _register_failure(request)
    log_action(request, "analyst_unauthorized", result="unauthorized")
    raise HTTPException(status_code=401, detail="Invalid or missing credentials")


REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# F-1: el WAF solo analiza como JSON el cuerpo con Content-Type application/json, pero FastAPI tambien
# acepta tipos "+json" (application/vnd.x+json): con ellos los campos llegarian a la app sin que CRS
# los viera como argumentos. Con cuerpo, solo se acepta application/json (parametros opcionales, sin
# distinguir mayusculas). Sin cuerpo (p. ej. POST /auth/logout) no se exige nada, como hasta ahora.
BODY_METHODS = {"POST", "PUT", "PATCH"}


def _has_body(request: Request) -> bool:
    if "transfer-encoding" in request.headers:
        return True
    length = request.headers.get("content-length")
    if length is None:
        return False
    try:
        return int(length) > 0
    except ValueError:  # longitud invalida: no se da el cuerpo por vacio
        return True


def _is_json_media_type(value: Optional[str]) -> bool:
    return value is not None and value.split(";", 1)[0].strip().lower() == "application/json"


def _reject_unsupported_media(request: Request) -> Optional[JSONResponse]:
    """415 para un cuerpo que no es application/json. Mismo orden que el handler de 422 (A21): en
    rutas autenticadas, sin credencial valida responde 401/429 antes, para que un anonimo no pueda
    sondear; en login/refresh (sin credencial previa) cuenta como intento fallido, con su bloqueo."""
    if request.method not in BODY_METHODS or not _has_body(request):
        return None
    if _is_json_media_type(request.headers.get("content-type")) or _matched_route(request) is None:
        return None
    scope = _auth_scope(request)
    actor = None
    if scope == "login":
        try:
            _check_not_locked(request, "login_locked_out", "login")
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)
        _register_failure(request, "login")
    elif scope is not None:
        actor = _authenticate_or_reject(request, scope)
        if isinstance(actor, JSONResponse):
            return actor
    # Rastro de auditoria con ruta, IP, actor y request_id; nunca el cuerpo ni el tipo enviado.
    log_action(request, "unsupported_media_type", actor=actor, result="unsupported_media_type")
    return JSONResponse(status_code=415, content={"detail": "Content-Type must be application/json"})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Nginx genera X-Request-ID ($request_id) y lo registra en access.log. Se acepta solo con la
    # forma esperada (32 hex): un valor ajeno no puede inyectar texto en el audit log.
    supplied = request.headers.get("x-request-id", "")
    request.state.request_id = supplied if REQUEST_ID_RE.fullmatch(supplied) else uuid.uuid4().hex
    # Antes de que FastAPI analice el cuerpo; la respuesta 415 lleva igual las cabeceras de abajo.
    rejection = _reject_unsupported_media(request)
    # Defensa en profundidad: aunque Nginx se omita, la app no sirve respuestas cacheables
    # ni embebibles. Las respuestas contienen datos de alertas: nunca deben cachearse.
    response = rejection if rejection is not None else await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


# --- Motores (clasificacion + escalamiento) -----------------------------------


def process_alert(alert_id: str, request_id: Optional[str] = None) -> None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        return
    alert = row_to_alert(row)
    # La clasificacion puede tardar (AbuseIPDB, hasta 3 s) y no retiene ningun bloqueo.
    score, classification, enriched = enrichment.classify(alert)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        # Se relee el estado bajo bloqueo de escritura: si un analista actuo mientras se
        # clasificaba, el estado que dejo (closed, acknowledged, ...) se respeta.
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if current is None:
            return
        new_status = current["status"]
        auto_escalate = False
        if current["status"] == "new":
            auto_escalate = escalation.should_escalate(score)
            new_status = "escalated" if auto_escalate else "classified"
        conn.execute(
            "UPDATE alerts SET risk_score = ?, classification = ?, enrichment = ?, "
            "status = ?, updated_at = ? WHERE id = ?",
            (score, classification, json.dumps(enriched, ensure_ascii=False), new_status, now, alert_id),
        )
        conn.commit()
    alert.update(risk_score=score, classification=classification)
    write_log(
        "alert_classified",
        alert_id=alert_id,
        actor="system:motor-clasificacion",
        result=f"{classification} ({score})",
        request_id=request_id,
    )
    if auto_escalate:
        escalation.notify(alert, reason=f"auto: risk_score {score} >= {escalation.threshold()}")
        write_log(
            "alert_escalated",
            alert_id=alert_id,
            actor="system:motor-escalamiento",
            result="auto",
            request_id=request_id,
        )


# El reprocesado de pendientes corre en segundo plano para que el arranque no dependa de
# servicios externos (AbuseIPDB lento o caido).
_startup_thread: Optional[threading.Thread] = None


def _reprocess_pending() -> None:
    with get_db() as conn:
        pending = conn.execute("SELECT id FROM alerts WHERE risk_score IS NULL").fetchall()
    for row in pending:
        try:
            process_alert(row["id"])
        except Exception as exc:  # una alerta defectuosa no debe frenar al resto
            write_log("alert_classify_failed", alert_id=row["id"], actor="system", result=type(exc).__name__)


def _on_startup() -> None:
    global _startup_thread
    escalation.threshold()  # falla al arrancar (no en la primera alerta) si el valor es invalido
    init_db()
    _startup_thread = threading.Thread(target=_reprocess_pending, name="reprocess-pending", daemon=True)
    _startup_thread.start()


# --- Endpoints -----------------------------------------------------------------


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def root(request: Request):
    # Sin log_action: es una ruta anonima y cada visita inflaria el log de auditoria.
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
    now_m = time.monotonic()
    with _ingest_lock:
        while _ingest_times and now_m - _ingest_times[0] >= 60:
            _ingest_times.popleft()
        limited = len(_ingest_times) >= MAX_INGEST_PER_MIN
        if not limited:
            _ingest_times.append(now_m)
    if limited:
        log_action(request, "create_alert_rate_limited", actor="emisor:falcon-api-key", result="rate_limited")
        raise HTTPException(status_code=429, detail="Ingest rate limit reached", headers={"Retry-After": "60"})
    alert_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    source_ip = str(alert.source_ip) if alert.source_ip else None
    with get_db() as conn:
        conn.execute("BEGIN IMMEDIATE")  # el conteo de la cuota y el INSERT son atomicos
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
        stored = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.commit()
    if stored >= 0.9 * MAX_ALERTS and stored % 100 == 0:
        write_log("alert_quota_warning", actor="system", result=f"{stored}/{MAX_ALERTS}")
    log_action(request, "create_alert", alert_id, actor="emisor:falcon-api-key")
    # La clasificacion (que puede consultar AbuseIPDB) corre despues de responder:
    # una API externa lenta o caida nunca bloquea la ingesta.
    background_tasks.add_task(process_alert, alert_id, request.state.request_id)
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
        # Estado leido, decision y escritura bajo un mismo bloqueo: dos acciones concurrentes
        # (p. ej. close + acknowledge) no pueden reabrir una alerta cerrada.
        conn.execute("BEGIN IMMEDIATE")
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


# --- Identidad: login, renovacion y cierre de sesion -------------------------------


class LoginIn(BaseModel):
    model_config = {"extra": "forbid"}
    username: str = Field(pattern=r"^[A-Za-z0-9._-]{3,32}$")
    password: str = Field(min_length=1, max_length=128)
    otp: Optional[str] = Field(default=None, pattern=r"^[0-9]{6}$")


class RefreshIn(BaseModel):
    model_config = {"extra": "forbid"}
    refresh_token: str = Field(min_length=16, max_length=256)


class LogoutIn(BaseModel):
    model_config = {"extra": "forbid"}
    refresh_token: Optional[str] = Field(default=None, min_length=16, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    refresh_token: str


def _identity_or_503(request: Request) -> None:
    if not identity.enabled():
        log_action(request, "identity_not_configured", result="unavailable")
        raise HTTPException(status_code=503, detail="Identity service not configured")


@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request):
    _check_not_locked(request, "login_locked_out", "login")
    _identity_or_503(request)
    actor = f"login:{body.username.lower()}"
    with get_db() as conn:
        try:
            user, amr = identity.authenticate(
                conn, body.username, body.password, body.otp, client_ip=_client_ip(request)
            )
        except identity.Throttled as wait:
            log_action(request, "login_throttled", actor=actor, result="locked_out")
            raise HTTPException(
                status_code=429, detail="Too many failed attempts", headers={"Retry-After": str(wait.retry_after)}
            )
        except identity.InvalidCredentials:
            # Misma respuesta y mismo cuerpo para usuario inexistente, contrasena o codigo incorrectos.
            _register_failure(request, "login")
            log_action(request, "login_failed", actor=actor, result="unauthorized")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        refresh_token, sid = identity.issue_refresh_token(conn, user["username"], amr)
        access, _jti, ttl = identity.issue_access_token(user, amr, sid)
        conn.commit()
    log_action(request, "login_ok", actor=f"analyst:{user['username']}")
    return TokenOut(access_token=access, expires_in=ttl, refresh_token=refresh_token)


@app.post("/auth/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, request: Request):
    _check_not_locked(request, "login_locked_out", "login")
    _identity_or_503(request)
    with get_db() as conn:
        try:
            user, amr, new_refresh, sid = identity.rotate_refresh_token(conn, body.refresh_token)
        except identity.RefreshReuse as reuse:
            _register_failure(request, "login")
            log_action(request, "refresh_reuse_detected", actor=f"analyst:{reuse.username}", result="unauthorized")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        except identity.TokenInvalid:
            _register_failure(request, "login")
            log_action(request, "refresh_failed", result="unauthorized")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        access, _jti, ttl = identity.issue_access_token(user, amr, sid)
    log_action(request, "refresh_ok", actor=f"analyst:{user['username']}")
    return TokenOut(access_token=access, expires_in=ttl, refresh_token=new_refresh)


LOGIN_ENDPOINTS = {login, refresh}  # el cuerpo mal formado en estas rutas cuenta como intento fallido


@app.post("/auth/logout", status_code=204)
def logout(request: Request, body: Optional[LogoutIn] = None, analyst: Analyst = Depends(require_analyst)):
    principal = getattr(request.state, "principal", None)
    with get_db() as conn:
        if principal is not None:  # sesion por token: se cierra la sesion completa y el token en uso
            identity.revoke_access_token(conn, principal.jti, principal.exp)
            identity.revoke_session(conn, principal.sid)  # tambien su token de renovacion, siempre
        if body and body.refresh_token:
            identity.revoke_family_of(conn, body.refresh_token)
        conn.commit()
    log_action(request, "logout", actor=f"analyst:{analyst.name}")
    return Response(status_code=204)


# --- Inventario de red (solo lectura) -------------------------------------------


def _device_for_role(device: dict, role: str) -> dict:
    """Filtrado de campos por rol: la IP de gestion solo la ve quien puede actuar (respondedor)."""
    if role == "respondedor":
        return device
    return {k: v for k, v in device.items() if k != "mgmt_ip"}


@app.get("/network/devices", response_model=list[NetworkDevice], response_model_exclude_none=True)
def list_network_devices(
    request: Request,
    analyst: Analyst = Depends(require_analyst),
    type: Optional[Literal["firewall", "router", "switch"]] = None,
):
    log_action(request, "list_network_devices", actor=f"analyst:{analyst.name}")
    return [_device_for_role(d, analyst.role) for d in inventory.list_devices(type)]


@app.get("/network/devices/{device_id}", response_model=NetworkDevice, response_model_exclude_none=True)
def get_network_device(device_id: DeviceId, request: Request, analyst: Analyst = Depends(require_analyst)):
    actor = f"analyst:{analyst.name}"
    device = inventory.get_device(device_id)
    if device is None:
        log_action(request, "get_network_device_not_found", actor=actor, result="not_found")
        raise HTTPException(status_code=404, detail="Device not found")
    log_action(request, "get_network_device", actor=actor)
    return _device_for_role(device, analyst.role)
