"""Servicio de identidad del laboratorio (propio y pequeno, con bibliotecas probadas).

- Contrasenas: Argon2id (argon2-cffi). Nunca se almacenan ni se registran en claro.
- Tokens de acceso: JWT firmado con EdDSA (Ed25519), vida corta; se valida fijando el algoritmo,
  el emisor y la audiencia. La API solo necesita la clave PUBLICA para validar.
- Tokens de renovacion: opacos, guardados con hash, rotados en cada uso; presentar uno ya usado
  invalida toda la familia (deteccion de robo).
- Segundo factor: TOTP (RFC 6238) con secreto cifrado en reposo (Fernet) y proteccion contra
  repeticion del mismo codigo. Obligatorio para el rol respondedor.
- Estado en SQLite (no en memoria): revocaciones y esperas por cuenta sobreviven a un reinicio.

Este modulo no depende de FastAPI: recibe una conexion sqlite3 (row_factory = sqlite3.Row).
Depende del reloj (NTP): la expiracion de los tokens y los codigos TOTP usan la hora del servidor.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUER = "muvautomation-identity"
AUDIENCE = "muvautomation-api"
ALGORITHM = "EdDSA"  # fijo: jamas se toma de la cabecera del token
ACCESS_TTL_S = 10 * 60
REFRESH_TTL_S = 8 * 3600
CLOCK_LEEWAY_S = 5

ROLES = ("lector", "respondedor")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LEN, MAX_PASSWORD_LEN = 12, 128  # el maximo evita usar Argon2 para agotar CPU/memoria

# Espera creciente por cuenta (no bloqueo duro): a partir del 3.er fallo seguido espera 1 s, 2 s,
# 4 s... con tope. Durante la espera ni siquiera una contrasena correcta se acepta.
THROTTLE_FREE_ATTEMPTS = 3
THROTTLE_MAX_WAIT_S = 120
THROTTLE_MAX_ROWS = 10_000
THROTTLE_FORGET_AFTER_S = 24 * 3600

_hasher = PasswordHasher()  # Argon2id con los parametros por defecto de la biblioteca (RFC 9106)


class IdentityError(Exception):
    """Base de los errores de identidad (nunca llevan datos sensibles en el mensaje)."""


class NotConfigured(IdentityError):
    pass


class InvalidCredentials(IdentityError):
    pass


class Throttled(IdentityError):
    def __init__(self, retry_after: int):
        super().__init__("throttled")
        self.retry_after = retry_after


class TokenInvalid(IdentityError):
    pass


class RefreshReuse(IdentityError):
    """Se presento un token de renovacion ya usado: la familia entera queda revocada."""

    def __init__(self, username: str):
        super().__init__("refresh token reuse")
        self.username = username


# --- Configuracion (se lee del entorno al primer uso) ---------------------------


@lru_cache(maxsize=1)
def _private_key() -> Optional[Ed25519PrivateKey]:
    raw = os.environ.get("MUV_JWT_PRIVATE_KEY", "").strip()
    if not raw:
        return None
    try:
        seed = base64.b64decode(raw, validate=True)
    except ValueError:
        return None
    if len(seed) != 32:
        return None
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_pem() -> Optional[bytes]:
    key = _private_key()
    if key is None:
        return None
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


@lru_cache(maxsize=1)
def _fernet() -> Optional[Fernet]:
    raw = os.environ.get("MUV_TOTP_KEY", "").strip()
    if not raw:
        return None
    try:
        return Fernet(raw.encode())
    except ValueError:
        return None


def reset_config_cache() -> None:
    """Para las pruebas: vuelve a leer las claves del entorno."""
    _private_key.cache_clear()
    _fernet.cache_clear()
    _dummy_hash.cache_clear()


def enabled() -> bool:
    """La identidad solo funciona con clave de firma y clave de cifrado de TOTP validas."""
    return _private_key() is not None and _fernet() is not None


# --- Esquema --------------------------------------------------------------------


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('lector', 'respondedor')),
            totp_secret_enc TEXT,
            totp_last_step INTEGER NOT NULL DEFAULT 0,
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            username TEXT NOT NULL,
            amr TEXT NOT NULL,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (family_id);
        CREATE TABLE IF NOT EXISTS revoked_jti (
            jti TEXT PRIMARY KEY,
            exp REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_throttle (
            username TEXT PRIMARY KEY,
            failures INTEGER NOT NULL,
            next_allowed REAL NOT NULL,
            updated REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_failures (
            key TEXT NOT NULL,
            ts REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_auth_failures ON auth_failures (key, ts);
        """
    )


# --- Contrasenas ----------------------------------------------------------------


def check_password_policy(username: str, password: str) -> None:
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise ValueError(f"la contrasena debe tener entre {MIN_PASSWORD_LEN} y {MAX_PASSWORD_LEN} caracteres")
    if any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError("la contrasena no admite caracteres de control")
    if username.lower() in password.lower():
        raise ValueError("la contrasena no puede contener el nombre de usuario")
    if len(set(password)) < 6:
        raise ValueError("la contrasena es demasiado repetitiva")


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    # Hash de una contrasena aleatoria: un usuario inexistente cuesta lo mismo que uno real.
    return _hasher.hash(secrets.token_urlsafe(24))


def _verify_password(stored_hash: Optional[str], password: str) -> bool:
    target = stored_hash or _dummy_hash()
    try:
        ok = _hasher.verify(target, password)
    except (argon2_exceptions.VerifyMismatchError, argon2_exceptions.VerificationError, argon2_exceptions.InvalidHashError):
        ok = False
    return bool(ok) and stored_hash is not None


# --- Usuarios (alta solo por la CLI de administracion) ---------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str) -> Optional[str]:
    """Crea el usuario. Para el rol respondedor enrola TOTP y devuelve el secreto (se muestra una vez)."""
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("usuario invalido: 3-32 caracteres [A-Za-z0-9._-]")
    if role not in ROLES:
        raise ValueError(f"rol invalido: {', '.join(ROLES)}")
    check_password_policy(username, password)
    if role == "respondedor" and _fernet() is None:
        raise NotConfigured("MUV_TOTP_KEY ausente o invalida: no se puede enrolar el segundo factor")
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username.lower(), _hasher.hash(password), role, _now_iso()),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError("el usuario ya existe") from exc
    secret = enroll_totp(conn, username) if role == "respondedor" else None
    conn.commit()
    return secret


def set_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    check_password_policy(username, password)
    cur = conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?", (_hasher.hash(password), username.lower())
    )
    if cur.rowcount != 1:
        raise ValueError("el usuario no existe")
    revoke_user_sessions(conn, username)  # una contrasena nueva cierra las sesiones abiertas
    conn.commit()


def disable_user(conn: sqlite3.Connection, username: str) -> None:
    cur = conn.execute("UPDATE users SET disabled = 1 WHERE username = ?", (username.lower(),))
    if cur.rowcount != 1:
        raise ValueError("el usuario no existe")
    revoke_user_sessions(conn, username)
    conn.commit()


def enroll_totp(conn: sqlite3.Connection, username: str) -> str:
    """Genera un secreto TOTP nuevo (lo guarda cifrado) y lo devuelve para entregarlo al usuario."""
    fernet = _fernet()
    if fernet is None:
        raise NotConfigured("MUV_TOTP_KEY ausente o invalida")
    secret = pyotp.random_base32()
    cur = conn.execute(
        "UPDATE users SET totp_secret_enc = ?, totp_last_step = 0 WHERE username = ?",
        (fernet.encrypt(secret.encode()).decode(), username.lower()),
    )
    if cur.rowcount != 1:
        raise ValueError("el usuario no existe")
    conn.commit()
    return secret


def provisioning_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username.lower(), issuer_name="MuvAutomation")


def list_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT username, role, disabled, totp_secret_enc IS NOT NULL AS totp, created_at FROM users ORDER BY username"
    ).fetchall()
    return [dict(r) for r in rows]


# --- Espera creciente por cuenta --------------------------------------------------


def _throttle_key(username: str) -> str:
    return username.lower()[:64]  # existe o no: la espera no revela si la cuenta existe


def _throttle_remaining(conn: sqlite3.Connection, username: str, now: float) -> int:
    row = conn.execute(
        "SELECT next_allowed FROM login_throttle WHERE username = ?", (_throttle_key(username),)
    ).fetchone()
    if row is None or row["next_allowed"] <= now:
        return 0
    return max(1, int(row["next_allowed"] - now + 0.999))


def _register_login_failure(conn: sqlite3.Connection, username: str, now: float) -> None:
    key = _throttle_key(username)
    conn.execute("DELETE FROM login_throttle WHERE updated < ?", (now - THROTTLE_FORGET_AFTER_S,))
    row = conn.execute("SELECT failures FROM login_throttle WHERE username = ?", (key,)).fetchone()
    failures = (row["failures"] if row else 0) + 1
    over = failures - THROTTLE_FREE_ATTEMPTS
    wait = 0 if over < 0 else min(2**over, THROTTLE_MAX_WAIT_S)
    if row is None:
        total = conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0]
        if total >= THROTTLE_MAX_ROWS:  # tope de tamano: se descarta lo mas antiguo
            conn.execute(
                "DELETE FROM login_throttle WHERE username IN "
                "(SELECT username FROM login_throttle ORDER BY updated LIMIT 100)"
            )
    conn.execute(
        "INSERT INTO login_throttle (username, failures, next_allowed, updated) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET failures = excluded.failures, "
        "next_allowed = excluded.next_allowed, updated = excluded.updated",
        (key, failures, now + wait, now),
    )


def _clear_login_failures(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("DELETE FROM login_throttle WHERE username = ?", (_throttle_key(username),))


# --- Inicio de sesion --------------------------------------------------------------


def _check_totp(conn: sqlite3.Connection, user: sqlite3.Row, otp: Optional[str], now: float) -> bool:
    """Verifica el codigo con ventana de +-1 paso y rechaza un codigo ya usado (repeticion)."""
    fernet = _fernet()
    if not user["totp_secret_enc"] or fernet is None or not otp or not re.fullmatch(r"\d{6}", otp):
        return False
    try:
        secret = fernet.decrypt(user["totp_secret_enc"].encode()).decode()
    except InvalidToken:
        return False
    totp = pyotp.TOTP(secret)
    current = int(now // 30)
    matched = 0
    for step in (current - 1, current, current + 1):
        if hmac.compare_digest(totp.at(step * 30), otp) and step > user["totp_last_step"]:
            matched = step
    if not matched:
        return False
    # Condicion en el UPDATE: dos peticiones simultaneas con el mismo codigo no pasan las dos.
    cur = conn.execute(
        "UPDATE users SET totp_last_step = ? WHERE username = ? AND totp_last_step < ?",
        (matched, user["username"], matched),
    )
    return cur.rowcount == 1


def authenticate(
    conn: sqlite3.Connection, username: str, password: str, otp: Optional[str], now: Optional[float] = None
) -> tuple[sqlite3.Row, list[str]]:
    """Devuelve (usuario, amr). Todo fallo es InvalidCredentials; una espera activa es Throttled."""
    now = time.time() if now is None else now
    if not enabled():
        raise NotConfigured("identity not configured")
    conn.execute("BEGIN IMMEDIATE")
    remaining = _throttle_remaining(conn, username, now)
    if remaining:
        conn.rollback()
        raise Throttled(remaining)
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
    password_ok = _verify_password(user["password_hash"] if user else None, password)
    ok = bool(user) and password_ok and not user["disabled"]
    amr = ["pwd"]
    if ok:
        needs_otp = user["role"] == "respondedor" or user["totp_secret_enc"] is not None
        if needs_otp:
            ok = _check_totp(conn, user, otp, now)
            amr.append("otp")
    if not ok:
        _register_login_failure(conn, username, now)
        conn.commit()
        raise InvalidCredentials()
    _clear_login_failures(conn, username)
    conn.commit()
    return user, amr


# --- Tokens de acceso ---------------------------------------------------------------


def issue_access_token(user: sqlite3.Row, amr: list[str], now: Optional[float] = None) -> tuple[str, str, int]:
    key = _private_key()
    if key is None:
        raise NotConfigured("identity not configured")
    now = int(time.time() if now is None else now)
    jti = uuid.uuid4().hex
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": user["username"],
        "roles": [user["role"]],
        "amr": amr,
        "iat": now,
        "nbf": now,
        "exp": now + ACCESS_TTL_S,
        "jti": jti,
    }
    return jwt.encode(claims, key, algorithm=ALGORITHM), jti, ACCESS_TTL_S


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    amr: tuple
    jti: str
    exp: int


def verify_access_token(conn: sqlite3.Connection, token: str) -> Principal:
    pem = _public_pem()
    if pem is None:
        raise NotConfigured("identity not configured")
    if len(token) > 2048:
        raise TokenInvalid("token too long")
    try:
        claims = jwt.decode(
            token,
            pem,
            algorithms=[ALGORITHM],  # nunca "none" ni HS256 con la clave publica como secreto
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=CLOCK_LEEWAY_S,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "jti"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenInvalid("invalid token") from exc
    if not all(isinstance(claims[k], str) and claims[k] for k in ("sub", "jti")):
        raise TokenInvalid("malformed claims")
    if conn.execute("SELECT 1 FROM revoked_jti WHERE jti = ?", (claims["jti"],)).fetchone():
        raise TokenInvalid("revoked")
    # El rol y el estado salen de la base, no del token: deshabilitar a un usuario surte efecto ya.
    user = conn.execute(
        "SELECT username, role, disabled FROM users WHERE username = ?", (str(claims["sub"]),)
    ).fetchone()
    if user is None or user["disabled"]:
        raise TokenInvalid("unknown or disabled user")
    amr = tuple(claims.get("amr") or ())
    if user["role"] == "respondedor" and "otp" not in amr:
        raise TokenInvalid("second factor required")
    return Principal(user["username"], user["role"], amr, claims["jti"], int(claims["exp"]))


def revoke_access_token(conn: sqlite3.Connection, jti: str, exp: float, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    conn.execute("DELETE FROM revoked_jti WHERE exp < ?", (now - CLOCK_LEEWAY_S,))
    conn.execute("INSERT OR IGNORE INTO revoked_jti (jti, exp) VALUES (?, ?)", (jti, exp))


# --- Tokens de renovacion --------------------------------------------------------------


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_refresh_token(
    conn: sqlite3.Connection, username: str, amr: list[str], family_id: Optional[str] = None,
    now: Optional[float] = None,
) -> str:
    now = time.time() if now is None else now
    raw = secrets.token_urlsafe(48)
    conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now - 86400,))
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, family_id, username, amr, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (_hash_token(raw), family_id or uuid.uuid4().hex, username, ",".join(amr), now + REFRESH_TTL_S, now),
    )
    return raw


def rotate_refresh_token(
    conn: sqlite3.Connection, raw: str, now: Optional[float] = None
) -> tuple[sqlite3.Row, list[str], str]:
    """Consume el token y emite el siguiente de la misma familia. Devuelve (usuario, amr, nuevo)."""
    now = time.time() if now is None else now
    if not (16 <= len(raw) <= 256):
        raise TokenInvalid("malformed")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (_hash_token(raw),)).fetchone()
    if row is None or row["revoked"]:
        conn.rollback()
        raise TokenInvalid("invalid")
    if row["used"]:
        # Reuso: o lo uso el atacante o lo uso el dueno legitimo. Se corta toda la sesion.
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (row["family_id"],))
        conn.commit()
        raise RefreshReuse(row["username"])
    if row["expires_at"] < now:
        conn.rollback()
        raise TokenInvalid("expired")
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (row["username"],)
    ).fetchone()
    if user is None or user["disabled"]:
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (row["family_id"],))
        conn.commit()
        raise TokenInvalid("unknown or disabled user")
    conn.execute("UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?", (row["token_hash"],))
    amr = row["amr"].split(",")
    new_raw = issue_refresh_token(conn, row["username"], amr, family_id=row["family_id"], now=now)
    conn.commit()
    return user, amr, new_raw


def revoke_family_of(conn: sqlite3.Connection, raw: str) -> None:
    row = conn.execute("SELECT family_id FROM refresh_tokens WHERE token_hash = ?", (_hash_token(raw),)).fetchone()
    if row:
        conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (row["family_id"],))


def revoke_user_sessions(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE username = ?", (username.lower(),))
