"""Servicio de identidad: usuarios, login, tokens EdDSA, renovacion, TOTP y espera por cuenta."""
import base64
import json
import time

import jwt
import pyotp
import pytest
from cryptography.fernet import Fernet

from app import identity
import test_api as base  # reutiliza el entorno y los datos de la suite principal

main = base.main
client = base.client  # fixture
ALERT, EMISOR, ANA, JUAN = base.ALERT, base.EMISOR, base.ANA, base.JUAN

PASSWORD = "contrasena-larga-de-prueba-1"


def _create(username="marta", role="lector", password=PASSWORD):
    with main.get_db() as conn:
        return identity.create_user(conn, username, password, role)


def _login(client, username="marta", password=PASSWORD, otp=None):
    body = {"username": username, "password": password}
    if otp is not None:
        body["otp"] = otp
    return client.post("/auth/login", json=body)


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _forge(claims_override=None, key=None, algorithm="EdDSA", headers=None):
    now = int(time.time())
    claims = {
        "iss": identity.ISSUER, "aud": identity.AUDIENCE, "sub": "marta", "roles": ["lector"],
        "amr": ["pwd"], "iat": now, "nbf": now, "exp": now + 300, "jti": "forjado-1",
    }
    claims.update(claims_override or {})
    return jwt.encode(claims, key or identity._private_key(), algorithm=algorithm, headers=headers)


# --- Alta y almacenamiento ------------------------------------------------------------


def test_passwords_are_stored_with_argon2id_and_never_in_clear(client):
    _create()
    with main.get_db() as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE username = 'marta'").fetchone()[0]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


@pytest.mark.parametrize(
    "username, password",
    [("marta", "corta"), ("marta", "x" * 129), ("marta", "marta-y-algo-mas-1"), ("marta", "aaaaaaaaaaaaaaa"),
     ("marta", "con\x00nulo-largo-123"), ("a", PASSWORD), ("con espacio", PASSWORD)],
)
def test_password_and_username_policy(client, username, password):
    with pytest.raises(ValueError):
        with main.get_db() as conn:
            identity.create_user(conn, username, password, "lector")


def test_respondedor_gets_totp_secret_stored_encrypted(client):
    secret = _create("rosa", "respondedor")
    assert secret and len(secret) >= 16
    with main.get_db() as conn:
        enc = conn.execute("SELECT totp_secret_enc FROM users WHERE username = 'rosa'").fetchone()[0]
    assert enc and secret not in enc
    assert Fernet(base64.urlsafe_b64encode(bytes(range(32, 64)))).decrypt(enc.encode()).decode() == secret


def test_duplicate_user_is_rejected(client):
    _create()
    with pytest.raises(ValueError):
        _create()


# --- Login ------------------------------------------------------------------------------


def test_login_and_access_with_bearer(client):
    _create()
    r = _login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == identity.ACCESS_TTL_S
    r = client.get("/alerts", headers=_bearer(body["access_token"]))
    assert r.status_code == 200
    assert base._last_audit_entry("list_alerts")["actor"] == "analyst:marta"


def test_login_failures_are_indistinguishable(client):
    _create()
    wrong_pw = _login(client, password="otra-contrasena-larga-9")
    unknown = _login(client, username="inexistente")
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json() == {"detail": "Invalid credentials"}


def test_login_requires_otp_for_respondedor(client):
    secret = _create("rosa", "respondedor")
    assert _login(client, "rosa").status_code == 401  # sin codigo
    assert _login(client, "rosa", otp="000000").status_code == 401  # codigo incorrecto
    r = _login(client, "rosa", otp=pyotp.TOTP(secret).now())
    assert r.status_code == 200
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["amr"] == ["pwd", "otp"] and claims["roles"] == ["respondedor"]


def test_totp_code_cannot_be_replayed(client):
    secret = _create("rosa", "respondedor")
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert _login(client, "rosa", otp=code).status_code == 200
    assert _login(client, "rosa", otp=code).status_code == 401  # mismo codigo: repeticion
    assert _login(client, "rosa", otp=totp.at(time.time() + 30)).status_code == 200  # paso siguiente


def test_respondedor_with_valid_token_can_close_but_lector_cannot(client):
    secret = _create("rosa", "respondedor")
    _create("marta", "lector")
    alert_id = base.create(client)
    rosa = _login(client, "rosa", otp=pyotp.TOTP(secret).now()).json()["access_token"]
    marta = _login(client, "marta").json()["access_token"]
    close = {"action": "close", "note": "cerrada"}
    assert client.post(f"/alerts/{alert_id}/actions", json=close, headers=_bearer(marta)).status_code == 403
    assert client.post(f"/alerts/{alert_id}/actions", json=close, headers=_bearer(rosa)).status_code == 201


def test_login_body_validation_counts_as_failed_attempt_not_422(client):
    r = client.post("/auth/login", json={"username": "x"})
    assert r.status_code == 401 and r.json() == {"detail": "Invalid credentials"}
    r = client.post("/auth/login", content=b"{roto", headers={"Content-Type": "application/json"})
    assert r.status_code == 401
    assert base._audit_actions()[-1]["action"] == "login_failed"


def test_login_503_when_identity_is_not_configured(client, monkeypatch):
    monkeypatch.setattr(identity, "enabled", lambda: False)
    assert _login(client).status_code == 503


# --- Espera creciente por cuenta ---------------------------------------------------------


def test_account_throttle_grows_and_blocks_even_the_right_password(client):
    _create()
    for _ in range(identity.THROTTLE_FREE_ATTEMPTS):
        assert _login(client, password="incorrecta-larga-123").status_code == 401
    r = _login(client)  # contrasena correcta durante la espera
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert base._audit_actions()[-1]["result"] == "locked_out"  # lo ve fail2ban


def test_throttle_does_not_reveal_whether_the_account_exists(client):
    for _ in range(identity.THROTTLE_FREE_ATTEMPTS):
        assert _login(client, username="fantasma", password="incorrecta-larga-123").status_code == 401
    r = _login(client, username="fantasma")
    assert r.status_code == 429  # igual que una cuenta real


def test_throttle_is_stored_in_the_database(client):
    for _ in range(identity.THROTTLE_FREE_ATTEMPTS):
        _login(client, username="fantasma", password="incorrecta-larga-123")
    with main.get_db() as conn:
        row = conn.execute("SELECT failures FROM login_throttle WHERE username = 'fantasma'").fetchone()
    assert row["failures"] == identity.THROTTLE_FREE_ATTEMPTS


def test_successful_login_resets_the_throttle(client):
    _create()
    _login(client, password="incorrecta-larga-123")
    assert _login(client).status_code == 200
    with main.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0] == 0


# --- Validacion del token de acceso -------------------------------------------------------


def test_forged_and_malformed_tokens_are_rejected(client):
    _create()
    from cryptography.hazmat.primitives import serialization

    # Ataque clasico de confusion de algoritmo: HS256 usando la clave publica como secreto.
    public_raw = identity._private_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    cases = {
        "alg none": jwt.encode({"sub": "marta"}, key=None, algorithm="none"),
        "HS256 con la clave publica como secreto": jwt.encode(
            {"iss": identity.ISSUER, "aud": identity.AUDIENCE, "sub": "marta", "jti": "x",
             "iat": int(time.time()), "exp": int(time.time()) + 300},
            public_raw, algorithm="HS256",
        ),
        "audiencia incorrecta": _forge({"aud": "otra-api"}),
        "emisor incorrecto": _forge({"iss": "otro"}),
        "expirado": _forge({"exp": int(time.time()) - 600, "iat": int(time.time()) - 900}),
        "sin jti": _forge({"jti": None}),
        "basura": "esto.no.es-un-jwt",
    }
    for name, token in cases.items():
        with main.get_db() as conn:  # cada caso por separado: no debe toparse con el bloqueo por IP
            conn.execute("DELETE FROM auth_failures")
            conn.commit()
        r = client.get("/alerts", headers=_bearer(token))
        assert r.status_code == 401, name


def test_token_signed_with_another_key_is_rejected(client):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _create()
    token = _forge(key=Ed25519PrivateKey.generate())
    assert client.get("/alerts", headers=_bearer(token)).status_code == 401


def test_valid_forged_claims_need_an_existing_user(client):
    # Firmado con la clave correcta, pero el usuario no existe: no hay acceso.
    assert client.get("/alerts", headers=_bearer(_forge({"sub": "fantasma"}))).status_code == 401


def test_respondedor_token_without_second_factor_is_rejected(client):
    _create("rosa", "respondedor")
    token = _forge({"sub": "rosa", "roles": ["respondedor"], "amr": ["pwd"]})
    assert client.get("/alerts", headers=_bearer(token)).status_code == 401


def test_role_comes_from_the_database_not_from_the_token(client):
    _create("marta", "lector")
    token = _forge({"sub": "marta", "roles": ["respondedor"], "amr": ["pwd", "otp"]})
    alert_id = base.create(client)
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "close", "note": "x"}, headers=_bearer(token))
    assert r.status_code == 403


def test_disabled_user_loses_access_immediately(client):
    _create()
    body = _login(client).json()
    assert client.get("/alerts", headers=_bearer(body["access_token"])).status_code == 200
    with main.get_db() as conn:
        identity.disable_user(conn, "marta")
    assert client.get("/alerts", headers=_bearer(body["access_token"])).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]}).status_code == 401
    assert _login(client).status_code == 401


def test_bad_bearer_counts_towards_lockout(client):
    for _ in range(main.MAX_AUTH_FAILURES):
        assert client.get("/alerts", headers=_bearer("basura")).status_code == 401
    assert client.get("/alerts", headers=ANA).status_code == 429


# --- Renovacion y cierre de sesion ----------------------------------------------------------


def test_refresh_rotates_and_old_token_is_dead(client):
    _create()
    first = _login(client).json()
    second = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    new = second.json()
    assert new["refresh_token"] != first["refresh_token"] and new["access_token"] != first["access_token"]
    assert client.get("/alerts", headers=_bearer(new["access_token"])).status_code == 200


def test_refresh_reuse_revokes_the_whole_session(client):
    _create()
    first = _login(client).json()
    second = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).json()
    # Alguien presenta de nuevo el token ya usado: 401 y toda la familia queda revocada.
    r = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 401
    assert base._audit_actions()[-1]["action"] == "refresh_reuse_detected"
    assert client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code == 401


def test_refresh_tokens_are_stored_hashed(client):
    _create()
    raw = _login(client).json()["refresh_token"]
    with main.get_db() as conn:
        stored = [r[0] for r in conn.execute("SELECT token_hash FROM refresh_tokens")]
    assert stored and raw not in stored and all(len(h) == 64 for h in stored)


def test_refresh_expires(client):
    _create()
    raw = _login(client).json()["refresh_token"]
    with main.get_db() as conn:
        conn.execute("UPDATE refresh_tokens SET expires_at = ?", (time.time() - 10,))
        conn.commit()
    assert client.post("/auth/refresh", json={"refresh_token": raw}).status_code == 401


def test_logout_revokes_access_and_refresh(client):
    _create()
    tokens = _login(client).json()
    r = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]},
                    headers=_bearer(tokens["access_token"]))
    assert r.status_code == 204
    assert client.get("/alerts", headers=_bearer(tokens["access_token"])).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_revocation_survives_restart(client):
    _create()
    tokens = _login(client).json()
    client.post("/auth/logout", headers=_bearer(tokens["access_token"]))
    # La revocacion esta en SQLite: una "nueva" conexion (reinicio) sigue viendola.
    with main.get_db() as conn:
        n = conn.execute("SELECT COUNT(*) FROM revoked_jti").fetchone()[0]
    assert n == 1


def test_logout_requires_authentication(client):
    assert client.post("/auth/logout").status_code == 401


# --- Claves estaticas e inventario por rol ----------------------------------------------------


def test_static_analyst_keys_can_be_switched_off(client, monkeypatch):
    _create()
    token = _login(client).json()["access_token"]
    monkeypatch.setattr(main, "ALLOW_STATIC_ANALYST_KEYS", False)
    assert client.get("/alerts", headers=ANA).status_code == 401
    assert client.get("/alerts", headers=_bearer(token)).status_code == 200
    # La clave del emisor (maquina) no depende del interruptor.
    assert client.post("/alerts", json=ALERT, headers=EMISOR).status_code == 201


def test_bearer_takes_precedence_over_static_key(client):
    _create("marta", "lector")
    token = _login(client).json()["access_token"]
    alert_id = base.create(client)
    # Con Bearer de un lector no se cae a la clave estatica de un respondedor.
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "close", "note": "x"},
                    headers={**_bearer(token), **ANA})
    assert r.status_code == 403


def test_mgmt_ip_is_only_visible_to_respondedor(client):
    secret = _create("rosa", "respondedor")
    _create("marta", "lector")
    lector = _bearer(_login(client, "marta").json()["access_token"])
    resp = _bearer(_login(client, "rosa", otp=pyotp.TOTP(secret).now()).json()["access_token"])
    assert all("mgmt_ip" not in d for d in client.get("/network/devices", headers=lector).json())
    assert "mgmt_ip" not in client.get("/network/devices/FW-LAB-01", headers=lector).json()
    assert all("mgmt_ip" in d for d in client.get("/network/devices", headers=resp).json())
    assert "mgmt_ip" in client.get("/network/devices/FW-LAB-01", headers=resp).json()


def test_audit_log_never_contains_passwords_or_tokens(client):
    _create()
    tokens = _login(client).json()
    _login(client, password="intento-fallido-largo-1")
    text = (main.LOG_DIR / "actions.log").read_text(encoding="utf-8")
    for secret in (PASSWORD, "intento-fallido-largo-1", tokens["access_token"], tokens["refresh_token"]):
        assert secret not in text


# --- CLI de administracion -----------------------------------------------------------------


def _cli(args, tmp_path, monkeypatch, passwords=(PASSWORD, PASSWORD)):
    import io

    from app import identity_cli

    monkeypatch.setenv("MUV_DATA_DIR", str(tmp_path))
    answers = iter(passwords)
    out = io.StringIO()
    code = identity_cli.main(args, ask_password=lambda _prompt: next(answers), out=out)
    return code, out.getvalue()


def test_cli_creates_users_and_prints_totp_once(tmp_path, monkeypatch):
    code, out = _cli(["create-user", "rosa", "--role", "respondedor"], tmp_path, monkeypatch)
    assert code == 0 and "Secreto" in out and "otpauth://totp/" in out
    code, out = _cli(["list-users"], tmp_path, monkeypatch)
    assert "rosa" in out and "respondedor" in out and "totp=si" in out
    assert PASSWORD not in out
    code, out = _cli(["create-user", "marta", "--role", "lector"], tmp_path, monkeypatch)
    assert code == 0 and "Secreto" not in out  # el lector no tiene TOTP obligatorio


def test_cli_rejects_mismatched_or_weak_passwords(tmp_path, monkeypatch, capsys):
    code, _ = _cli(["create-user", "marta", "--role", "lector"], tmp_path, monkeypatch, ("uno-largo-123456", "otro-largo-123456"))
    assert code == 1
    code, _ = _cli(["create-user", "marta", "--role", "lector"], tmp_path, monkeypatch, ("corta", "corta"))
    assert code == 1


def test_cli_disable_and_enroll(tmp_path, monkeypatch):
    _cli(["create-user", "marta", "--role", "lector"], tmp_path, monkeypatch)
    code, out = _cli(["enroll-totp", "marta"], tmp_path, monkeypatch)
    assert code == 0 and "Secreto" in out
    code, _ = _cli(["disable-user", "marta"], tmp_path, monkeypatch)
    assert code == 0
    code, out = _cli(["list-users"], tmp_path, monkeypatch)
    assert "deshabilitado" in out
    assert _cli(["disable-user", "nadie"], tmp_path, monkeypatch)[0] == 1


def test_cli_gen_keys_produces_usable_keys(tmp_path, monkeypatch):
    code, out = _cli(["gen-keys"], tmp_path, monkeypatch)
    values = dict(line.split("=", 1) for line in out.strip().splitlines())
    assert code == 0 and set(values) == {"MUV_JWT_PRIVATE_KEY", "MUV_TOTP_KEY"}
    assert len(base64.b64decode(values["MUV_JWT_PRIVATE_KEY"])) == 32
    Fernet(values["MUV_TOTP_KEY"].encode())  # no lanza: clave Fernet valida
