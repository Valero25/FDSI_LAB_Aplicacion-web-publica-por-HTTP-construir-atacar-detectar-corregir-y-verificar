"""Pruebas de la Parte 2: controles de seguridad y motores de clasificacion/escalamiento.

Ejecutar desde la raiz del repositorio:  python -m pytest -q
"""
import io
import json
import os
import urllib.error

import pytest

API_KEY = "clave-emisor-de-prueba-123456"
KEY_ANA = "clave-ana-respondedora-123456"
KEY_JUAN = "clave-juan-lector-1234567890"
os.environ["MUV_API_KEY"] = API_KEY
os.environ["MUV_ANALYSTS"] = f"ana:respondedor:{KEY_ANA};juan:lector:{KEY_JUAN}"
os.environ.pop("ABUSEIPDB_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import enrichment, main  # noqa: E402

EMISOR = {"X-API-Key": API_KEY}
ANA = {"X-Analyst-Key": KEY_ANA}
JUAN = {"X-Analyst-Key": KEY_JUAN}
ALERT = {
    "severity": "high",
    "tactic": "Initial Access",
    "technique": "T1078 - Valid Accounts",
    "hostname": "WEB-LAB-01",
    "description": "Prueba automatizada (dato ficticio)",
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.db")
    main._auth_failures.clear()  # el bloqueo por IP no debe filtrarse entre pruebas
    main._ingest_times.clear()  # ni el tope de ingesta por minuto
    with TestClient(main.app) as c:
        # El reprocesado de pendientes del arranque corre en segundo plano: se espera para
        # que las pruebas partan de alertas ya clasificadas.
        main._startup_thread.join(timeout=10)
        yield c


def create(client, **overrides):
    r = client.post("/alerts", json={**ALERT, **overrides}, headers=EMISOR)
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- Superficie expuesta ------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_disabled(client, path):
    assert client.get(path).status_code == 404


def test_root_is_public(client):
    assert client.get("/").status_code == 200


# --- Autenticacion del emisor (H1) ----------------------------------------------


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "incorrecta"}, ANA])
def test_post_requires_emitter_key(client, headers):
    assert client.post("/alerts", json=ALERT, headers=headers).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"severity": "xxx"},
        {"hostname": "a b<script>"},
        {"description": "x" * 1001},
        {"status": "closed"},
        {"source_ip": "no-es-una-ip"},
    ],
)
def test_post_validates_schema(client, overrides):
    r = client.post("/alerts", json={**ALERT, **overrides}, headers=EMISOR)
    assert r.status_code == 422


# --- Autenticacion y roles del analista (H3, H4, H6) ------------------------------


def test_read_requires_analyst(client):
    assert client.get("/alerts").status_code == 401
    assert client.get("/alerts", headers=EMISOR).status_code == 401
    assert client.get("/alerts", headers=JUAN).status_code == 200


def test_reader_cannot_escalate_or_close(client):
    alert_id = create(client)
    for action in ("escalate", "close"):
        r = client.post(f"/alerts/{alert_id}/actions", json={"action": action}, headers=JUAN)
        assert r.status_code == 403
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "acknowledge"}, headers=JUAN)
    assert r.status_code == 201


def test_responder_actions_are_attributed(client):
    alert_id = create(client)
    r = client.post(
        f"/alerts/{alert_id}/actions", json={"action": "close", "note": "falso positivo"}, headers=ANA
    )
    assert r.status_code == 201
    detail = client.get(f"/alerts/{alert_id}", headers=ANA).json()
    assert detail["status"] == "closed"
    assert detail["actions"][-1] == {**detail["actions"][-1], "analyst": "ana", "role": "respondedor"}
    # Una alerta cerrada solo admite comentarios.
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "escalate"}, headers=ANA)
    assert r.status_code == 409


# --- Motor de Clasificacion y Enriquecimiento + Escalamiento --------------------


def test_alert_is_classified_with_mitre(client):
    alert_id = create(client)
    alert = client.get(f"/alerts/{alert_id}", headers=JUAN).json()
    assert alert["risk_score"] == 60
    assert alert["classification"] == "media"
    assert alert["status"] == "classified"
    mitre = alert["enrichment"]["mitre"]
    assert mitre["technique_id"] == "T1078"
    assert mitre["name"] == "Valid Accounts"
    assert mitre["tactic_matches"] is True
    assert alert["enrichment"]["abuseipdb"]["status"] == "skipped_no_ip"


def test_critical_alert_is_auto_escalated(client):
    alert_id = create(
        client, severity="critical", tactic="Exfiltration", technique="T1041 - Exfiltration Over C2 Channel"
    )
    alert = client.get(f"/alerts/{alert_id}", headers=JUAN).json()
    assert alert["risk_score"] == 90
    assert alert["status"] == "escalated"


def test_tactic_mismatch_is_flagged(client):
    alert_id = create(client, tactic="Impact")
    flags = client.get(f"/alerts/{alert_id}", headers=JUAN).json()["enrichment"]["flags"]
    assert "tactic_mismatch" in flags


def test_filters(client):
    create(client, severity="low")
    create(client, severity="critical", tactic="Impact", technique="T1485 - Data Destruction")
    r = client.get("/alerts", params={"severity": "critical"}, headers=JUAN).json()
    assert r and all(a["severity"] == "critical" for a in r)
    r = client.get("/alerts", params={"min_score": 70}, headers=JUAN).json()
    assert r and all(a["risk_score"] >= 70 for a in r)
    assert client.get("/alerts", params={"limit": 1000}, headers=JUAN).status_code == 422


# --- AbuseIPDB: integracion externa controlada --------------------------------


def test_abuseipdb_never_queries_private_ips(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    monkeypatch.setattr(enrichment.urllib.request, "urlopen", pytest.fail)
    assert enrichment.abuseipdb_check("192.168.61.1")["status"] == "skipped_not_public"


def test_abuseipdb_without_key_is_skipped():
    assert enrichment.abuseipdb_check("8.8.8.8")["status"] == "skipped_no_key"


def _fake_response(payload):
    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return lambda req, timeout: Resp(json.dumps(payload).encode())


def test_abuseipdb_ok_raises_score(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()
    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        _fake_response({"data": {"abuseConfidenceScore": 100, "totalReports": 50, "countryCode": "NL"}}),
    )
    score, _, enriched = enrichment.classify({**ALERT, "source_ip": "203.0.114.10"})
    assert score == 80
    assert "ip_maliciosa" in enriched["flags"]


def test_abuseipdb_rejects_invalid_response(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()
    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        _fake_response({"data": {"abuseConfidenceScore": 999, "totalReports": 1}}),
    )
    assert enrichment.abuseipdb_check("203.0.114.11") == {"status": "error", "reason": "invalid_response"}


def test_abuseipdb_failure_does_not_block_classification(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    enrichment._abuse_cache.clear()

    def boom(req, timeout):
        raise urllib.error.URLError("sin red")

    monkeypatch.setattr(enrichment.urllib.request, "urlopen", boom)
    score, classification, enriched = enrichment.classify({**ALERT, "source_ip": "203.0.114.12"})
    assert (score, classification) == (60, "media")
    assert enriched["abuseipdb"]["status"] == "error"


# --- Anti fuerza bruta y cabeceras ------------------------------------------------


def test_bruteforce_lockout_blocks_even_valid_key(client, monkeypatch):
    monkeypatch.setattr(main, "_auth_failures", {})
    for _ in range(main.MAX_AUTH_FAILURES):
        assert client.get("/alerts", headers={"X-Analyst-Key": "x" * 20}).status_code == 401
    r = client.get("/alerts", headers=ANA)
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_api_responses_are_not_cacheable_and_have_security_headers(client):
    r = client.get("/")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_acknowledge_does_not_downgrade_escalated_alert(client):
    alert_id = create(client, severity="critical", tactic="Exfiltration", technique="T1041 - Exfiltration Over C2 Channel")
    client.post(f"/alerts/{alert_id}/actions", json={"action": "acknowledge"}, headers=JUAN)
    assert client.get(f"/alerts/{alert_id}", headers=JUAN).json()["status"] == "escalated"


# --- Claves, ids y tabla de bloqueos ------------------------------------------------


def test_invalid_alert_id_is_rejected(client):
    assert client.get("/alerts/not-a-uuid", headers=JUAN).status_code == 422
    assert client.get("/alerts/..%2F..%2Fetc%2Fpasswd", headers=JUAN).status_code in (404, 422)
    ok = create(client)
    assert client.get(f"/alerts/{ok}", headers=JUAN).status_code == 200


def test_duplicate_analyst_keys_rejected():
    with pytest.raises(ValueError):
        main.load_analysts("a:lector:clave-compartida-123456;b:respondedor:clave-compartida-123456")


def test_lockout_table_evicts_oldest_not_everything(monkeypatch):
    monkeypatch.setattr(main, "_auth_failures", {f"10.{i // 65000}.{i % 250}.{i // 250 % 250}": [1.0] for i in range(10_000)})
    first = next(iter(main._auth_failures))

    class Req:
        client = type("C", (), {"host": "203.0.113.9"})()

    main._register_failure(Req())
    assert len(main._auth_failures) == 10_000
    assert first not in main._auth_failures and "analyst:203.0.113.9" in main._auth_failures


# --- Cuotas y base de datos -----------------------------------------------------------


def test_alert_quota(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_ALERTS", 3)  # el arranque ya siembra 3 alertas
    assert client.post("/alerts", json=ALERT, headers=EMISOR).status_code == 507


def test_action_quota(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_ACTIONS_PER_ALERT", 2)
    alert_id = create(client)
    body = {"action": "comment", "note": "x"}
    codes = [client.post(f"/alerts/{alert_id}/actions", json=body, headers=ANA).status_code for _ in range(3)]
    assert codes == [201, 201, 409]


def test_db_uses_wal_and_foreign_keys(client):
    with main.get_db() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_data_and_log_dirs_come_from_env(tmp_path):
    import subprocess, sys
    code = "import app.main as m; print(m.DB_PATH, m.LOG_DIR)"
    env = {**os.environ, "MUV_DATA_DIR": str(tmp_path / "d"), "MUV_LOG_DIR": str(tmp_path / "l")}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout
    assert str(tmp_path / "d" / "alerts.db") in out and (tmp_path / "l").is_dir()


# --- Correcciones del analisis de vulnerabilidades (V-01 ... V-13) ------------------


def test_late_classification_does_not_reopen_closed_alert(client):
    # V-01: el motor corre en segundo plano y puede terminar despues de que el analista actuo.
    alert_id = create(client)
    assert client.post(f"/alerts/{alert_id}/actions", json={"action": "close"}, headers=ANA).status_code == 201
    main.process_alert(alert_id)
    detail = client.get(f"/alerts/{alert_id}", headers=ANA).json()
    assert detail["status"] == "closed"
    assert detail["risk_score"] is not None  # igual queda clasificada


def test_late_classification_does_not_renotify_escalated_alert(client, monkeypatch):
    alert_id = create(
        client, severity="critical", tactic="Exfiltration", technique="T1041 - Exfiltration Over C2 Channel"
    )
    sent = []
    monkeypatch.setattr(main.escalation, "notify", lambda alert, reason: sent.append(reason))
    main.process_alert(alert_id)  # ya estaba escalada: no se vuelve a notificar
    assert sent == []
    assert client.get(f"/alerts/{alert_id}", headers=ANA).json()["status"] == "escalated"


def test_trailing_slash_does_not_redirect_with_client_host(client):
    # V-02: el Location del redirect de Starlette se construye con el header Host.
    r = client.get("/alerts/", headers={**ANA, "Host": "evil.example"}, follow_redirects=False)
    assert r.status_code == 404
    assert "location" not in r.headers


def test_concurrent_close_and_acknowledge_never_reopen(client):
    # V-08: leer el estado y escribir la decision es atomico.
    from concurrent.futures import ThreadPoolExecutor

    ids = [create(client) for _ in range(12)]

    def act(args):
        alert_id, action = args
        return client.post(f"/alerts/{alert_id}/actions", json={"action": action}, headers=ANA).status_code

    jobs = [(i, a) for i in ids for a in ("acknowledge", "close")]
    with ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(act, jobs))
    assert set(codes) <= {201, 409}
    for alert_id in ids:
        assert client.get(f"/alerts/{alert_id}", headers=ANA).json()["status"] == "closed"


def test_alert_quota_holds_under_concurrency(client, monkeypatch):
    # V-08: el conteo de la cuota y el INSERT no admiten carreras.
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(main, "MAX_ALERTS", 8)  # el arranque ya siembra 3
    with ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(lambda _: client.post("/alerts", json=ALERT, headers=EMISOR).status_code, range(20)))
    assert codes.count(201) == 5 and codes.count(507) == 15
    with main.get_db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 8


def test_lockout_scopes_are_independent(client):
    # V-13: fallos con la clave del emisor no bloquean a los analistas de la misma IP.
    for _ in range(main.MAX_AUTH_FAILURES):
        assert client.post("/alerts", json=ALERT, headers={"X-API-Key": "x" * 20}).status_code == 401
    assert client.post("/alerts", json=ALERT, headers=EMISOR).status_code == 429
    assert client.get("/alerts", headers=ANA).status_code == 200


@pytest.mark.parametrize(
    "value, ok",
    [
        ("clave-emisor-de-prueba-123456", True),
        ("a" * 32, False),  # baja variedad
        ("corta-123", False),
        ("clave-emisor-local-123456", False),  # ejemplo del README
        ("CAMBIAR_POR_VALOR_ALEATORIO", False),  # ejemplo de env.example
    ],
)
def test_usable_secret(value, ok):
    assert main.usable_secret(value) is ok


@pytest.mark.parametrize("value", ["abc", "-1", "101", ""])
def test_invalid_escalation_threshold_fails_at_startup(tmp_path, monkeypatch, value):
    # V-07: un valor invalido debe detener el arranque, no romper en la primera alerta.
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.db")
    monkeypatch.setenv("MUV_ESCALATION_THRESHOLD", value)
    with pytest.raises(ValueError, match="MUV_ESCALATION_THRESHOLD"):
        with TestClient(main.app):
            pass


def test_startup_does_not_wait_for_classification(tmp_path, monkeypatch):
    # V-07: AbuseIPDB lento no debe retrasar el arranque de la API.
    import threading

    gate = threading.Event()
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "alerts.db")
    monkeypatch.setattr(
        main.enrichment, "classify", lambda alert: (gate.wait(10), (10, "baja", {"flags": []}))[1]
    )
    with TestClient(main.app) as c:  # entra sin esperar a que termine la clasificacion
        assert main._startup_thread.is_alive()
        assert c.get("/").status_code == 200
        gate.set()
        main._startup_thread.join(timeout=10)
        assert not main._startup_thread.is_alive()


def test_abuseipdb_cache_is_bounded(monkeypatch):
    # V-10: un emisor no puede hacer crecer la cache sin limite.
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    monkeypatch.setattr(enrichment, "ABUSEIPDB_CACHE_MAX", 3)
    enrichment._abuse_cache.clear()
    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        _fake_response({"data": {"abuseConfidenceScore": 10, "totalReports": 1, "countryCode": "NL"}}),
    )
    for i in range(10):
        assert enrichment.abuseipdb_check(f"203.0.114.{i + 20}")["status"] == "ok"
    assert len(enrichment._abuse_cache) <= 3
    enrichment._abuse_cache.clear()


# --- Correlacion Nginx <-> app (request_id) -------------------------------------------


def _last_audit_entry(action):
    lines = (main.LOG_DIR / "actions.log").read_text(encoding="utf-8").splitlines()
    return next(json.loads(l) for l in reversed(lines) if json.loads(l)["action"] == action)


def test_request_id_is_echoed_and_logged(client):
    rid = "0123456789abcdef0123456789abcdef"
    r = client.get("/alerts", headers={**JUAN, "X-Request-ID": rid})
    assert r.headers["x-request-id"] == rid
    assert _last_audit_entry("list_alerts")["request_id"] == rid


def test_request_id_is_generated_when_missing(client):
    r = client.get("/alerts", headers=JUAN)
    rid = r.headers["x-request-id"]
    assert len(rid) == 32 and int(rid, 16) >= 0
    assert _last_audit_entry("list_alerts")["request_id"] == rid


@pytest.mark.parametrize("hostile", ['x" , "result": "ok', "A" * 200, "../../etc/passwd", "0123456789ABCDEF0123456789ABCDEF"])
def test_hostile_request_id_is_replaced(client, hostile):
    # Sin Nginx por delante, un cliente podria intentar inyectar texto en el audit log.
    r = client.get("/alerts", headers={**JUAN, "X-Request-ID": hostile})
    assert r.headers["x-request-id"] != hostile
    entry = _last_audit_entry("list_alerts")
    assert entry["request_id"] == r.headers["x-request-id"] and entry["result"] == "ok"


def test_request_id_links_ingestion_and_classification(client):
    rid = "fedcba9876543210fedcba9876543210"
    r = client.post("/alerts", json=ALERT, headers={**EMISOR, "X-Request-ID": rid})
    assert r.status_code == 201
    assert _last_audit_entry("create_alert")["request_id"] == rid
    assert _last_audit_entry("alert_classified")["request_id"] == rid


# --- Texto libre, errores sin eco, IPv6, tope de ingesta -------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"description": "rojo\x1b[31m"},  # secuencia ANSI
        {"description": "a\x00b"},  # NUL
        {"tactic": "Discovery\u202e"},  # override de direccion (trojan source)
        {"technique": "T1046\nT1078 - Valid Accounts"},  # salto de linea en campo de una linea
        {"hostname": "WEB-LAB-01"[:3] + "\u200b"},  # caracter invisible (ademas incumple el patron)
    ],
)
def test_control_and_bidi_characters_are_rejected(client, overrides):
    r = client.post("/alerts", json={**ALERT, **overrides}, headers=EMISOR)
    assert r.status_code == 422


def test_multiline_description_and_notes_are_allowed(client):
    alert_id = create(client, description="linea 1\nlinea 2\tcon tabulador")
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "comment", "note": "a\nb"}, headers=ANA)
    assert r.status_code == 201
    r = client.post(f"/alerts/{alert_id}/actions", json={"action": "comment", "note": "x\x1b[0m"}, headers=ANA)
    assert r.status_code == 422


def test_validation_errors_do_not_echo_input(client):
    r = client.post("/alerts", json={**ALERT, "severity": "SECRETO-REFLEJADO"}, headers=EMISOR)
    assert r.status_code == 422 and "SECRETO-REFLEJADO" not in r.text
    r = client.get("/alerts", headers={"X-Analyst-Key": "clave-casi-correcta-" + "z" * 300})
    assert r.status_code == 422 and "clave-casi-correcta" not in r.text


def test_ipv6_failures_are_counted_per_64_prefix():
    class Req:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})()

    a, b = main._lock_key(Req("2001:db8:1:2::1"), "analyst"), main._lock_key(Req("2001:db8:1:2:ffff::9"), "analyst")
    other = main._lock_key(Req("2001:db8:1:3::1"), "analyst")
    assert a == b and a != other
    assert main._lock_key(Req("::ffff:203.0.113.9"), "analyst") == main._lock_key(Req("203.0.113.9"), "analyst")


def test_ingest_rate_limit(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_INGEST_PER_MIN", 3)
    codes = [client.post("/alerts", json=ALERT, headers=EMISOR).status_code for _ in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    r = client.post("/alerts", json=ALERT, headers=EMISOR)
    assert r.headers["retry-after"] == "60"


def test_audit_path_is_truncated(client):
    client.get("/" + "a" * 3000)
    lines = (main.LOG_DIR / "actions.log").read_text(encoding="utf-8").splitlines()
    # un 404 del router no pasa por log_action; se comprueba con un id invalido autenticado
    client.get("/alerts/" + "b" * 3000, headers=JUAN)
    assert all(len(json.loads(l)["path"]) <= 256 for l in lines if '"path"' in l)


# --- Inventario de red (solo lectura) ---------------------------------------------------


def test_network_inventory_requires_analyst(client):
    assert client.get("/network/devices").status_code == 401
    assert client.get("/network/devices", headers=EMISOR).status_code == 401
    assert client.get("/network/devices", headers=JUAN).status_code == 200


def test_network_inventory_content_and_filter(client):
    devices = client.get("/network/devices", headers=JUAN).json()
    assert len(devices) >= 3 and {d["type"] for d in devices} == {"firewall", "router", "switch"}
    assert all(set(d) == set(devices[0]) for d in devices)
    # Sin credenciales ni campos de secretos en el inventario.
    assert not any(k in d for d in devices for k in ("password", "secret", "token", "credentials"))
    only = client.get("/network/devices", params={"type": "firewall"}, headers=JUAN).json()
    assert only and all(d["type"] == "firewall" for d in only)
    assert client.get("/network/devices", params={"type": "toaster"}, headers=JUAN).status_code == 422
    one = client.get("/network/devices/FW-LAB-01", headers=JUAN)
    assert one.status_code == 200 and one.json()["id"] == "FW-LAB-01"


def test_network_inventory_is_read_only(client):
    for method in ("post", "put", "patch", "delete"):
        r = client.request(method.upper(), "/network/devices", headers={**ANA, **EMISOR}, json={})
        assert r.status_code == 405
        r = client.request(method.upper(), "/network/devices/FW-LAB-01", headers=ANA, json={})
        assert r.status_code == 405


def test_network_device_id_is_validated(client):
    assert client.get("/network/devices/NO-EXISTE-99", headers=JUAN).status_code == 404
    assert client.get("/network/devices/..%2F..%2Fetc", headers=JUAN).status_code in (404, 422)
    assert client.get("/network/devices/fw-lab-01", headers=JUAN).status_code == 422  # minusculas


def test_anonymous_root_does_not_write_to_audit_log(client):
    log = main.LOG_DIR / "actions.log"
    before = log.read_text(encoding="utf-8") if log.exists() else ""
    for _ in range(5):
        assert client.get("/").status_code == 200
    after = log.read_text(encoding="utf-8") if log.exists() else ""
    assert after == before  # un cliente anonimo no puede inflar el log de auditoria
