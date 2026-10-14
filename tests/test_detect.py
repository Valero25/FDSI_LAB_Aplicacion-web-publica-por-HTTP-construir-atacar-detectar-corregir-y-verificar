"""Pruebas de la regla de deteccion (scripts/detect.py): umbral, ventana, falsos positivos."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "detect", Path(__file__).resolve().parent.parent / "scripts" / "detect.py"
)
detect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detect)

# Marcas de tiempo relativas a la hora actual: con fechas fijas, save_state (7 dias) acababa descartando
# el estado y los tests caducaban. Base = inicio de la hora de hace 2 h, asi minute/second (0-59) siguen
# siendo desplazamientos dentro de una misma hora y ningun evento queda en el futuro.
BASE = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(minute=0, second=0, microsecond=0)


def at(minute=0, second=0):
    return BASE + timedelta(minutes=minute, seconds=second)


def iso(minute=0, second=0, micro=True):
    return at(minute, second).isoformat(timespec="microseconds" if micro else "seconds")


def line(ip, second, status, path="/x", minute=0):
    ts = at(minute, second).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 153 "-" "curl/8.5"'


def run(lines, **kw):
    return detect.detect(detect.parse(lines), **kw)


def test_five_404_in_five_minutes_triggers():
    logs = [line("10.0.0.5", s, 404, f"/p{s}") for s in range(5)]
    sig = run(logs)
    assert len(sig) == 1 and sig[0]["ip"] == "10.0.0.5" and sig[0]["count"] == 5
    assert sig[0]["rule"] == "R1-enumeracion-404"


def test_four_404_do_not_trigger():
    assert run([line("10.0.0.5", s, 404) for s in range(4)]) == []


def test_404_spread_over_more_than_window_do_not_trigger():
    # 5 errores, uno cada 2 minutos: nunca hay 5 dentro de 300 s
    logs = [line("10.0.0.5", 0, 404, minute=m) for m in (0, 2, 4, 6, 8)]
    assert run(logs) == []


def test_ips_are_counted_separately():
    logs = [line(f"10.0.0.{i}", 0, 404) for i in range(10)]  # 1 error por IP
    assert run(logs) == []


def test_successful_requests_are_ignored():
    assert run([line("10.0.0.5", s, 200) for s in range(20)]) == []


def test_bruteforce_rule_counts_401_and_429():
    logs = [line("10.0.0.9", s, 401 if s < 3 else 429, "/alerts") for s in range(6)]
    sig = run(logs)
    assert [s["rule"] for s in sig] == ["R2-fuerza-bruta-401-429"] and sig[0]["count"] == 6


def test_malformed_lines_are_skipped():
    assert run(["basura", "", '1.2.3.4 - - [mala fecha] "GET / HTTP/1.1" 404 1']) == []


def test_cli_exit_codes(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("\n".join(line("10.0.0.5", s, 404) for s in range(5)), encoding="utf-8")
    assert detect.main([str(log)]) == 10
    log.write_text(line("10.0.0.5", 0, 200), encoding="utf-8")
    assert detect.main([str(log)]) == 0


def test_forbidden_rule_counts_403():
    # Un lector que insiste en escalate/close genera 403 con una clave valida.
    logs = [line("10.0.0.7", s, 403, "/alerts/x/actions") for s in range(5)]
    sig = run(logs)
    assert [s["rule"] for s in sig] == ["R3-abuso-privilegios-403"] and sig[0]["count"] == 5


def test_few_403_do_not_trigger():
    assert run([line("10.0.0.7", s, 403) for s in range(4)]) == []


# --- R4: escaneo de puertos visto por ufw (capa HOST) -------------------------------


def ufw(src, second, dpt, dst="192.168.61.129", proto="TCP", minute=0):
    return (
        f"{iso(minute, second)} lab3-server kernel: [ 100.1] "
        f"[UFW BLOCK] IN=ens33 OUT= MAC=00:0c:29:aa:bb:cc SRC={src} DST={dst} LEN=44 TOS=0x00 "
        f"PREC=0x00 TTL=40 ID=1 PROTO={proto} SPT=40000 DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0"
    )


def run_ufw(lines, **kw):
    return detect.detect(detect.parse_ufw(lines), **kw)


def test_port_scan_in_ufw_log_triggers_r4():
    sig = run_ufw([ufw("192.168.61.50", s, 1000 + s) for s in range(12)])
    assert len(sig) == 1 and sig[0]["rule"] == "R4-escaneo-ufw-block"
    assert sig[0]["ip"] == "192.168.61.50" and sig[0]["count"] == 12
    assert sig[0]["sample_requests"][0].startswith("TCP/")


def test_few_blocks_do_not_trigger_r4():
    assert run_ufw([ufw("192.168.61.50", s, 2000 + s) for s in range(4)]) == []


def test_multicast_and_broadcast_noise_is_ignored():
    noisy = [ufw("192.168.61.1", s % 50, 5353, dst="224.0.0.251", proto="UDP") for s in range(30)]
    noisy += [ufw("192.168.61.1", s % 50, 137, dst="192.168.61.255", proto="UDP") for s in range(30)]
    assert run_ufw(noisy) == []


def test_ufw_syslog_classic_timestamp_is_parsed():
    classic = [
        f"{at(0, s).strftime('%b %d %H:%M:%S')} lab3-server kernel: [1.0] [UFW BLOCK] IN=ens33 OUT= SRC=10.9.9.9 "
        f"DST=192.168.61.129 PROTO=TCP SPT=1 DPT={3000 + s}"
        for s in range(10)
    ]
    assert [x["ip"] for x in run_ufw(classic)] == ["10.9.9.9"]


def test_ufw_lines_with_forged_fields_are_skipped():
    forged = [f"{iso(micro=False)} h kernel: [UFW BLOCK] SRC=no-es-ip DST=1.2.3.4 PROTO=TCP DPT=1"] * 20
    assert run_ufw(forged) == []


def test_cli_combines_nginx_and_ufw_logs(tmp_path):
    access = tmp_path / "access.log"
    access.write_text(line("10.0.0.5", 0, 200), encoding="utf-8")
    ufw_log = tmp_path / "ufw.log"
    ufw_log.write_text(chr(10).join(ufw("10.0.0.9", s, 4000 + s) for s in range(10)), encoding="utf-8")
    assert detect.main([str(access), "--ufw-log", str(ufw_log)]) == 10
    assert detect.main([str(access), "--ufw-log", str(tmp_path / "no-existe.log")]) == 0  # R4 omitida, sin caerse


def test_signals_carry_request_ids_for_correlation():
    rid = "0123456789abcdef0123456789abcdef"
    logs = [line("10.0.0.5", s, 404, f"/p{s}") + f' rid={rid}' for s in range(5)]
    sig = run(logs)
    assert sig[0]["request_ids"] == [rid]


def test_outbound_blocks_are_not_a_scan():
    # "deny outgoing": el propio servidor aparece como SRC con IN= vacio.
    out = [
        ufw("192.168.61.129", s, 3000 + s).replace("IN=ens33 OUT=", "IN= OUT=ens33")
        for s in range(30)
    ]
    sig = run_ufw(out)
    assert [x["rule"] for x in sig] == ["R5-salida-bloqueada-ufw"]  # nunca como R4
    assert sig[0]["ip"] == "192.168.61.129" and "->192.168.61.129" in sig[0]["sample_requests"][0]


def test_few_outbound_blocks_do_not_trigger_r5():
    out = [ufw("192.168.61.129", s, 3000 + s).replace("IN=ens33 OUT=", "IN= OUT=ens33") for s in range(4)]
    assert run_ufw(out) == []


def test_outbound_multicast_is_not_r5():
    out = [
        ufw("192.168.61.129", s % 50, 5353, dst="224.0.0.251", proto="UDP").replace("IN=ens33 OUT=", "IN= OUT=ens33")
        for s in range(30)
    ]
    assert run_ufw(out) == []


def test_state_file_does_not_repeat_reported_signals(tmp_path):
    access = tmp_path / "access.log"
    access.write_text(chr(10).join(line("10.0.0.5", s, 404, f"/x{s}") for s in range(6)), encoding="utf-8")
    state = tmp_path / "state.json"
    args = [str(access), "--state-file", str(state)]
    assert detect.main(args) == 10  # primera vez: senal
    assert detect.main(args) == 0  # mismo log: ya reportada
    with access.open("a", encoding="utf-8") as fh:  # ataque nuevo, posterior
        fh.write(chr(10) + chr(10).join(line("10.0.0.5", s, 404, f"/y{s}", minute=30) for s in range(6)))
    assert detect.main(args) == 10
    state.write_text("{no es json", encoding="utf-8")  # estado corrupto: se trata como vacio
    assert detect.main(args) == 10


# --- R6: punteria contra una cuenta (audit log) --------------------------------------------------


def audit(account, minute, ip="198.51.100.9", action="login_failed", second=0):
    return json.dumps({
        "timestamp": iso(minute % 60, second), "action": action,
        "method": "POST", "path": "/auth/login", "client_ip": ip, "actor": f"login:{account}",
        "result": "unauthorized", "request_id": "0" * 32,
    })


def run_audit(lines, **kw):
    return detect.detect(detect.parse_audit(lines), **kw)


def test_slow_distributed_attack_on_one_account_triggers_r6():
    # Un fallo cada 4 minutos desde IP distintas: por debajo de cualquier umbral por IP.
    lines = [audit("marta", m * 4, ip=f"203.0.113.{m}") for m in range(12)]
    sig = run_audit(lines)
    assert len(sig) == 1 and sig[0]["rule"] == "R6-punteria-contra-cuenta"
    assert sig[0]["ip"] == "login:marta" and sig[0]["count"] >= 10
    assert len(set(sig[0]["sample_requests"])) >= 1  # IP de origen como evidencia


def test_failures_spread_over_many_accounts_do_not_trigger_r6():
    lines = [audit(f"usuario{m}", m) for m in range(30)]
    assert run_audit(lines) == []


def test_r6_ignores_other_actions_and_malformed_lines():
    lines = [audit("marta", m, action="login_ok") for m in range(20)] + ["no es json", "{}", '{"action": 1}']
    assert run_audit(lines) == []


def test_cli_reads_audit_log(tmp_path):
    access = tmp_path / "access.log"
    access.write_text(line("10.0.0.5", 0, 200), encoding="utf-8")
    log = tmp_path / "actions.log"
    log.write_text("\n".join(audit("marta", m * 2) for m in range(12)), encoding="utf-8")
    assert detect.main([str(access), "--audit-log", str(log)]) == 10
    assert detect.main([str(access), "--audit-log", str(tmp_path / "no-existe.log")]) == 0


# --- R7: eventos del WAF (error.log de Nginx con ModSecurity) -------------------------------------


def _rid(ip, minute, second):
    return ("%032x" % (abs(hash((ip, minute, second))) % (16 ** 32)))


def modsec_line(ip, minute, second, kind, rule_id, uri, rid, data=""):
    """Una linea de ModSecurity en el error.log de Nginx (una por regla coincidente)."""
    ts = at(minute, second).strftime("%Y/%m/%d %H:%M:%S")
    return (f'{ts} [error] 12#12: *7 [client {ip}] ModSecurity: {kind} (phase 2). '
            f'Matched "Operator" [file "x.conf"] [line "1"] [id "{rule_id}"] [msg "..."] [data "{data}"] '
            f'[severity "2"] [tag "attack"] [uri "{uri}"] [unique_id "{rid}"], client: {ip}, '
            f'server: _, request: "POST {uri} HTTP/1.1", host: "192.168.61.129:443"')


def waf(ip, minute, second=0, ids=("949110",), uri="/alerts", rid=None, blocked=True, data=""):
    """Las lineas de error.log de UNA peticion. En bloqueo: una linea "Access denied" con 949110. En
    deteccion: una "Warning" por cada regla. Cada peticion lleva su propio unique_id."""
    rid = rid if rid is not None else _rid(ip, minute, second)
    out = []
    for rule_id in ids:
        kind = "Access denied with code 403" if (blocked and rule_id in ("949110", "959100")) else "Warning"
        out.append(modsec_line(ip, minute, second, kind, rule_id, uri, rid, data))
    return out


def run_waf(requests, **kw):
    lines = [ln for req in requests for ln in (req if isinstance(req, list) else [req])]
    return detect.detect(detect.parse_waf(lines), **kw)


def test_waf_blocks_from_one_ip_trigger_r7():
    sig = run_waf([waf("203.0.113.7", 0, s) for s in range(5)])
    assert len(sig) == 1 and sig[0]["rule"] == "R7-waf-crs"
    assert sig[0]["ip"] == "203.0.113.7" and sig[0]["count"] == 5 and sig[0]["blocked"] == 5
    assert sig[0]["sample_requests"] == ["/alerts [949110]"]
    assert len(sig[0]["request_ids"]) >= 1 and all(len(r) == 32 for r in sig[0]["request_ids"])


def test_r7_distinguishes_blocked_from_detected():
    blocked = run_waf([waf("203.0.113.7", 0, s) for s in range(5)])          # Access denied (949110)
    assert blocked[0]["blocked"] == 5
    # Modo deteccion: solo "Warning", ninguna "Access denied".
    detected = run_waf([waf("203.0.113.8", 0, s, ids=("942100", "942190"), blocked=False) for s in range(5)])
    assert detected[0]["count"] == 5 and detected[0]["blocked"] == 0
    assert detected[0]["sample_requests"] == ["/alerts [942100,942190]"]


def test_r7_groups_error_log_lines_by_request():
    # Una sola peticion con tres reglas (tres lineas, mismo unique_id) = un evento con tres IDs.
    one = waf("203.0.113.7", 0, 0, ids=("942100", "942190", "949110"))
    assert len(one) == 3
    sig = run_waf([one] + [waf("203.0.113.7", 0, s) for s in range(1, 5)])
    assert sig[0]["count"] == 5  # cinco peticiones, no siete lineas
    assert sig[0]["sample_requests"][0].startswith("/alerts [949110")


def test_app_403_is_not_a_waf_event():
    # Un 403 de la aplicacion (denegacion por rol) no escribe lineas de ModSecurity: no es evento R7.
    app403 = [f'2026/10/14 12:00:0{s} [error] 1#1: *1 upstream sent 403 [client 203.0.113.7] '
              f'while reading response, request: "POST /alerts/x/actions HTTP/1.1"' for s in range(10)]
    assert run_waf(app403) == []
    # Mezcla: 5 bloqueos reales del WAF + 10 lineas de 403 de la app -> R7 cuenta solo los 5 bloqueos.
    mixed = [waf("203.0.113.7", 0, s) for s in range(5)]
    sig = detect.detect(detect.parse_waf(app403 + [ln for r in mixed for ln in r]))
    assert len(sig) == 1 and sig[0]["count"] == 5 and sig[0]["blocked"] == 5


def test_few_waf_events_do_not_trigger_r7():
    assert run_waf([waf("203.0.113.7", 0, s) for s in range(4)]) == []
    assert run_waf([waf("203.0.113.7", m * 10) for m in range(5)]) == []  # fuera de la ventana de 5 min


def test_r7_signal_never_copies_request_data():
    secret = "S3cr3t-Pass!"
    reqs = [waf("203.0.113.7", 0, s, ids=("942100", "949110"), uri="/auth/login?token=eyJhbGciOi&x=1",
                data=f"Matched Data: {secret} found within ARGS:json.password", blocked=True) for s in range(6)]
    out = json.dumps(run_waf(reqs))
    assert secret not in out and "eyJhbGciOi" not in out and "Matched" not in out
    assert "/auth/login [949110,942100]" in out  # ruta sin query string, regla de bloqueo primero


def test_r7_ignores_malformed_lines():
    bad_ip = waf("no-es-ip", 0, 0)
    bad_id = [modsec_line("203.0.113.8", 0, s, "Access denied with code 403", "94x; rm -rf /", "/alerts",
                          _rid("203.0.113.8", 0, s)) for s in range(10)]
    junk = ["no es una linea", "", "2026/13/40 99:99:99 nada"]
    assert run_waf([bad_ip]) == []          # IP invalida: se descarta
    sig = detect.detect(detect.parse_waf(bad_id + junk))
    # Las lineas con id invalido siguen siendo bloqueos (Access denied) pero sin ID valido.
    assert sig and sig[0]["sample_requests"] == ["/alerts [bloqueado]"]


def test_r7_sanitizes_path_and_request_id():
    reqs = [waf("203.0.113.7", 0, s, uri="/x\x1b[31m\u202e", rid="no-es-un-id") for s in range(5)]
    sig = run_waf(reqs)
    assert sig[0]["sample_requests"] == ["/x?[31m? [949110]"]
    assert sig[0]["request_ids"] == []  # unique_id invalido no se reporta


def test_cli_reads_waf_log_with_state(tmp_path):
    access = tmp_path / "access.log"
    access.write_text(line("10.0.0.5", 0, 200), encoding="utf-8")
    log = tmp_path / "error.log"
    log.write_text(chr(10).join(ln for s in range(5) for ln in waf("203.0.113.7", 0, s)), encoding="utf-8")
    state = tmp_path / "state.json"
    args = [str(access), "--waf-log", str(log), "--state-file", str(state)]
    assert detect.main(args) == 10
    assert detect.main(args) == 0  # ya reportada
    assert detect.main([str(access), "--waf-log", str(tmp_path / "no-existe.log")]) == 0  # R7 omitida
    assert detect.main([str(access), "--waf-log", str(log), "--waf-threshold", "6"]) == 0
