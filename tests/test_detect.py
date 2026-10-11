"""Pruebas de la regla de deteccion (scripts/detect.py): umbral, ventana, falsos positivos."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "detect", Path(__file__).resolve().parent.parent / "scripts" / "detect.py"
)
detect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detect)


def line(ip, second, status, path="/x", minute=0):
    ts = f"05/Oct/2026:10:{minute:02d}:{second:02d} +0000"
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
    assert detect.main([str(log)]) == 2
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
        f"2026-10-11T12:{minute:02d}:{second:02d}.000000+00:00 lab3-server kernel: [ 100.1] "
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
    assert run_ufw([ufw("192.168.61.50", s, 2000 + s) for s in range(9)]) == []


def test_multicast_and_broadcast_noise_is_ignored():
    noisy = [ufw("192.168.61.1", s % 50, 5353, dst="224.0.0.251", proto="UDP") for s in range(30)]
    noisy += [ufw("192.168.61.1", s % 50, 137, dst="192.168.61.255", proto="UDP") for s in range(30)]
    assert run_ufw(noisy) == []


def test_ufw_syslog_classic_timestamp_is_parsed():
    classic = [
        f"Oct 11 12:00:{s:02d} lab3-server kernel: [1.0] [UFW BLOCK] IN=ens33 OUT= SRC=10.9.9.9 "
        f"DST=192.168.61.129 PROTO=TCP SPT=1 DPT={3000 + s}"
        for s in range(10)
    ]
    assert [x["ip"] for x in run_ufw(classic)] == ["10.9.9.9"]


def test_ufw_lines_with_forged_fields_are_skipped():
    forged = ["2026-10-11T12:00:00+00:00 h kernel: [UFW BLOCK] SRC=no-es-ip DST=1.2.3.4 PROTO=TCP DPT=1"] * 20
    assert run_ufw(forged) == []


def test_cli_combines_nginx_and_ufw_logs(tmp_path):
    access = tmp_path / "access.log"
    access.write_text(line("10.0.0.5", 0, 200), encoding="utf-8")
    ufw_log = tmp_path / "ufw.log"
    ufw_log.write_text(chr(10).join(ufw("10.0.0.9", s, 4000 + s) for s in range(10)), encoding="utf-8")
    assert detect.main([str(access), "--ufw-log", str(ufw_log)]) == 2
    assert detect.main([str(access), "--ufw-log", str(tmp_path / "no-existe.log")]) == 0  # R4 omitida, sin caerse


def test_signals_carry_request_ids_for_correlation():
    rid = "0123456789abcdef0123456789abcdef"
    logs = [line("10.0.0.5", s, 404, f"/p{s}") + f' rid={rid}' for s in range(5)]
    sig = run(logs)
    assert sig[0]["request_ids"] == [rid]
