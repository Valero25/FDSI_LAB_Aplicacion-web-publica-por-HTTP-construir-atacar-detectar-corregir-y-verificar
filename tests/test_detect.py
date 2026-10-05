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
