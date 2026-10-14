"""Invariantes de la configuracion del WAF (nginx/modsecurity/): modo, privacidad del audit log y carga.

No ejecutan ModSecurity (eso se verifica en la VM): fijan en el repo las decisiones que no deben
cambiar sin darse cuenta, sobre todo que el audit log no pueda contener secretos.
"""
import re
from pathlib import Path

import nginx_conf

ROOT = Path(__file__).resolve().parent.parent
WAF = ROOT / "nginx" / "modsecurity"


def directives(name):
    """Lineas de configuracion sin comentarios, con las continuaciones (\\ al final) unidas."""
    text = (WAF / name).read_text(encoding="utf-8")
    text = re.sub(r"\\\n\s*", "", text)
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def value(name, directive):
    found = [ln.split(None, 1)[1] for ln in directives(name) if ln.split(None, 1)[0] == directive]
    assert len(found) == 1, (directive, found)
    return found[0].strip('"')


def test_engine_blocks_by_default():
    # Etapa I: el valor del repo es el seguro (bloqueo). harden-host.sh con WAF_MODE=detection lo
    # cambia a DetectionOnly en el despliegue; el archivo versionado nunca debe quedar en detection.
    assert value("modsecurity.conf", "SecRuleEngine") == "On"


def test_harden_host_has_waf_mode_switch():
    harden = (ROOT / "deploy" / "harden-host.sh").read_text(encoding="utf-8")
    assert 'WAF_MODE="${WAF_MODE:-blocking}"' in harden
    assert "s/^SecRuleEngine On$/SecRuleEngine DetectionOnly/" in harden
    assert 'WAF_MODE debe ser blocking o detection' in harden


def test_audit_log_has_no_request_headers_body_or_response():
    parts = value("modsecurity.conf", "SecAuditLogParts")
    assert set(parts) <= set("AHZ"), parts
    assert value("modsecurity.conf", "SecAuditEngine") == "RelevantOnly"
    assert value("modsecurity.conf", "SecAuditLogFormat") == "JSON"
    assert value("modsecurity.conf", "SecResponseBodyAccess") == "Off"


def test_body_limits_match_nginx():
    site = (ROOT / "nginx" / "muvautomation.conf").read_text(encoding="utf-8")
    assert "client_max_body_size 16k;" in site
    for d in ("SecRequestBodyLimit", "SecRequestBodyNoFilesLimit"):
        assert int(value("modsecurity.conf", d)) == 16 * 1024


# Directivas de ModSecurity v2 que libmodsecurity v3 no acepta (src/parser/seclang-parser.yy de
# v3/master): con cualquiera de ellas nginx -t falla y harden-host.sh deja el sitio sin WAF.
V3_REJECTED = {
    "SecRequestBodyInMemoryLimit", "SecServerSignature", "SecCacheTransformations", "SecChrootDir",
    "SecHashKey", "SecHashParam", "SecHashMethodRx", "SecHashMethodPm", "SecGsbLookupDb",
    "SecGuardianLog", "SecConnReadStateLimit", "SecConnWriteStateLimit", "SecSensorId",
    "SecRulePerfTime", "SecStreamInBodyInspection", "SecStreamOutBodyInspection", "SecCookieV0Separator",
}
# Solo se rechazan con este valor (con Off/0 se aceptan).
V3_REJECTED_VALUE = {
    "SecConnEngine": "on", "SecContentInjection": "on", "SecHashEngine": "on", "SecInterceptOnError": "on",
    "SecRuleInheritance": "on", "SecDisableBackendCompression": "on", "SecCookieFormat": "1",
}
# v3 las acepta pero no hacen nada (el parser solo omite el error para no romper el recomendado) o
# dependen de algo que aqui no se usa: no deben aparecer para que nadie crea que tienen efecto.
V3_NO_EFFECT_OR_UNUSED = {
    "SecTmpDir", "SecStatusEngine", "SecCollectionTimeout",
    "SecDataDir",  # colecciones persistentes (LMDB): no se usan
    "SecGeoLookupDb",  # requiere libmodsecurity con GeoIP/MaxMind y una base que no se instala
    "SecUnicodeMapFile",  # requiere unicode.mapping, que no se instala
}


def test_no_modsecurity_v2_only_directives():
    for name in ("modsecurity.conf", "crs-setup.conf", "privacidad.conf", "exclusiones.conf", "main.conf"):
        for ln in directives(name):
            directive, _, rest = ln.partition(" ")
            assert directive not in V3_REJECTED, (name, directive)
            assert directive not in V3_NO_EFFECT_OR_UNUSED, (name, directive)
            bad = V3_REJECTED_VALUE.get(directive)
            assert bad is None or rest.strip().strip('"').lower() != bad, (name, ln)


def test_json_depth_limit_is_low():
    # Los cuerpos de la API son objetos planos; el recomendado de v3 usa 512.
    assert 2 <= int(value("modsecurity.conf", "SecRequestBodyJsonDepthLimit")) <= 32


def test_json_body_processor_for_application_json_and_plus_json():
    rule = next(ln for ln in directives("modsecurity.conf") if "id:200001" in ln)
    assert "ctl:requestBodyProcessor=JSON" in rule and "t:lowercase" in rule
    pattern = re.compile(re.search(r'"@rx ([^"]+)"', rule).group(1))
    # La cabecera llega en minusculas (t:lowercase): se prueba con el valor ya transformado.
    for ctype in ("application/json", "application/json; charset=utf-8", "application/vnd.prueba+json",
                  "application/problem+json"):
        assert pattern.search(ctype), ctype
    for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data", "text/json"):
        assert not pattern.search(ctype), ctype


def test_body_parse_error_does_not_log_the_body_fragment():
    rule = next(ln for ln in directives("modsecurity.conf") if "id:200002" in ln)
    assert "logdata" not in rule and "reqbody_error_msg" not in rule.lower()


def test_secrets_are_never_inspected_by_crs():
    rules = " ".join(directives("privacidad.conf"))
    for field in ("password", "otp", "refresh_token"):
        for name in (field, f"json.{field}"):
            assert f"ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:{name}," in rules + ",", name
    assert "^/auth/(?:login|refresh|logout)$" in rules
    for header in ("Authorization", "Proxy-Authorization", "X-API-Key", "X-Analyst-Key", "Cookie"):
        for name in (header, header.lower()):
            assert f"ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:{name}" in rules, name


def test_crs_paranoia_level_one_and_setup_version():
    setup = " ".join(directives("crs-setup.conf"))
    assert "setvar:tx.paranoia_level=1" in setup
    assert "setvar:tx.crs_setup_version=" in setup
    assert "anomaly_score_threshold" not in setup  # umbrales por defecto de CRS


def test_load_order_privacy_before_crs_and_exclusions_after():
    includes = [ln.split(None, 1)[1] for ln in directives("main.conf") if ln.startswith("Include ")]
    names = [Path(i).name for i in includes]
    assert names == ["modsecurity.conf", "crs-setup.conf", "privacidad.conf", "*.conf", "exclusiones.conf"]
    assert includes[3].endswith("/rules/*.conf")


def test_waf_covers_the_whole_https_server():
    text = nginx_conf.site_text()
    https = nginx_conf.https_server(text)
    waf = "include /etc/nginx/fdsi-lab3-waf.d/*.conf"
    # G-1: a nivel del server :443 (API, / y frontend), una sola vez y no repetido en ningun location.
    assert waf in nginx_conf.top_level(https)
    assert https.count("fdsi-lab3-waf.d") == 1
    for header in ("location /", "location ^~ /app/", "location = /"):
        assert "fdsi-lab3-waf.d" not in nginx_conf.block(https, header), header
    http = nginx_conf.http_server(text)
    assert "fdsi-lab3-waf.d" not in http and "modsecurity" not in http
    snippet = directives("waf.conf")
    assert "modsecurity on;" in snippet
    assert "modsecurity_rules_file /etc/nginx/fdsi-lab3-modsecurity/main.conf;" in snippet


# --- Etapa I: bloqueo, exclusiones por ruta y campo, metodos y tipos -------------------------------

ATTACK_FAMILIES = ("attack-sqli", "attack-xss", "attack-rce", "attack-lfi")


def test_only_global_removal_is_920350():
    # SecRuleRemoveById/ByTag globales: solo 920350 (Host por IP). Nunca una familia de ataque entera.
    for ln in directives("exclusiones.conf"):
        if ln.startswith(("SecRuleRemoveById", "SecRuleRemoveByTag", "SecRuleRemoveByMsg")):
            assert ln == "SecRuleRemoveById 920350", ln
    # Ninguna familia de ataque se quita de forma global (siempre con ;ARGS:json.<campo>).
    text = (WAF / "exclusiones.conf").read_text(encoding="utf-8")
    for family in ATTACK_FAMILIES:
        for m in re.finditer(r"ruleRemoveTargetByTag=" + re.escape(family) + r"(;ARGS:[^,\"\s]+)?", text):
            assert m.group(1), f"{family} sin campo concreto"


def test_field_exclusions_are_bound_to_a_route():
    # Cada SecRule con ctl:ruleRemoveTarget* debe filtrar por REQUEST_FILENAME (una ruta concreta).
    text = re.sub(r"\\n\s*", " ", (WAF / "exclusiones.conf").read_text(encoding="utf-8"))
    for block in re.findall(r"SecRule[^\n]*ruleRemoveTargetByTag[^\n]*", text):
        assert "REQUEST_FILENAME" in block
        assert "/alerts" in block
        # Solo se excluyen los campos de texto libre, por nombre json.<campo>.
        targets = set(re.findall(r"ARGS:(json\.[a-z_]+)", block))
        assert targets <= {"json.description", "json.technique", "json.tactic", "json.note"}, targets
        # Nunca se excluyen campos sensibles ni de control.
        assert not (targets & {"json.severity", "json.source_ip", "json.hostname"})


def test_allowed_methods_and_content_type_restricted():
    setup = re.sub(r"\\n\s*", " ", (WAF / "crs-setup.conf").read_text(encoding="utf-8"))
    assert "setvar:'tx.allowed_methods=GET HEAD POST'" in setup
    assert "setvar:'tx.allowed_request_content_type=|application/json|'" in setup


def test_blocked_response_is_small_generic_json():
    https = nginx_conf.https_server(nginx_conf.site_text())
    assert "error_page 403 = @blocked" in nginx_conf.top_level(https)
    blocked = nginx_conf.top_level(nginx_conf.block(https, "location @blocked"))
    assert "internal" in blocked
    assert 'default_type application/json' in blocked
    assert any(d.startswith("return 403 ") and "Request blocked" in d for d in blocked)
    # No revela la regla ni menciona el WAF.
    body = (ROOT / "nginx" / "muvautomation.conf").read_text(encoding="utf-8")
    assert "modsec" not in nginx_conf.block(https, "location @blocked").lower()
