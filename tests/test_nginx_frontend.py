"""Etapa G: location del frontend en nginx/muvautomation.conf (CSP propia, cabeceras, solo estaticos)."""
import re

import nginx_conf

FRONTEND_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'"
)


# --- Nginx: location del frontend ------------------------------------------------------------------


def app_location():
    return nginx_conf.block(nginx_conf.https_server(nginx_conf.site_text()), "location ^~ /app/")


def test_frontend_csp_only_in_its_location():
    https = nginx_conf.https_server(nginx_conf.site_text())
    assert nginx_conf.headers(app_location())["Content-Security-Policy"] == FRONTEND_CSP
    # La API conserva la suya.
    assert nginx_conf.headers(https)["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_frontend_location_repeats_every_server_security_header():
    # add_header dentro de un location anula TODAS las del server: deben repetirse.
    server = nginx_conf.headers(nginx_conf.https_server(nginx_conf.site_text()))
    location = nginx_conf.headers(app_location())
    assert set(server) <= set(location), set(server) - set(location)
    for name, value in server.items():
        if name not in ("Content-Security-Policy", "Cache-Control"):
            assert location[name] == value, name
    assert server["Cache-Control"] == "no-store" and location["Cache-Control"] == "no-cache"


def test_frontend_location_is_static_only():
    body = app_location()
    statements = nginx_conf.top_level(body)
    assert "alias /var/www/fdsi-lab3/" in statements
    assert re.search(r"limit_except GET \{\s*deny all;\s*\}", body)  # HEAD va incluido en GET
    assert "proxy_pass" not in body and "fdsi-lab3-waf.d" not in body and "modsecurity" not in body
    assert "zone=muv_api" not in body and "zone=muv_auth" not in body
    assert "limit_req zone=muv_static burst=40 nodelay" in statements


def test_root_redirects_to_the_console_without_host_header():
    https = nginx_conf.https_server(nginx_conf.site_text())
    root = nginx_conf.top_level(nginx_conf.block(https, "location = /"))
    assert root == ["absolute_redirect off", "return 302 /app/"]
