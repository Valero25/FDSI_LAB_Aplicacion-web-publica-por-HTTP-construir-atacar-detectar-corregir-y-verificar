"""Etapa G: reglas de seguridad del frontend (frontend/). Su location de Nginx: test_nginx_frontend.py.

Analisis estatico: fija en el repo lo que no debe cambiar sin darse cuenta (render solo como texto,
tokens solo en memoria, peticiones al mismo origen con JSON, CSP estricta). La carga real en el
navegador se comprueba en la VM.
"""
import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
JS = sorted(FRONTEND.glob("*.js"))
HTML = sorted(FRONTEND.glob("*.html"))
CSS = sorted(FRONTEND.glob("*.css"))

def read(path):
    return path.read_text(encoding="utf-8")


def code(path):
    """El JS sin comentarios: las reglas miran el codigo, no la explicacion de lo que no se usa."""
    text = re.sub(r"/\*.*?\*/", "", read(path), flags=re.S)
    return re.sub(r"(?m)(^|\s)//.*$", r"\1", text)


def test_frontend_files_exist():
    names = {p.name for p in FRONTEND.iterdir()}
    assert {"index.html", "app.js", "api.js", "dom.js", "app.css"} <= names
    # Solo lo que se publica: nada oculto ni de otro tipo que acabe en /var/www.
    assert all(p.suffix in {".html", ".js", ".css"} and not p.name.startswith(".") for p in FRONTEND.iterdir())


# --- XSS: solo texto, nunca HTML ni codigo desde cadenas ------------------------------------------

FORBIDDEN_JS = {
    "innerHTML": r"\binnerHTML\b",
    "outerHTML": r"\bouterHTML\b",
    "insertAdjacentHTML": r"\binsertAdjacentHTML\b",
    "document.write": r"\bdocument\s*\.\s*write(ln)?\b",
    "eval": r"\beval\s*\(",
    "new Function": r"\bFunction\s*\(",
    "setTimeout/setInterval con cadena": r"\bset(Timeout|Interval)\s*\(\s*[\"'`]",
    "HTML desde cadena": r"\b(setHTMLUnsafe|parseHTMLUnsafe|createContextualFragment|DOMParser)\b|\.srcdoc\b",
    "manejador on* asignado": r"\.\s*on[a-z]+\s*=",
    "estilo en linea": r"\.style\b|setAttribute\(\s*[\"']style",
    "almacenamiento del navegador": r"\b(localStorage|sessionStorage|indexedDB|caches)\b|document\s*\.\s*cookie",
    "consola": r"\bconsole\s*\.",
    "URL o historial": r"\b(location|history)\s*\.|\bwindow\s*\.\s*open\b",
    "import dinamico o externo": r"\bimport\s*\(|\bfrom\s+[\"'](?!\./)",
}


@pytest.mark.parametrize("path", JS, ids=lambda p: p.name)
@pytest.mark.parametrize("rule", FORBIDDEN_JS, ids=str)
def test_js_never_uses_forbidden_apis(path, rule):
    assert not re.search(FORBIDDEN_JS[rule], code(path)), f"{path.name}: {rule}"


def test_only_dom_js_creates_elements_and_only_with_text_content():
    for path in JS:
        if path.name != "dom.js":
            assert "createElement" not in read(path), path.name
    dom = read(FRONTEND / "dom.js")
    assert "node.textContent = String(options.text)" in dom
    # Los atributos peligrosos se rechazan aunque alguien los pida.
    assert "FORBIDDEN_ATTR" in dom and "^(on|style$|src$|srcdoc$|href$|action$|formaction$" in dom


@pytest.mark.parametrize("path", HTML, ids=lambda p: p.name)
def test_html_has_no_inline_js_css_or_handlers(path):
    html = read(path)
    assert not re.search(r"<\s*style\b", html, re.I), "bloque <style>"
    assert not re.search(r"\sstyle\s*=", html, re.I), "atributo style"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "manejador on*"
    assert not re.search(r"javascript\s*:", html, re.I)
    assert not re.search(r"<\s*base\b", html, re.I)
    # El cierre admite espacios y atributos (</script >, </script foo>), que el navegador acepta;
    # con "</script>" literal un script en linea cerrado asi escapaba a la comprobacion (CodeQL #1).
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script\b[^>]*>", html, re.I | re.S)
    assert scripts, "sin script"
    for attrs, body in scripts:
        assert body.strip() == "", "script en linea"
        assert re.search(r'\btype="module"', attrs) and re.search(r'\bsrc="[a-z]+\.js"', attrs), attrs


# --- Tokens: solo en memoria, nunca expuestos ------------------------------------------------------


def test_tokens_live_only_in_api_module_memory():
    api = read(FRONTEND / "api.js")
    assert "let accessToken = null;" in api and "let refreshToken = null;" in api
    assert not re.search(r"export\s+(let|var|const)\s+(accessToken|refreshToken)", api)
    assert not re.search(r"export\s*\{[^}]*(accessToken|refreshToken)", api)
    for path in JS + HTML:
        if path.name != "api.js":
            text = read(path)
            for name in ("accessToken", "refreshToken", "access_token", "refresh_token"):
                assert name not in text, (path.name, name)


def test_secrets_are_never_put_in_the_page_or_the_url():
    app = read(FRONTEND / "app.js")
    # La contrasena y el codigo se borran del formulario tras cada intento.
    assert app.count('passwordInput.value = ""') >= 2 and app.count('otpInput.value = ""') >= 2
    api = read(FRONTEND / "api.js")
    # Ni el token ni la contrasena viajan en la URL: solo en la cabecera Authorization o en el cuerpo.
    assert '"Bearer " + accessToken' in api
    assert not re.search(r"[?&](token|access_token|password|otp)=", api + app)


# --- Peticiones: mismo origen, JSON, sin cookies ----------------------------------------------------


def test_single_fetch_same_origin_json_without_credentials():
    calls = {p.name: len(re.findall(r"\bfetch\s*\(", read(p))) for p in JS}
    assert calls == {"api.js": 1, "app.js": 0, "dom.js": 0}
    api = read(FRONTEND / "api.js")
    assert 'credentials: "omit"' in api and 'mode: "same-origin"' in api
    assert 'headers["Content-Type"] = "application/json"' in api
    assert 'if (!path.startsWith("/") || path.startsWith("//"))' in api
    assert "XMLHttpRequest" not in api and "WebSocket" not in api


def test_api_paths_used_are_real_endpoints():
    app = read(FRONTEND / "app.js") + read(FRONTEND / "api.js")
    used = set(re.findall(r'"(/(?:alerts|auth|network)[^"?]*)', app))
    assert used == {"/alerts", "/alerts/", "/auth/login", "/auth/refresh", "/auth/logout",
                    "/network/devices", "/network/devices/"}, used


# --- Formulario de login ---------------------------------------------------------------------------


def test_login_form_autocomplete_and_method():
    html = read(FRONTEND / "index.html")
    form = re.search(r'<form id="login-form"[^>]*>', html).group(0)
    assert 'method="post"' in form  # sin JS, la contrasena nunca iria en la URL
    for field, value in (("login-username", "username"), ("login-password", "current-password"),
                         ("login-otp", "one-time-code")):
        tag = re.search(rf'<input id="{field}"[^>]*>', html, re.S).group(0)
        assert f'autocomplete="{value}"' in tag, field
    assert 'type="password"' in re.search(r'<input id="login-password"[^>]*>', html, re.S).group(0)


# --- Sin recursos externos --------------------------------------------------------------------------

EXTERNAL = re.compile(r"(?i)\b(?:https?|wss?|ftp):|(?<![\w:])//[a-z0-9-]+\.[a-z]")


@pytest.mark.parametrize("path", JS + HTML + CSS, ids=lambda p: p.name)
def test_no_external_urls(path):
    text = read(path)
    assert not EXTERNAL.search(text), EXTERNAL.search(text)
    if path.suffix == ".css":
        assert "@import" not in text and "url(" not in text
