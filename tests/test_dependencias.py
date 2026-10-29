"""SCA (laboratorio FSI, H-4): el entorno que corre las pruebas usa exactamente las versiones fijadas.

Un venv viejo (FastAPI 0.115 / Starlette 0.38.6) seguia funcionando en local con 35 CVE conocidos,
entre ellos el del Host header que falseaba la ruta del audit log. Si el entorno no coincide con
app/requirements.txt, las pruebas fallan aqui en lugar de pasar sobre dependencias vulnerables.
"""
from importlib.metadata import version
from pathlib import Path

import pytest

REQUIREMENTS = Path(__file__).resolve().parent.parent / "app" / "requirements.txt"


def pinned():
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            name, _, ver = line.partition("==")
            yield name.split("[")[0], ver


@pytest.mark.parametrize("name,expected", list(pinned()))
def test_installed_version_matches_pin(name, expected):
    assert expected, f"{name} debe ir fijado con == en app/requirements.txt"
    assert version(name) == expected, f"{name} {version(name)} instalado; requirements.txt fija {expected}"


def test_starlette_is_not_the_vulnerable_line():
    major, minor = (int(x) for x in version("starlette").split(".")[:2])
    assert (major, minor) >= (1, 3), "Starlette < 1.3: Host header altera request.url.path"
