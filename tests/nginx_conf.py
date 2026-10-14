"""Lectura minima de nginx/muvautomation.conf para los tests: bloques por su cabecera y directivas
de primer nivel de cada bloque (sin entrar en los bloques anidados). No sustituye a nginx -t."""
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent / "nginx" / "muvautomation.conf"


def site_text() -> str:
    """El archivo sin las lineas de comentario."""
    lines = SITE.read_text(encoding="utf-8").splitlines()
    return "\n".join("" if line.lstrip().startswith("#") else line for line in lines)


def _block_at(text: str, open_brace: int) -> str:
    depth, i = 1, open_brace + 1
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[open_brace + 1 : i - 1]


def blocks(text: str, header: str) -> list[str]:
    """Contenido de cada bloque cuya cabecera es exactamente `header` (p. ej. "location ^~ /app/")."""
    found, start = [], 0
    while True:
        i = text.find(header + " {", start)
        if i < 0:
            return found
        before = text[i - 1] if i else "\n"
        if before in " \t\n;{}":
            found.append(_block_at(text, i + len(header) + 1))
        start = i + 1


def block(text: str, header: str) -> str:
    found = blocks(text, header)
    assert len(found) == 1, (header, len(found))
    return found[0]


def top_level(body: str) -> list[str]:
    """Directivas del bloque (sin las de los bloques anidados), normalizadas a un espacio."""
    statements, current, depth, quote = [], [], 0, None
    for c in body:
        if quote:  # dentro de comillas: { } ; son texto (p. ej. los ; de una CSP)
            if depth == 0:
                current.append(c)
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            if depth == 0:
                current.append(c)
        elif c == "{":
            depth += 1
            if depth == 1:
                current = []  # cabecera de un bloque anidado: no es una directiva
        elif c == "}":
            depth -= 1
        elif depth == 0:
            if c == ";":
                statements.append(" ".join("".join(current).split()))
                current = []
            else:
                current.append(c)
    return [s for s in statements if s]


def headers(body: str) -> dict[str, str]:
    """add_header de primer nivel: {nombre: valor sin comillas}."""
    out = {}
    for statement in top_level(body):
        if statement.startswith("add_header "):
            _, name, rest = statement.split(" ", 2)
            out[name] = rest.removesuffix(" always").strip('"')
    return out


def https_server(text: str) -> str:
    servers = [b for b in blocks(text, "server") if "listen 443" in b]
    assert len(servers) == 1
    return servers[0]


def http_server(text: str) -> str:
    servers = [b for b in blocks(text, "server") if "listen 80" in b]
    assert len(servers) == 1
    return servers[0]
