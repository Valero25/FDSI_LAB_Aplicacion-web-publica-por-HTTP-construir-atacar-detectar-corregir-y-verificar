#!/usr/bin/env bash
# Validacion manual del hallazgo H-3 (laboratorio FSI): una cabecera Host manipulada no debe cambiar
# la ruta ni la accion del audit log. Peticiones inocuas a una API local con datos ficticios; nada
# sale del contenedor. OLD=1 instala la version vulnerable de Starlette (la del venv local antiguo).
#
#   docker run --rm -v "$PWD:/src:ro" -w /src python:3.12-slim bash deploy/staging-local/validar-host-header.sh
#   docker run --rm -e OLD=1 -v "$PWD:/src:ro" -w /src python:3.12-slim bash deploy/staging-local/validar-host-header.sh
set -e
pip install -q -r app/requirements.txt 2>/dev/null
if [ -n "${OLD:-}" ]; then pip install -q "fastapi==0.115.0" "starlette==0.38.6" 2>/dev/null; fi
python -c "import starlette,fastapi;print('starlette',starlette.__version__,'fastapi',fastapi.__version__)"
MUV_DATA_DIR=$(mktemp -d) MUV_LOG_DIR=$(mktemp -d)
MUV_API_KEY=$(python -c "import secrets;print(secrets.token_hex(16))")
export MUV_DATA_DIR MUV_LOG_DIR MUV_API_KEY
uvicorn app.main:app --host 127.0.0.1 --port 8000 >/dev/null 2>&1 &
sleep 4
python - <<'PY'
import http.client
for host in ("127.0.0.1:8000", "lab/auth/refresh?"):
    c = http.client.HTTPConnection("127.0.0.1", 8000)
    c.request("POST", "/auth/login", body="{bad", headers={"Host": host, "Content-Type": "application/json"})
    print(f"POST /auth/login  Host: {host!r:22} -> {c.getresponse().status}")
PY
sleep 1
echo "actions.log:"
grep -h -E "login_failed|refresh_failed" "$MUV_LOG_DIR"/*.log | sed -E 's/"client_ip": "[^"]*"/"client_ip": "..."/'
