#!/usr/bin/env bash
# Arranque del staging local: certificado autofirmado, claves ficticias aleatorias (nunca se
# guardan en el repositorio ni salen del contenedor), API en 127.0.0.1:8000 y Nginx en primer plano.
set -euo pipefail

openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=staging.local" \
    -keyout /etc/ssl/private/lab3-server.key -out /etc/ssl/certs/lab3-server.crt 2>/dev/null

rnd() { openssl rand -hex 24; }
export MUV_DATA_DIR=/var/lib/muvautomation MUV_LOG_DIR=/var/log/muvautomation
export MUV_API_KEY="$(rnd)" MUV_ANALYSTS="ana:respondedor:$(rnd);juan:lector:$(rnd)"
eval "$(cd /opt/fdsi-lab3 && python -m app.identity_cli gen-keys | sed 's/^/export /')"

cd /opt/fdsi-lab3
runuser -u muvapi -- env MUV_DATA_DIR="$MUV_DATA_DIR" MUV_LOG_DIR="$MUV_LOG_DIR" \
    MUV_API_KEY="$MUV_API_KEY" MUV_ANALYSTS="$MUV_ANALYSTS" \
    MUV_JWT_PRIVATE_KEY="$MUV_JWT_PRIVATE_KEY" MUV_TOTP_KEY="$MUV_TOTP_KEY" \
    PYTHONDONTWRITEBYTECODE=1 \
    uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 \
    --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-server-header &

nginx -t
exec nginx -g 'daemon off;'
