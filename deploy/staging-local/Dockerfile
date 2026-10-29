# Staging HTTPS aislado para el DAST pasivo (laboratorio FSI, paso 5). Reproduce la cadena de la VM
# (Nginx :443 con nginx/muvautomation.conf -> uvicorn 127.0.0.1:8000) en un solo contenedor, con
# datos y claves ficticias generadas al arrancar. No incluye el WAF ni systemd: ZAP baseline es
# pasivo y lo que mide son las cabeceras y respuestas de Nginx y de la app.
#
#   docker build -f deploy/staging-local/Dockerfile -t fdsi-staging .
#   docker run --rm -d --name staging -p 127.0.0.1:8443:443 fdsi-staging
#   curl -k https://127.0.0.1:8443/app/
FROM python:3.12-slim-trixie

# trixie trae Nginx 1.26 (la configuracion usa "http2 on;", que exige >= 1.25.1).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx openssl \
    && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/default

WORKDIR /opt/fdsi-lab3
COPY app/requirements.txt app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

COPY app/ app/
COPY frontend/ /var/www/fdsi-lab3/
COPY nginx/muvautomation.conf /etc/nginx/conf.d/muvautomation.conf
COPY deploy/staging-local/entrypoint.sh /usr/local/bin/staging-entrypoint
RUN chmod 755 /usr/local/bin/staging-entrypoint \
    && useradd --system --no-create-home muvapi \
    && install -d -o muvapi -g muvapi /var/lib/muvautomation /var/log/muvautomation

EXPOSE 443
# El arranque necesita root (puerto 443, certificado y runuser); la API corre como muvapi y los
# workers de Nginx como www-data. Falso positivo aceptado de Semgrep para este contenedor de pruebas.
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint
ENTRYPOINT ["/usr/local/bin/staging-entrypoint"]
