# Registro de riesgos: endurecimiento adicional (Lab 3, Parte 2+)

Estados: **Corregido** (verificado) · **Mitigado** · **Aceptado** · **Pendiente** (Lab 4).
"Verificación local" = probado en el equipo de desarrollo. "Servidor" = hay que comprobarlo en `lab3-server`.

| ID | Riesgo (STRIDE) | Corrección | Verificación | Estado |
|---|---|---|---|---|
| V0a | Fuerza bruta contra `X-API-Key` / `X-Analyst-Key` (S, E) | Bloqueo por IP: 5 fallos en 5 min → 429 con `Retry-After`; registro `locked_out` | Pruebas + servidor uvicorn real (4×401 → 429, incluso con clave válida) | Corregido |
| V0b | IP falsificable con `X-Forwarded-For` (R, S) | Nginx sobrescribe con `$remote_addr` | Observado: uvicorn confía en 127.0.0.1, por eso la corrección va en Nginx | Corregido (servidor: confirmar) |
| V0c | `acknowledge` degradaba una alerta escalada (T) | No cambia el estado si ya está `escalated` | Prueba automática | Corregido |
| V0d | Dependencias con CVE (Starlette) (D, E) | `fastapi==0.142.2`, `uvicorn==0.40.0` | `pip-audit`: 0 vulnerabilidades | Corregido |
| V1 | Redirección abierta por `Host` en `:80` (S) | `return 301 https://192.168.61.129$request_uri` | `nginx -t` OK en contenedor; `curl -H "Host: evil.com" http://…` → 301 a `https://192.168.61.129/…` | Corregido |
| V2 | Código de la app escribible por el servicio → persistencia tras RCE (T, E) | DB y logs en `/var/lib` y `/var/log` (`MUV_DATA_DIR`, `MUV_LOG_DIR`); sin `ReadWritePaths` | Prueba de arranque con las variables; el resto en servidor | Mitigado (servidor: `harden-host.sh`) |
| V3 | Usuario compartido con Nginx (E) | Usuario `muvapi` sin shell; `/etc/muvautomation.env` 0600 root | Solo servidor | Mitigado |
| V4 | Agotamiento de disco con clave de emisor filtrada (D) | Tope 50 000 alertas (507) y 200 acciones por alerta (409) | Pruebas automáticas | Corregido |
| V5 | SQLite bloqueada bajo concurrencia (D) | WAL, `busy_timeout` 10 s, `foreign_keys=ON` | 800 peticiones concurrentes: 0 errores `database is locked` | Corregido |
| V6 | El tope de la tabla de bloqueos la vaciaba (D, E) | Se descarta solo la entrada más antigua | Prueba con 10 000 IP | Corregido |
| V7 | Claves repetidas o emisor = analista (E, R) | La app no arranca si hay duplicados | Prueba automática | Corregido |
| V8 | `alert_id` sin validar (T, R) | Patrón UUID, 422 si no cumple | Prueba automática | Corregido |
| V9 | Permisos de DB y logs (I) | DB `0600`, `UMask=0027`, directorios `0750` | Local: `chmod`; permisos reales en servidor | Mitigado |
| V10 | Logs sin rotación (D) | `deploy/logrotate-muvautomation` | Solo servidor (`logrotate -d`) | Mitigado |
| V11 | Sin límites de concurrencia en uvicorn (D) | `--limit-concurrency 100 --timeout-keep-alive 5 --workers 1` | Arranque local con esos flags | Corregido |
| V12 | Bloqueo solo en memoria (D) | `fail2ban` con filtro sobre `actions.log` | Regex probado con líneas reales; jail solo en servidor | Mitigado |
| V13 | Proxy HTTP/1.0 al backend (T) | `proxy_http_version 1.1`, `Connection ""` | `nginx -t` OK y proxy funcional en contenedor | Corregido |
| V14 | SSH y firewall sin comprobar (S, E) | `harden-host.sh` + `sshd-hardening.conf`, con protección contra autobloqueo | `bash -n`; ejecución en servidor | Pendiente de ejecución |
| V15 | Clave privada TLS con permisos amplios (I) | `0640 root:ssl-cert` | Solo servidor | Pendiente de ejecución |
| D1 | Detección del Paso 13 | `scripts/detect.py`: ≥5 respuestas 404 o ≥5 401/429 por IP en 5 min | 8 pruebas + log de ejemplo (señal correcta, sin falsos positivos en la IP normal) | Corregido |

## Riesgos aceptados o pendientes para el Lab 4

| Riesgo | Motivo | Estado |
|---|---|---|
| Certificado autofirmado | Es un laboratorio; sin CA propia | Aceptado |
| Claves en texto plano en el archivo de entorno | Falta hash y rotación | Pendiente Lab 4 |
| Sin mTLS para el emisor (Falcon) | Requiere CA propia | Pendiente Lab 4 |
| Sin hash encadenado en logs y DB | Integridad criptográfica | Pendiente Lab 4 |
| Bloqueo anti fuerza bruta no persistente entre reinicios | Reducido con fail2ban | Mitigado |
| Descripciones de alertas con HTML se guardan sin escapar | Solo JSON con CSP `default-src 'none'`; escapar si hay front-end | Aceptado |
| Migración a microservicios | Aumenta la superficie (broker, DB de red); no lo pide el Lab 3 | Descartado, ver evolución arquitectónica |

## Límites de la verificación
`nginx -t` y la prueba funcional de Nginx (headers sin duplicar, 403/404/413, rate limit 429, TLS, XFF falsificado) se ejecutaron en contenedor Docker. No se pudo ejecutar en local: `systemd-analyze`, `ufw`, `sshd -t` y `fail2ban` reales. Esos puntos quedan como "Servidor" y se comprueban con el retest.
