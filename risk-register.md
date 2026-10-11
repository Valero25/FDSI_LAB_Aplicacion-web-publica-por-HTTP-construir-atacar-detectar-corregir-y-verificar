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
| B1 | Texto libre con ANSI, NUL, saltos o direccionalidad (U+202E) se almacenaba tal cual (T, R) | Rechazo 422 de caracteres de control y bidi en `tactic`/`technique`/`hostname`; `description` y `note` permiten `
` y tabulador | 5 pruebas + sonda previa que demostraba la aceptación | Corregido |
| B2 | El 422 de FastAPI reflejaba el valor enviado (incluida una clave casi correcta) (I) | Manejador propio: solo `loc`, `msg` y `type` | Prueba automática | Corregido |
| B3 | Rotar direcciones de un /64 IPv6 evadía el bloqueo por IP (S, D) | La clave de bloqueo agrupa IPv6 por /64 y normaliza IPv4 mapeada | Prueba automática | Corregido |
| B4 | Una clave de emisor filtrada llenaba la cuota de 50 000 alertas en minutos (D) | Tope global de ingesta 300/min (`MUV_MAX_INGEST_PER_MIN`), 429 con `Retry-After`; aviso de cuota al 90 % | Prueba automática | Mitigado |
| B5 | URL largos inflaban `actions.log` (D) | `path` truncado a 256 caracteres | Prueba automática | Corregido |
| B6 | ZAP pasivo: aislamiento Spectre incompleto; exceso de conexiones devolvía 503 (R) | `Cross-Origin-Embedder-Policy`, `limit_conn_status 429`, `reset_timedout_connection`, `autoindex off` | `nginx -t` y prueba funcional en Docker | Corregido |
| B7 | Inventario de red de solo lectura (Lab 3, línea Network Automation Hub) | `GET /network/devices[/{id}]`, datos ficticios TEST-NET-1, sin credenciales ni escritura | 4 pruebas (auth, filtro, solo lectura, id validado) | Corregido |
| B8 | Host: kernel/red permisivo (E, D) | `sysctl-hardening.conf` (syncookies, rp_filter, sin redirects, kptr/dmesg/ptrace/bpf) | Solo servidor | Mitigado (servidor: ejecutar) |
| B9 | SSH: fuerza bruta y opciones por defecto (S) | `ufw limit` en 22, fail2ban `sshd` (3 intentos), `MaxSessions`, `PermitTunnel no`, `LogLevel VERBOSE`, etc. | `sshd -t` OK en contenedor Ubuntu 24.04; efecto real solo en servidor | Mitigado (servidor: ejecutar) |
| B10 | Manipulación del host sin rastro (T, R) | Reglas `auditd` sobre secretos, código, configuración defensiva e identidad (`deploy/audit/lab3.rules`) | Solo servidor (`ausearch -k lab3_*`) | Mitigado (servidor: ejecutar) |
| B11 | Nginx sin sandbox de systemd (E) | Drop-in `nginx-hardening.conf` con reversión automática si nginx no arranca | Solo servidor | Mitigado (servidor: ejecutar) |
| A15 | Un escaneo SYN no deja rastro en `access.log` (R, capa HOST) | `ufw logging medium` + regla R4 en `detect.py` (≥5 bloqueos **entrantes**/5 min por IP, descarta multicast/broadcast y salientes); el timer lee `ufw.log` | 7 pruebas automáticas; el log real solo en servidor | Corregido (servidor: ejecutar `harden-host.sh`) |
| A16 | Correlación Nginx↔app solo por IP+hora (R) | `X-Request-ID` generado por Nginx (`$request_id`), `rid=` en `access.log`, `request_id` en `actions.log`; la app descarta valores con forma inválida | 5 pruebas + prueba real Nginx→app en Docker: mismo id en access.log, `create_alert` y `alert_classified`; un id falso del cliente se descarta | Corregido |
| A17 | WAF (ModSecurity + OWASP CRS) | Evaluado en contenedor: bloquea SQLi/XSS/traversal/scanners/log4shell, pero también alertas legítimas con `cmd.exe`, `powershell -enc`, `/etc/passwd`, `<script>` en la descripción | Prueba manual (ver conversación): 3 de 3 alertas realistas legítimas → 403 con CRS PL1 | **No incorporado**: corresponde al Lab 6; exigiría excluir `POST /alerts` |
| A18 | Entradas inválidas sin rastro en el audit log: Nginx las ve, la app no (R) | `validation_error` en `actions.log` con ruta, IP, `request_id` y solo `loc`/`type` de los campos que fallan (nunca el valor; nombres acotados a 64 car.) | 3 pruebas automáticas | Corregido (servidor: `git pull` y reiniciar) |
| A21 | Un JSON roto sin clave recibía 422 y escribía `validation_error` en el audit log: FastAPI analiza el cuerpo antes de la autenticación, así que un anónimo escribía en el log sin que el bloqueo, fail2ban ni la detección lo contaran (R, E) | El handler de 422 exige antes una credencial válida para la ruta: sin ella responde 401, registra `*_unauthorized`, cuenta el fallo y respeta el bloqueo por IP (comparación en tiempo constante); con ella, 422 y `validation_error` con el actor real | 5 pruebas automáticas | Corregido (servidor: `git pull` y reiniciar) |
| A19 | Un proceso del servidor que intenta salir a destinos no permitidos no deja alerta (R, E) | Regla R5 en `detect.py` (≥5 bloqueos salientes de ufw por ventana, destino como evidencia) | 3 pruebas automáticas | Corregido (servidor: ejecutar el timer) |
| A20 | El veto de fail2ban respondía `REJECT`, que confirma al atacante que hay un firewall (I) | `banaction = ufw[blocktype=deny]` en los jails `muvautomation` y `sshd`: el paquete se descarta en silencio (resolución comprobada con `fail2ban-client -d`) | Verificación de configuración; retest en VM | Corregido (servidor: ejecutar `harden-host.sh`) |
| A1 | La clasificación en segundo plano reabría/des-escalaba alertas ya gestionadas (T, R) | `process_alert` relee el estado con `BEGIN IMMEDIATE` y solo cambia el estado si sigue en `new`; no re-notifica | 2 pruebas automáticas (alerta cerrada, alerta ya escalada) | Corregido |
| A2 | Redirección por `Host` en `/alerts/` (S) | `redirect_slashes=False` + `proxy_set_header Host 192.168.61.129` | Prueba automática (404 sin `Location`); `nginx -t` OK en contenedor | Corregido |
| A3 | `99-lab3.conf` podía perder frente a otro fragmento de sshd (S, E) | Se instala como `00-lab3.conf` (gana el primer valor), se elimina `99-lab3.conf` y se comprueba `sshd -T` | `bash -n`; efecto real solo en servidor | Mitigado (servidor: ejecutar) |
| A4 | `harden-host.sh` no activaba ufw (S, E) | `ufw --force enable` + comprobación de `Status: active` + aborta si la IP SSH no está en `LAB_CIDR` | `bash -n`; solo servidor | Mitigado (servidor: ejecutar) |
| A5 | Configuración sshd inválida quedaba instalada tras `sshd -t` fallido (D) | Respaldo y restauración automática | `bash -n`; solo servidor | Mitigado (servidor: ejecutar) |
| A6 | Acciones y cuotas con lectura-decisión-escritura no atómica (T, D) | `BEGIN IMMEDIATE` en `register_action` y en `create_alert` | Pruebas concurrentes (12 alertas × close/ack; 20 POST contra cuota de 8 → exactamente 5 aceptadas) | Corregido |
| A7 | Arranque bloqueado por AbuseIPDB y umbral inválido tardío (D) | Reprocesado en hilo de fondo; `MUV_ESCALATION_THRESHOLD` se valida al arrancar | 6 pruebas automáticas | Corregido |
| A8 | Detección manual y sin cobertura de 403 (R) | Regla R3 (≥5 × 403) y `muvautomation-detect.timer` cada 5 min | 2 pruebas; timer solo en servidor | Corregido (servidor: ejecutar) |
| A9 | Caché de AbuseIPDB sin límite (D) | Tope de 5 000 entradas (expiradas primero) | Prueba automática | Corregido |
| A10 | Claves de baja entropía y ejemplos del README aceptados (S) | ≥16 caracteres, ≥8 distintos, lista de ejemplos rechazados; README genera claves aleatorias | 5 pruebas automáticas | Corregido |
| A11 | Bloqueo compartido entre emisor y analistas de una misma IP (D) | Contadores separados por ámbito (`emitter:`/`analyst:`) | Prueba automática | Corregido |
| A12 | `env.example` indicaba `640 root:www-data` (I) | `600 root:root` en `env.example` e `INFORME_PARTE2.md` | Revisión | Corregido |
| A13 | Clave TLS con grupo `ssl-cert` (I) | `600 root:root` (Nginx la lee con su proceso maestro) | Solo servidor | Mitigado (servidor: ejecutar) |
| A14 | `.gitignore` sin `.venv/`, `.env`, `*.key`, `*.pem`, `*.db` (I) | Entradas añadidas | Revisión | Corregido |

## Riesgos aceptados o pendientes para el Lab 4

| Riesgo | Motivo | Estado |
|---|---|---|
| Certificado autofirmado | Es un laboratorio; sin CA propia | Aceptado |
| Claves en texto plano en el archivo de entorno | Falta hash y rotación | Pendiente Lab 4 |
| Sin mTLS para el emisor (Falcon) | Requiere CA propia | Pendiente Lab 4 |
| Sin hash encadenado en logs y DB | Integridad criptográfica | Pendiente Lab 4 |
| `high` + táctica sin alto impacto = 60 (< umbral 70) no se escala sola, y el emisor declara severidad/táctica | Decisión de diseño que cambia los puntajes documentados | Pendiente de decisión |
| Dependencias transitivas sin lockfile con hashes | Debe generarse en Linux (uvloop/httptools); `pip-audit`: sin vulnerabilidades conocidas | Pendiente |
| `X-Forwarded-For` falsificable por procesos locales que alcancen `127.0.0.1:8000` | Requiere socket Unix entre Nginx y uvicorn | Aceptado |
| Bloqueo anti fuerza bruta no persistente entre reinicios | Estado en SQLite (`auth_failures`); además fail2ban | Corregido (Etapa D) |
| Descripciones de alertas con HTML se guardan sin escapar | Solo JSON con CSP `default-src 'none'`; escapar si hay front-end | Aceptado |
| Migración a microservicios | Aumenta la superficie (broker, DB de red); no lo pide el Lab 3 | Descartado, ver evolución arquitectónica |

## Etapa D: identidad y autenticación

| ID | Riesgo (STRIDE) | Corrección | Verificación | Estado |
|---|---|---|---|---|
| D1 | Claves estáticas de analista: sin expiración, sin revocación, sin segundo factor (S, E) | Login con Argon2id y token EdDSA de 10 min; interruptor `MUV_ALLOW_ANALYST_STATIC_KEYS` | Pruebas automáticas (`tests/test_identity.py`) | Corregido (servidor: crear usuarios y apagar las claves) |
| D2 | Falsificación de token: `alg: none`, confusión HS256/EdDSA, otra clave, audiencia o emisor ajenos (S) | Algoritmo fijo `EdDSA`, `iss`/`aud`/`exp`/`jti` obligatorios, rol y estado tomados de la base | 8 casos forjados → 401 | Corregido |
| D3 | Robo de token de renovación (S, I) | Hash en base, rotación en cada uso, reutilización revoca la familia, evento `refresh_reuse_detected` | Pruebas | Corregido |
| D4 | Enumeración de usuarios por respuesta o tiempo (I) | Respuesta idéntica y hash ficticio para usuarios inexistentes; la espera por cuenta tampoco distingue | Pruebas | Corregido |
| D5 | Fuerza bruta de contraseñas y uso de Argon2 para agotar CPU (S, D) | Espera creciente por cuenta + bloqueo por IP + `limit_req` 20/min en `/auth/login` y `/auth/refresh` + contraseña máx. 128 | Pruebas; `nginx -t` en contenedor | Corregido (servidor: ejecutar) |
| D6 | El rol con más poder (`respondedor`) dependía de una sola credencial (E) | TOTP obligatorio (secreto cifrado, código de un solo uso); el token sin `otp` se rechaza | Pruebas | Corregido |
| D7 | `mgmt_ip` visible para cualquier rol (I) | Filtrado de campos por rol | Prueba | Corregido |
| D8 | Revocación o bloqueo perdidos al reiniciar la app (E) | Estado en SQLite | Prueba de persistencia | Corregido |
| D9 | Alta de usuarios por un endpoint abierto o con usuario por defecto (E) | Solo CLI en el host (`identity-admin.sh`); contraseña por terminal sin eco | Pruebas de la CLI | Corregido |
| D10 | La clave de firma y la de cifrado de TOTP comparten host con la API (I) | Archivo de entorno 600 root, auditd; separación física pendiente | — | Aceptado |

## Límites de la verificación
`nginx -t` y la prueba funcional de Nginx (headers sin duplicar, 403/404/413, rate limit 429, TLS, XFF falsificado) se ejecutaron en contenedor Docker. No se pudo ejecutar en local: `systemd-analyze`, `ufw`, `sshd -t` y `fail2ban` reales. Esos puntos quedan como "Servidor" y se comprueban con el retest.
