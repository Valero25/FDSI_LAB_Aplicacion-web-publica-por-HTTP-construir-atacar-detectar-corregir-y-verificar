# FDSI Lab 3 — Aplicación web pública por HTTP: construir, atacar, detectar, corregir y verificar

Secure Product Challenge — MuvAutomation | Automatización de incidentes de CrowdStrike Falcon

## Equipo

- Ana Gabriela Fiquitiva Poveda
- Juan David Valero Abril

## Propósito del proyecto

Este proyecto es un prototipo (API + Nginx) que recibe alertas **ficticias** de seguridad (simulando CrowdStrike Falcon), las clasifica y enriquece, escala las críticas y registra las acciones que toman los analistas sobre ellas. No se usa información real ni hay integración real con CrowdStrike.

**Problemática:** hoy la recepción, clasificación, enriquecimiento y escalamiento de alertas de seguridad dependen de muchas actividades manuales. Eso alarga los tiempos de respuesta, dificulta correlacionar evidencias y hace que cada quien priorice los incidentes con criterios distintos.

## Informes

El laboratorio se hizo en dos partes. La idea es **comparar** la versión inicial con la versión fortalecida:

| Parte | Informe | Contenido |
|---|---|---|
| **Parte 1** — arquitectura inicial | [**INFORME.md**](INFORME.md) | La versión **deliberadamente insegura**: API FastAPI + Nginx por HTTP `:80`, sin autenticación ni hardening. Incluye el DFD, el diagrama de puertos, el despliegue real en Ubuntu, el diagnóstico del incidente de `ufw`/SSH y la tabla STRIDE inicial (H1–H6). Todos los diagramas de esta parte están en ese informe. |
| **Parte 2** — arquitectura fortalecida | [**INFORME_PARTE2.md**](INFORME_PARTE2.md) | Es una **implementación nueva** sobre la Parte 1, que sigue el hilo *Arquitectura inicial → Gap → Riesgo/Amenaza → Mejora → Arquitectura fortalecida*. Incluye HTTPS con TLS 1.3/1.2, hardening de Nginx, API key del emisor, analistas con rol, validación de entrada, Motor de Clasificación (MITRE ATT&CK + AbuseIPDB), Motor de Escalamiento, sandboxing y firewall de entrada y salida. Trae la tabla de gaps G1–G16, el STRIDE con su estado actualizado, los diagramas nuevos y las evidencias antes/después. |

## Parte 1 vs Parte 2 — qué cambió y qué descubrimos

### Diferencias principales

| Aspecto | Parte 1 (inicial) | Parte 2 (fortalecida) | Gap |
|---|---|---|---|
| Protocolo | HTTP/1.1 en claro por `:80` | **HTTPS** por `:443`; `:80` solo hace `301 → https` | G1 |
| Versión TLS | No había TLS | **TLS 1.3 + TLS 1.2**, suites ECDHE + AEAD; TLS 1.0/1.1 rechazadas | G2 |
| HSTS | No | `max-age=31536000` | G3 |
| SSH | `OpenSSH ALLOW Anywhere` (v4 y v6) | 22/tcp **solo desde `192.168.61.0/24`**, solo con llave, sin root | G4 |
| IPv6 | Nginx escuchaba en `[::]:80` | Se quitó (no se usa) | G5 |
| Documentación de la API | `/docs`, `/redoc` y `/openapi.json` públicos | Desactivados en FastAPI + 404 en Nginx | G6 |
| Fingerprinting | `Server: nginx/1.28.3 (Ubuntu)` y `server: uvicorn` | `server_tokens off`, `--no-server-header`, cabeceras CSP/XFO/nosniff/Referrer-Policy | G7 |
| Límites | Ninguno | `limit_req 10 r/s` (429), body de 16 KB como máximo (413), timeouts | G8 |
| Validación de entrada | `severity` libre, sin longitudes | `Literal`, `max_length`, `pattern`, IP validada, `extra="forbid"` → 422 | G9 |
| `POST /alerts` | Abierto a cualquiera | Exige `X-API-Key` (401 sin ella) y registra los intentos fallidos | G10 |
| Servicio systemd | `User=www-data` sin restricciones | `NoNewPrivileges`, `ProtectSystem=strict`, solo escribe la DB y los logs | G11 |
| Permisos y repositorio | `.git`/`.venv` en `rwxrwxr-x`; repositorio público | Sin acceso para "otros", DB y logs en 640, `/.git` bloqueado y repositorio privado | G12 |
| Clasificación y escalamiento | Solo en el diseño; toda alerta queda en `new` | **Motor de Clasificación**: MITRE ATT&CK local + AbuseIPDB → `risk_score` 0–100. **Motor de Escalamiento**: escala solo si el score es ≥ 70 | G13 |
| Integraciones externas | Ninguna | Solo AbuseIPDB, con controles (IPs públicas, timeout, validación, caché, cuota, segundo plano) | G14 |
| Salida a Internet | `allow outgoing` | `deny outgoing` salvo 53, 123/udp, 80 y 443 | G15 |
| Analistas | Anónimos: `GET /alerts` abierto y sin registro de quién actúa | Clave por analista con rol `lector` / `respondedor`; acciones con 401 / 403 / 409 y registro del `actor` | G16 |
| Límites de confianza (DFD) | **Uno** ("Backend del prototipo") | **Cuatro zonas** (red de laboratorio, borde Nginx/TLS, aplicación en loopback y datos en disco), más Internet como tercero no confiable | — |

### Lo más importante que descubrimos

1. **El DFD inicial tenía un error de modelado.** El *audit log* estaba **fuera** del límite de confianza, pero vive en el mismo servidor. Además, el DFD no mostraba Nginx, el acceso de administración SSH, el protocolo ni los puertos, así que no dejaba ver por dónde entra realmente un atacante.
2. **La superficie de ataque real era mayor que la que habíamos modelado.** La tabla STRIDE de la Parte 1 solo miraba los endpoints de negocio. Al revisar el host aparecieron SSH abierto a *Anywhere*, Nginx escuchando en IPv6, la salida a Internet sin restricción y la documentación de FastAPI publicando el mapa completo de la API. Nada de eso estaba en el modelo inicial.
3. **Poner HTTPS no alcanza por sí solo.** Migrar a HTTPS implica también redirigir el `:80`, fijar las versiones de TLS, agregar HSTS y ajustar el firewall. Como no hay dominio público, Let's Encrypt no aplica y se usó un certificado autofirmado con SAN = IP.
4. **La mitigación de H1 (spoofing) y la de H5 (DoS) se refuerzan entre sí.** La API key corta las alertas falsas, y el rate limit, junto con la validación estricta, limita el daño cuando alguien tiene la key o intenta adivinarla.
5. **Cada mejora también trae amenazas nuevas.** Al integrar AbuseIPDB aparecieron un flujo de salida, una clave más y la posibilidad de respuestas manipuladas (G14). Por eso evaluamos varias APIs de threat intelligence y solo integramos dos: MITRE ATT&CK, que funciona offline, y AbuseIPDB, con controles. **No integrar lo que no se necesita también es una decisión de seguridad.**
6. **La táctica y la técnica deben coincidir.** Con el índice de MITRE se detecta cuando la táctica declarada no corresponde a la técnica (`tactic_mismatch`), lo que sirve como señal de una alerta mal formada o manipulada.
7. **El orden de los cambios de firewall importa.** Lo aprendimos con el incidente de `ufw` de la Parte 1: primero se crean los `allow` y después se borran las reglas amplias o se cambia la política por defecto. El procedimiento de la Parte 2 está escrito en ese orden.
8. **Quedan riesgos para la Parte 3.** La identidad del analista es una clave estática: faltan SSO/MFA y rotación. También falta la integridad criptográfica de la DB (H2) y el filtrado de campos por rol (H4).

## Arquitectura actual (Parte 2)

```
Falcon / Analista (LAN) --HTTPS :443 (TLS 1.3/1.2) + clave--> Nginx (hardening, rate limit)
    --HTTP loopback--> FastAPI/uvicorn 127.0.0.1:8000 (sandbox)
        ├── Motor de Clasificación --> índice MITRE ATT&CK (local)
        │                         └──HTTPS :443--> AbuseIPDB (solo IPs públicas)
        ├── Motor de Escalamiento --> logs/escalations.log
        └── SQLite (alerts, alert_actions) · logs/actions.log
Cliente LAN --HTTP :80--> Nginx --301--> https://
Admin LAN   --SSH :22 (llave)--> lab3-server
```

Los diagramas de la Parte 2 están en [INFORME_PARTE2.md §7](INFORME_PARTE2.md#7-diagramas-de-la-arquitectura-fortalecida). Los de la Parte 1 están en [INFORME.md §3](INFORME.md#3-arquitectura-implementada).

## Endpoints

| Método | Ruta | Descripción | Quién puede |
|---|---|---|---|
| GET | `/` | Página informativa del portal (LAB) | Cualquiera (HTTPS) |
| POST | `/alerts` | Ingesta de una alerta ficticia (con `source_ip` opcional). Se clasifica y, si corresponde, se escala en segundo plano | Emisor con `X-API-Key` |
| GET | `/alerts?severity=&status=&min_score=&limit=` | Lista de alertas con filtros, `risk_score`, clasificación y enriquecimiento | Analista (`Authorization: Bearer` o, si se permite, `X-Analyst-Key`; cualquier rol) |
| GET | `/alerts/{alert_id}` | Detalle de la alerta con su historial de acciones; 404 si no existe | Analista (cualquier rol) |
| POST | `/alerts/{alert_id}/actions` | `acknowledge`, `comment`, `escalate` o `close` | `lector`: acknowledge y comment · `respondedor`: todas |
| POST | `/auth/login` | Usuario + contraseña (+ código TOTP) → token de acceso EdDSA de 10 min y token de renovación. Respuesta uniforme ante cualquier fallo | Público (limitado por tasa, espera creciente por cuenta) |
| POST | `/auth/refresh` | Rota el token de renovación; reutilizar uno ya usado revoca la sesión | Titular del token de renovación |
| POST | `/auth/logout` | Revoca el token de acceso (y la sesión, si se envía el de renovación) | Sesión con `Authorization: Bearer` |
| GET | `/network/devices?type=` | Inventario de red ficticio **de solo lectura** (firewalls, routers, switches); sin credenciales. `mgmt_ip` solo para `respondedor` | Analista (cualquier rol) |
| GET | `/network/devices/{device_id}` | Detalle de un dispositivo; 404 si no existe. No hay endpoints de escritura (POST/PUT/PATCH/DELETE → 405) | Analista (cualquier rol) |

Cada request relevante queda registrado en `logs/actions.log`, un JSON por línea con timestamp UTC, acción, método, ruta, IP de origen, `alert_id`, **actor** (`emisor:…`, `analyst:<nombre>` o `system:motor-…`) y **resultado** (`ok`, `unauthorized`, `forbidden`, `not_found`, `conflict`). Los escalamientos se notifican en `logs/escalations.log`.

## Estructura del repositorio

```
app/
├── main.py                        # API FastAPI: endpoints, autenticación, roles, audit log
├── enrichment.py                  # Motor de Clasificación y Enriquecimiento (MITRE ATT&CK + AbuseIPDB)
├── escalation.py                  # Motor de Escalamiento (umbral + notificación)
├── data/mitre_attack_index.json   # índice local de ATT&CK v19.2 (697 técnicas)
└── requirements.txt
scripts/
└── build_mitre_index.py           # regenera el índice MITRE desde el bundle STIX oficial
tests/
└── test_api.py                    # pruebas de los controles y de los motores
nginx/
└── muvautomation.conf             # :80 -> 301, :443 TLS + hardening -> 127.0.0.1:8000
deploy/
├── muvautomation-api.service      # unidad systemd con sandboxing
└── muvautomation.env.example      # plantilla de secretos (el archivo real va en /etc y no se versiona)
diagrams/
├── dfd-lab3.png                   # DFD de la Parte 1
├── arquitectura-inicial.jpeg      # arquitectura de la Parte 1 (protocolo, puertos, logs)
└── parte2/                        # diagramas de la Parte 2 (DFD y arquitectura fortalecidos)
evidencias/
├── Capturas_FDSI_LAB3.pdf         # capturas del despliegue de la Parte 1
└── local-http-server/             # evidencia del comando python3 -m http.server
requirements-dev.txt               # dependencias + pytest
INFORME.md                         # informe de la Parte 1
INFORME_PARTE2.md                  # informe de la Parte 2
```

## Ejecutar en local (desarrollo/pruebas)

Desde la **raíz** del repositorio (`app/` es un paquete):

```bash
python -m venv .venv
source .venv/bin/activate          # en Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
# Claves aleatorias (la API rechaza claves cortas, de baja variedad o de ejemplo):
export MUV_API_KEY=$(python -c "import secrets; print(secrets.token_hex(16))")
export ANA_KEY=$(python -c "import secrets; print(secrets.token_hex(16))")
export MUV_ANALYSTS="ana:respondedor:$ANA_KEY;juan:lector:$(python -c "import secrets; print(secrets.token_hex(16))")"
# export ABUSEIPDB_API_KEY=...     # opcional
uvicorn app.main:app --reload
python -m pytest -q                # 162 pruebas (API, identidad y detección)
```

En PowerShell: `$env:MUV_API_KEY = python -c "import secrets; print(secrets.token_hex(16))"` (igual para `$env:ANA_KEY` y `$env:MUV_ANALYSTS`).

Pruebas rápidas:

```bash
curl -i http://127.0.0.1:8000/docs                                  # 404
curl -s -X POST http://127.0.0.1:8000/alerts \
  -H "Content-Type: application/json" -H "X-API-Key: $MUV_API_KEY" \
  -d '{"severity":"critical","tactic":"Exfiltration","technique":"T1041 - Exfiltration Over C2 Channel","hostname":"DB-LAB-01","description":"Prueba de laboratorio"}'
curl -i -X POST http://127.0.0.1:8000/alerts -H "Content-Type: application/json" -d '{}'   # 401
curl -s "http://127.0.0.1:8000/alerts?min_score=70" -H "X-Analyst-Key: $ANA_KEY"
curl -i http://127.0.0.1:8000/alerts                                # 401
```

## Despliegue en el servidor

- Parte 1 (HTTP): [INFORME.md, Anexo](INFORME.md#anexo--procedimiento-de-despliegue-en-ubuntu-paso-a-paso).
- Parte 2 (HTTPS + hardening): [INFORME_PARTE2.md §8](INFORME_PARTE2.md#8-cambios-implementados). Explica, en un orden seguro, cómo generar el certificado, configurar los secretos, systemd, Nginx, `ufw` (entrada y salida), SSH y los permisos.

## URL publicada

`https://192.168.61.129` corresponde a `lab3-server` (Ubuntu 26.04.1 LTS, VM VMware). Solo es accesible dentro de la red NAT del laboratorio (`192.168.61.0/24`, restringida por `ufw`). `http://192.168.61.129` redirige a HTTPS. El certificado es autofirmado, así que hay que confiar en él de forma explícita (por ejemplo, `curl -k`).

## Limitaciones de seguridad pendientes

- **Identidad:** servicio propio con Argon2id, tokens EdDSA, renovación con rotación y TOTP obligatorio para `respondedor` (ver [IDENTIDAD.md](IDENTIDAD.md)). Siguen faltando SSO/federación y recuperación autónoma de cuentas; la clave del emisor (máquina) es una API key estática.
- **Filtrado de campos por rol:** `mgmt_ip` solo lo ve `respondedor`; el resto de campos del inventario es igual para todos.
- **No hay integridad criptográfica** en `alerts.db` ni en los logs (H2): los permisos y el sandbox la reducen, pero no la garantizan.
- **El certificado es autofirmado**, y las notificaciones de escalamiento van a un archivo, no a un canal real.

## Estado del laboratorio

- **Parte 1 — Fases A y B:** completa (ver [INFORME.md](INFORME.md)).
- **Parte 2 — análisis de amenazas, hardening y motores:** implementada y probada con 162 pruebas automatizadas y un stack Nginx + TLS en Docker. Faltan las evidencias del servidor (ver [INFORME_PARTE2.md](INFORME_PARTE2.md)).
- **Fases C–F** (ataque Red Team, detección Blue Team y verificación): pendientes.
