# SECURITY.md — Evaluación de seguridad (Laboratorio FSI)

## 1. Alcance y línea base

| Campo | Valor |
|---|---|
| Repositorio | `https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar` (privado) |
| Rama base | `main` |
| Commit de línea base | `44ddc48` (`main` al iniciar el laboratorio, ya con las actualizaciones de Dependabot fusionadas) |
| Rama del laboratorio | `security/lab-fsi` |
| Responsables | Valero25 (Juan Valero). *Agregar aquí al resto del equipo.* |
| Tecnología | Python 3.12, FastAPI 0.142.2 / Starlette 1.10, Uvicorn, SQLite, PyJWT (Ed25519), Argon2, pyotp (TOTP). Frontend HTML/CSS/JS sin dependencias. Nginx 1.26 (TLS, cabeceras, *rate limit*), ModSecurity v3 + OWASP CRS, fail2ban, systemd. Ubuntu 26.04 en una VM de VMware. |
| Entorno de staging | VM `lab3-server`, `https://192.168.61.129`, en una red NAT privada (`192.168.61.0/24`). Para el DAST se usó un **staging local equivalente en Docker** ([deploy/staging-local](../deploy/staging-local/Dockerfile)): Nginx con la misma configuración del repo, más la API, HTTPS autofirmado y claves y datos ficticios generados al arrancar. |

### Flujos de autenticación

| Flujo | Mecanismo |
|---|---|
| Analista humano (consola `/app/`) | `POST /auth/login`: usuario, contraseña (Argon2id) y TOTP, obligatorio para `respondedor`. Devuelve un *access token* JWT EdDSA y un *refresh token* rotativo. `POST /auth/refresh` y `POST /auth/logout`. Los tokens viven solo en la memoria de la página, sin cookies. |
| Analista con clave estática | Cabecera `X-Analyst-Key`. Se puede desactivar con `MUV_ALLOW_ANALYST_STATIC_KEYS=no`. |
| Emisor de alertas (máquina) | Cabecera `X-API-Key` en `POST /alerts`. |
| Alta de usuarios | Solo por CLI en el servidor (`app/identity_cli.py`). No hay registro ni usuario por defecto. |

### APIs

`POST /alerts`, `GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/actions`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /network/devices`, `GET /network/devices/{id}`. `/docs`, `/redoc` y `/openapi.json` están deshabilitados (404).

### Activos y riesgo principal

| Activo | C | I | D |
|---|---|---|---|
| Alertas SOC y su historial de acciones (SQLite) | Alta | **Alta** | Media |
| Audit log (`actions.log`), que alimenta la detección (`scripts/detect.py`) y fail2ban | Media | **Alta** | Media |
| Credenciales: hash Argon2, secretos TOTP cifrados, clave de firma JWT | **Alta** | Alta | Media |
| Inventario de red | Media | Media | Baja |

**Riesgo principal:** suplantación o manipulación de la trazabilidad. Si un atacante falsea lo que registra el audit log, oculta un ataque de fuerza bruta o desvía la detección (integridad). La validación H-3 confirmó este riesgo.

## 2. Controles automatizados

| Control | Tipo | Dónde | Estado |
|---|---|---|---|
| Semgrep (`p/default`, `p/python`, `p/secrets`) con artefacto `resultado-semgrep` y puerta en ERROR | SAST | [seguridad-estatica.yml](../.github/workflows/seguridad-estatica.yml) | Nuevo |
| gitleaks sobre el historial completo, con `.gitleaksignore` por huella | Secretos | `seguridad-estatica.yml` y `devsecops.yml` | Nuevo / existente |
| Bandit (puerta en severidad alta) | SAST | [devsecops.yml](../.github/workflows/devsecops.yml) | Existente |
| pip-audit `--strict` de producción **y de desarrollo** | SCA | `devsecops.yml` | Ampliado |
| Dependabot (*version updates* de Actions, con `cooldown` de 7 días) | SCA | [dependabot.yml](../.github/dependabot.yml) | Ampliado |
| OWASP ZAP baseline (pasivo), con artefacto `informe-zap` | DAST | [dast-staging.yml](../.github/workflows/dast-staging.yml) | Nuevo |
| pytest (270 pruebas, con regresiones de este laboratorio) | Regresión | `devsecops.yml` | Ampliado |
| Dependabot alerts, CodeQL *default setup*, secret scanning | Nativos de GitHub | Settings → Advanced Security | **Pendiente de activar** (ver §4) |

## 3. Política de reporte

Las vulnerabilidades se reportan en privado al responsable del repositorio, nunca en un *issue* público. Las pruebas se hacen solo sobre el staging propio y con datos ficticios.

## 4. Limitaciones

- **Controles nativos de GitHub:** el repositorio es **privado** y de una cuenta personal. En el inicio del laboratorio, la API de GitHub respondía *"Dependabot alerts are disabled"*, *"Code scanning is not enabled"* y *"Secret scanning is disabled"*. Las Dependabot alerts son gratuitas y se pueden activar. CodeQL y secret scanning en repos privados requieren GitHub Advanced Security (Code Security / Secret Protection). Si el plan no lo incluye, se documenta como limitación y Semgrep y gitleaks cubren esa función.
- **DAST:** GitHub Actions no alcanza la VM, que está en una NAT privada. Por eso `dast-staging.yml` levanta el staging local dentro del runner cuando no existe la variable `STAGING_URL`. El staging local no incluye el WAF ni fail2ban.
- **ZAP baseline es pasivo:** no prueba inyección ni control de acceso. Lo que no cubre lo validan las pruebas automatizadas (`tests/`) y la validación manual (H-3).
- **Semgrep** analiza parcialmente `deploy/harden-host.sh` y `deploy/waf-smoke.sh` (*PartialParsing* del analizador de Bash). ShellCheck ya cubre esos scripts.
