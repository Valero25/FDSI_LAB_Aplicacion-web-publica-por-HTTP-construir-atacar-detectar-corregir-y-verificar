# SECURITY.md — Evaluación de seguridad (Laboratorio FSI)

## 1. Alcance y línea base

| Campo | Valor |
|---|---|
| Repositorio | <https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar> (**público** desde el 2026-11-10; ver [§5](#5-decisión-de-riesgo-repositorio-público-revisión-de-g12)) |
| Rama base | `main` |
| Commit de línea base | [`44ddc48`](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/commit/44ddc48e5ebc02fc46f6fe96e52bb8f7a11dca9a) (`main` al iniciar el laboratorio, ya con las actualizaciones de Dependabot fusionadas) |
| Ramas del laboratorio | [`security/lab-fsi`](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/tree/security/lab-fsi) (PR [#5](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/5)), luego `security/lab-fsi-cierre`, `-dependabot`, `-ruleset` e `-informe-final` (PRs [#6](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/6), [#12](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/12), [#13](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/13) y el PR del informe final) |
| Responsables | Ana Gabriela Fiquitiva Poveda y Juan David Valero Abril (Valero25) |
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

### Autorización y reglas de enfrentamiento

| Aspecto | Definición |
|---|---|
| **Titularidad** | El código, el repositorio `Valero25/…` y la VM `lab3-server` son **propios del equipo**: los construyeron los responsables de §1 para el curso. No se evaluó ningún sistema de terceros. |
| **Quién autoriza** | Los dos responsables del equipo, como dueños del sistema, en el marco del Lab 05 de Fundamentos de Seguridad de la Información (ECI), que exige trabajar solo sobre proyectos y entornos propios. |
| **Objetivos permitidos** | (1) El repositorio, para SAST, secretos y SCA. (2) El staging HTTPS aislado de [deploy/staging-local](../deploy/staging-local/Dockerfile), en `localhost` o dentro del runner de GitHub, para el DAST. (3) Contenedores aislados para la validación manual (H-3). La VM de la NAT privada no se escaneó desde Internet. |
| **Objetivos prohibidos** | Producción, dominios o IP de terceros y cualquier URL que no sea del equipo. `dast-staging.yml` solo usa `STAGING_URL` si el equipo la configura; no está configurada, así que analiza el staging del runner. |
| **Técnicas permitidas** | Análisis estático, ZAP **baseline pasivo** (araña y observación de respuestas, sin ataques) y peticiones **inocuas** (un cuerpo JSON inválido con un `Host` manipulado). |
| **Técnicas prohibidas** | Fuerza bruta, denegación de servicio, explotación destructiva, exfiltración y escaneo activo de ZAP. El *rate limit* y el bloqueo por cuenta se verifican con pruebas automatizadas, sin atacar. |
| **Datos** | Solo datos y cuentas ficticios: alertas simuladas, usuarios de laboratorio, y claves JWT y TOTP generadas al arrancar el staging. No hay datos personales reales. |
| **Evidencias** | Ninguna evidencia publica credenciales: los informes de gitleaks usan `--redact` y las claves de prueba son ficticias. |
| **Ventana** | Del 2026-10-28 al 2026-11-10. |

## 2. Controles automatizados

| Control | Tipo | Dónde | Estado |
|---|---|---|---|
| Semgrep (`p/default`, `p/python`, `p/secrets`) con artefacto `resultado-semgrep` y puerta en ERROR | SAST | [seguridad-estatica.yml](../.github/workflows/seguridad-estatica.yml) | Nuevo |
| gitleaks en CI sobre los commits de cada PR o push (el historial completo se revisa con `gitleaks git .`), con `.gitleaksignore` por huella | Secretos | `seguridad-estatica.yml` y `devsecops.yml` | Nuevo / existente |
| Bandit (puerta en severidad alta) | SAST | [devsecops.yml](../.github/workflows/devsecops.yml) | Existente |
| pip-audit `--strict` de producción **y de desarrollo** | SCA | `devsecops.yml` | Ampliado |
| Dependabot (*version updates* de Actions **y de pip**: `app/requirements.txt` y `requirements-dev.txt`, con `cooldown` de 7 días) | SCA | [dependabot.yml](../.github/dependabot.yml) | Ampliado (PR de cierre) |
| Dependency Review en cada PR (falla si el PR agrega una dependencia con vulnerabilidad moderada o mayor) | SCA | job `revision-dependencias` de `seguridad-estatica.yml` | Nuevo (PR de cierre) |
| OWASP ZAP baseline (pasivo), con artefacto `informe-zap` | DAST | [dast-staging.yml](../.github/workflows/dast-staging.yml) | Nuevo |
| pytest (271 pruebas, con 8 regresiones de este laboratorio) | Regresión | `devsecops.yml` | Ampliado |
| Dependency graph, **Dependabot alerts**, **Dependabot security updates**, Malware alerts | Nativos de GitHub (SCA) | Settings → Advanced Security | ✅ **Activos** (2026-11-04). Dependabot alerts: 0 alertas abiertas. La API confirma `automated-security-fixes: enabled` |
| **CodeQL *default setup*** (suite `extended`; Python, JavaScript/TypeScript y GitHub Actions) | Nativo de GitHub (SAST) | Settings → Advanced Security → Code scanning | ✅ **Activo** (2026-11-10, al pasar el repo a público). Primer análisis: run [`42888933539`](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/actions/runs/42888933539), 3 alertas (H-7, F-5, F-6) |
| **Ruleset `proteger-main`**: sin borrado ni *force push*, PR obligatorio, 7 checks obligatorios y actualizados (Semgrep, gitleaks, Dependency Review, pytest, Bandit, pip-audit, CodeQL) y resultados de CodeQL sin alertas *high* ni *error*. Sin excepciones (*bypass list* vacía) | Gobierno del pipeline | Settings → Rules → Rulesets ([evidencia](evidencias/ci/ruleset-proteger-main.json)) | ✅ **Activo** (2026-11-10). Convierte los escaneos de informativos en una **puerta de merge** |
| **Secret scanning** y **push protection** | Nativo de GitHub (secretos) | Settings → Advanced Security → Secret Protection | ✅ **Activos** (2026-11-10). 0 alertas sobre todo el historial |

## 3. Política de reporte

Las vulnerabilidades se reportan en privado al responsable del repositorio, nunca en un *issue* público. Las pruebas se hacen solo sobre el staging propio y con datos ficticios.

## 4. Limitaciones

- **Controles nativos de GitHub (historia):** el repositorio era **privado** y de una cuenta personal.
  - Al inicio del laboratorio, la API respondía *"Dependabot alerts are disabled"*, *"Code scanning is not enabled"* y *"Secret scanning is disabled"*.
  - El 2026-11-04 se activaron Dependabot alerts, Malware alerts y Dependabot security updates. CodeQL y secret scanning no aparecían: en repositorios privados requieren GitHub Advanced Security.
  - **El 2026-11-10 el repositorio pasó a público** para poder usar CodeQL, secret scanning y Dependency Review sin licencia. Antes se comprobó que no se publicaba nada sensible: gitleaks sobre todo el historial (`no leaks found`), ninguna rama con commits fuera de `main` salvo los 3 de Dependabot (solo versiones de acciones), sin archivos `.env`, `.pem` ni bases de datos, y solo claves de prueba ficticias.
  - Semgrep y gitleaks se mantienen: CodeQL encontró cosas que Semgrep no vio (H-7) y viceversa (H-5), así que se complementan.
- **Dependency graph y evidencias:** Dependabot trata como manifiesto de pip cualquier `*requirements*.txt`. Una evidencia llamada `pip-audit-requirements-antes.txt` hizo fallar el job *Dependency Graph*. Se renombró a `pip-audit-produccion-antes.txt`.
- **DAST:** GitHub Actions no alcanza la VM, que está en una NAT privada. Por eso `dast-staging.yml` levanta el staging local dentro del runner cuando no existe la variable `STAGING_URL`. El staging local no incluye el WAF ni fail2ban.
- **ZAP baseline es pasivo:** no prueba inyección ni control de acceso. Lo que no cubre lo validan las pruebas automatizadas (`tests/`) y la validación manual (H-3).
- **Semgrep** analiza parcialmente `deploy/harden-host.sh` y `deploy/waf-smoke.sh` (*PartialParsing* del analizador de Bash). ShellCheck ya cubre esos scripts.

## 5. Decisión de riesgo: repositorio público (revisión de G12)

En la Parte 2 del Lab 3, el gap **G12** se mitigó, entre otras medidas, dejando el repositorio en **privado** y clonándolo en la VM con una deploy key de solo lectura ([INFORME_PARTE2.md](../INFORME_PARTE2.md)). El 2026-11-10 el equipo **revirtió conscientemente esa parte de G12** y publicó el repositorio. Esta es la justificación:

| Pregunta | Respuesta |
|---|---|
| **¿Por qué?** | En un repositorio privado de cuenta personal, CodeQL, secret scanning, push protection y Dependency Review requieren GitHub Advanced Security. El laboratorio exige CodeQL de forma explícita. |
| **¿Qué se expone?** | El código, la configuración de Nginx, ModSecurity y fail2ban, las evidencias y el historial de Git. |
| **¿Qué NO se expone?** | Secretos. Antes de publicar se revisó todo: gitleaks sobre el historial completo (`no leaks found`), ninguna rama con contenido fuera de `main` salvo las 3 de Dependabot, sin `.env`, `.pem` ni bases de datos, y las claves de los tests son ficticias. Los secretos reales (`/etc/muvautomation.env`, la clave JWT, la clave TOTP y la base de datos) viven solo en la VM y nunca estuvieron en Git. |
| **¿Qué riesgo queda?** | Un atacante conoce el diseño y las reglas del WAF y puede buscar formas de evadirlas. **Probabilidad:** baja, porque la VM está en una NAT privada y no es alcanzable desde Internet. **Impacto:** medio, porque el WAF es una capa más y la app valida por sí misma (Pydantic, consultas parametrizadas y autenticación). **Prioridad: baja.** |
| **Controles compensatorios** | Secret scanning + **push protection** (bloquea un secreto antes de que llegue al repo), gitleaks en cada PR, el ruleset `proteger-main` (nadie fusiona sin los 7 checks) y la deploy key de la VM, que sigue siendo de solo lectura. El resto de G12 no cambia: permisos `o-rwx`, base de datos y logs en 640, y `/.git` bloqueado en Nginx. |
| **Principio** | Kerckhoffs: la seguridad del sistema no depende de ocultar el código, sino de las claves, que siguen fuera del repositorio. |
| **Reversibilidad** | Se puede volver a privado en *Settings → General → Danger Zone*, pero se perderían CodeQL y secret scanning. Se acepta el riesgo residual mientras dure el curso. |
