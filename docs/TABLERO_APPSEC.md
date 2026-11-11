# Informe de integración AppSec — FSI

Exportado con el formato del tablero del kit ([AppSec_Lab_FSI.html](AppSec_Lab_FSI.html)): una sección por etapa, con su estado, la evidencia y las observaciones.

Fecha: 10/11/2026

## 1. Alcance y autorización
Estado: Completado
Evidencia: [SECURITY.md §1](SECURITY.md) · commit base [44ddc48](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/commit/44ddc48e5ebc02fc46f6fe96e52bb8f7a11dca9a) · rama [security/lab-fsi](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/tree/security/lab-fsi)
Observaciones: El repositorio, el código y la VM son propios. Las reglas de enfrentamiento están escritas: solo staging aislado, datos ficticios, DAST pasivo; sin fuerza bruta ni DoS. Riesgo principal: integridad del audit log.

## 2. Code scanning
Estado: Completado
Evidencia: [Code scanning](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/security/code-scanning?query=is%3Aclosed) · run [42888933539](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/actions/runs/42888933539)
Observaciones: CodeQL default setup (suite extended) desde que el repositorio es público. 3 alertas: #1 corregida (H-7), #3 falsa alarma con prueba (F-5) y #2 riesgo aceptado (F-6). El ruleset exige CodeQL sin alertas high/error.

## 3. SAST + secretos
Estado: Completado
Evidencia: [seguridad-estatica.yml](../.github/workflows/seguridad-estatica.yml) · artefacto [resultado-semgrep](evidencias/ci/resultado-semgrep/semgrep.json) · PR [#5](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/5)
Observaciones: Semgrep pasó de 7 hallazgos a 0 (H-5 corregido; F-1 y F-2 justificados). gitleaks pasó de 13 coincidencias a 0 (F-4, huellas en .gitleaksignore). Secret scanning y push protection activos.

## 4. SCA / Dependabot
Estado: Completado
Evidencia: [dependabot.yml](../.github/dependabot.yml) · [Dependabot](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/security/dependabot) · PR [#12](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/12)
Observaciones: Starlette 0.38.6 en el venv local: 35 CVE, solo una alcanzable (Host header, H-3), corregida en el código. Dependency Review en cada PR. Las actualizaciones de fastapi y uvicorn se validaron en CI y con DAST antes de decidir (REPORTE §7.1).

## 5. DAST pasivo
Estado: Completado
Evidencia: [dast-staging.yml](../.github/workflows/dast-staging.yml) · [informe ZAP final](evidencias/ci/informe-zap-final/informe-zap.html) · puerta [.zap/rules.tsv](../.zap/rules.tsv)
Observaciones: Staging HTTPS aislado en el runner, porque GitHub no alcanza la VM de la NAT privada. H-4 (10055) corregido. ZAP ahora es una puerta de regresión: el run 42950614751, con la CSP rota a propósito, falló.

## 6. Pentest controlado
Estado: Completado
Evidencia: [validar-host-header.sh](../deploy/staging-local/validar-host-header.sh) · [antes](evidencias/antes/validar-host-header-antes.txt) → [después](evidencias/despues/validar-host-header-despues.txt)
Observaciones: Hipótesis: un Host manipulado reescribe la ruta del audit log. Se validó con un cuerpo JSON inválido en un contenedor aislado: login_failed quedaba como refresh_failed. Corregido con scope["path"].

## 7. Corrección y reescaneo
Estado: Completado
Evidencia: PRs [#5](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/5), [#6](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/6), [#12](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/12), [#13](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/13), [#14](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/14) y [#17](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/17) · PRs demo bloqueados [#15](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/15) y [#16](https://github.com/Valero25/FDSI_LAB_Aplicacion-web-publica-por-HTTP-construir-atacar-detectar-corregir-y-verificar/pull/16)
Observaciones: 8 hallazgos corregidos (H-1 a H-8) con 8 pruebas de regresión. Cada herramienta se volvió a ejecutar después de la corrección. Los PRs demo demuestran que el ruleset bloquea una inyección SQL y una regresión de la CSP.

## 8. Entrega y sustentación
Estado: Completado
Evidencia: [INFORME_LAB5.md](../INFORME_LAB5.md) · [REPORTE_HALLAZGOS.md](REPORTE_HALLAZGOS.md) · [SECURITY.md](SECURITY.md)
Observaciones: El informe final reúne la arquitectura del pipeline, el código de cada corrección, las evidencias antes y después, la priorización P×I, las limitaciones y las conclusiones.
