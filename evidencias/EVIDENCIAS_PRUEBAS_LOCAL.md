# Evidencias de pruebas en local

Secure Product Challenge — MuvAutomation | FDSI Lab 3, Parte 2

Este documento registra, paso a paso, las pruebas ejecutadas en el entorno **local** (máquinas virtuales en VMware, red NAT privada) el **11 de octubre de 2026**. Incluye los comandos usados, sus salidas y la interpretación de cada resultado.

- Las salidas son transcripciones de la sesión de pruebas. Donde se recortaron líneas repetitivas se indica con `[…]`.
- Todas las horas están en **UTC**.
- No se incluye ningún secreto: las claves se comprobaron por longitud o por conteo de coincidencias, nunca mostrando su valor.
- Todos los datos son ficticios y el alcance se limitó al segmento `192.168.61.0/24`.

## Índice

1. [Entorno](#1-entorno)
2. [Línea base: estado antes del hardening](#2-línea-base-estado-antes-del-hardening)
3. [Despliegue de la Parte 2](#3-despliegue-de-la-parte-2)
4. [Verificación del hardening](#4-verificación-del-hardening)
5. [Ronda Red Team](#5-ronda-red-team)
6. [Ronda Blue Team: detección y correlación](#6-ronda-blue-team-detección-y-correlación)
7. [Correcciones y retest](#7-correcciones-y-retest)
8. [Captura de red](#8-captura-de-red)
9. [Controles de la API desde Kali](#9-controles-de-la-api-desde-kali)
10. [Rotación de claves y auditoría](#10-rotación-de-claves-y-auditoría)
11. [Validación final de controles](#11-validación-final-de-controles)
12. [Segunda ronda de correcciones y retest](#12-segunda-ronda-de-correcciones-y-retest)
13. [Línea de tiempo Purple Team](#13-línea-de-tiempo-purple-team)
14. [Resumen de hallazgos](#14-resumen-de-hallazgos)
15. [Riesgos residuales y pruebas no realizadas](#15-riesgos-residuales-y-pruebas-no-realizadas)

---

## 1. Entorno

| Máquina | IP | Rol |
|---|---|---|
| Windows (anfitrión) | `192.168.61.1` | Administración por SSH (MobaXterm, llave ED25519) |
| Ubuntu Server 26.04.1 LTS `lab3-server` | `192.168.61.129` | Servicio: Nginx + API FastAPI |
| Kali Linux | `192.168.61.130` | Red Team |

Variables del ejercicio:

```bash
TARGET_IP=192.168.61.129
TARGET_URL=https://192.168.61.129
LAB_CIDR=192.168.61.0/24
```

**Comprobación de red** (Ubuntu y Kali):

```bash
ip -br a
```

```text
# Ubuntu
ens33            UP             192.168.61.129/24 metric 100 fe80::20c:29ff:fe09:b339/64
# Kali
eth0             UP             192.168.61.130/24 fe80::4abf:7b56:226c:89b/64
```

**Acceso de administración con llave** (Ubuntu):

```bash
sudo journalctl -u ssh -n 20 --no-pager | grep Accepted
```

```text
oct 05 06:59:57 lab3-server sshd-session[4246]: Accepted password for ubuntu from 192.168.61.1 port 49707 ssh2
oct 11 14:41:29 lab3-server sshd-session[2167]: Accepted publickey for ubuntu from 192.168.61.1 port 62631 ssh2: ED25519 SHA256:IeuV32rF[…]
```

Interpretación: el acceso del 5 de octubre fue con contraseña; el del día de la prueba ya es con llave pública. Se confirmó antes de cerrar las contraseñas para no perder el acceso.

---

## 2. Línea base: estado antes del hardening

**Versión desplegada** (Ubuntu):

```bash
git -C /opt/fdsi-lab3 log --oneline -1
```

```text
f1858b6 (HEAD -> main, origin/main, origin/HEAD) chore: forzar LF en scripts y configuracion de despliegue (.gitattributes)
```

**Firewall** (Ubuntu, 14:4x UTC):

```bash
sudo ufw status verbose
```

```text
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere
80/tcp                     ALLOW IN    192.168.61.0/24
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)
```

**Servicios, secretos y paquetes** (Ubuntu):

```bash
systemctl is-active nginx muvautomation-api fail2ban auditd
sudo ls -l /etc/muvautomation.env /etc/ssl/private/lab3-server.key /etc/ssl/certs/lab3-server.crt
ls -ld /opt/fdsi-lab3 /opt/fdsi-lab3/.venv /opt/fdsi-lab3/app/alerts.db
```

```text
active
active
active
inactive
ls: no se puede acceder a '/etc/muvautomation.env': No existe el archivo o directorio
ls: no se puede acceder a '/etc/ssl/private/lab3-server.key': No existe el archivo o directorio
ls: no se puede acceder a '/etc/ssl/certs/lab3-server.crt': No existe el archivo o directorio
drwxr-xr-x 12 ubuntu   www-data  4096 Oct 11 14:50 /opt/fdsi-lab3
drwxrwxr-x  5 ubuntu   www-data  4096 Sep 13 01:52 /opt/fdsi-lab3/.venv
-rw-------  1 www-data www-data 20480 Oct  5 06:34 /opt/fdsi-lab3/app/alerts.db
```

**Lectura de la línea base:**

| Observación | Riesgo |
|---|---|
| SSH `ALLOW Anywhere` en IPv4 e IPv6 | Administración expuesta a cualquier origen (G4) |
| Sin regla para el puerto 443 | No hay HTTPS (G1) |
| `allow (outgoing)` | Sin filtrado de salida (G15) |
| `Logging: on (low)` | Insuficiente para detectar escaneos |
| Sin certificado ni archivo de secretos | La Parte 2 no estaba desplegada |
| Base de datos dentro del directorio del código, a nombre de `www-data` | Datos y código mezclados (G12) |
| `auditd` inactivo | Sin auditoría de cambios |
| 67 actualizaciones pendientes, 39 de seguridad | Parches atrasados |

---

## 3. Despliegue de la Parte 2

### 3.1 Código

```bash
cd /opt/fdsi-lab3 && sudo git fetch origin && sudo git checkout vm-test && sudo git log --oneline -1
```

```text
branch 'vm-test' set up to track 'origin/vm-test'.
Switched to a new branch 'vm-test'
c6f5f63 (HEAD -> vm-test, origin/vm-test) wip: hardening ronda 3, R4, request_id e inventario de red (pruebas en VM)
```

### 3.2 Requisitos previos

```bash
.venv/bin/pip install -r app/requirements.txt
sudo apt install -y auditd
dpkg -l auditd | grep ^ii; .venv/bin/pip check
```

```text
ii  auditd         1:4.1.2-1ubuntu0.1 amd64        User space tools for security auditing
No broken requirements found.
```

Certificado autofirmado con SAN = IP:

```bash
sudo openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout /etc/ssl/private/lab3-server.key -out /etc/ssl/certs/lab3-server.crt \
  -subj "/CN=lab3-server" -addext "subjectAltName=IP:192.168.61.129"
```

Archivo de secretos con claves aleatorias (los valores nunca se muestran en pantalla):

```bash
sudo install -m 600 -o root -g root deploy/muvautomation.env.example /etc/muvautomation.env
sudo sed -i "s/^MUV_API_KEY=.*/MUV_API_KEY=$(openssl rand -hex 32)/; s/CAMBIAR_CLAVE_ANA/$(openssl rand -hex 32)/; s/CAMBIAR_CLAVE_JUAN/$(openssl rand -hex 32)/" /etc/muvautomation.env
```

Configuración de Nginx y comprobaciones:

```bash
sudo cp nginx/muvautomation.conf /etc/nginx/sites-available/fdsi-lab3 && sudo nginx -t
sudo ls -l /etc/muvautomation.env /etc/ssl/private/lab3-server.key /etc/ssl/certs/lab3-server.crt
sudo grep -c CAMBIAR /etc/muvautomation.env
```

```text
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
-rw------- 1 root root 1264 Oct 11 14:53 /etc/muvautomation.env
-rw-r--r-- 1 root root 1489 Oct 11 14:53 /etc/ssl/certs/lab3-server.crt
-rw------- 1 root root 2484 Oct 11 14:53 /etc/ssl/private/lab3-server.key
0
```

Interpretación: secretos y llave privada en `600 root:root`; el `0` confirma que no quedó ningún valor de ejemplo, sin revelar las claves.

### 3.3 Script de hardening

```bash
sudo LAB_CIDR=192.168.61.0/24 ADMIN_USER=ubuntu SSH_CLIENT="$SSH_CLIENT" bash deploy/harden-host.sh
```

```text
[1] Usuario de sistema dedicado (V3)
[2] Migrar DB y logs fuera del codigo (V2)
[3] Permisos de secretos (V9, V15)
[4] Firewall: primero allow, luego deny, y se activa (V14)
Rule added
Rule added
Skipping adding existing rule
Default incoming policy changed to 'deny'
Firewall is active and enabled on system startup
Logging enabled
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] OpenSSH                    ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    192.168.61.0/24
[ 3] 22/tcp                     LIMIT IN    192.168.61.0/24
[ 4] 443/tcp                    ALLOW IN    192.168.61.0/24
[ 5] OpenSSH (v6)               ALLOW IN    Anywhere (v6)

[5] SSH solo con llave (V14), con proteccion contra autobloqueo
[6] Rotacion de logs (V10), fail2ban (V12) y deteccion periodica (V-06)
[8] Endurecimiento de kernel/red, auditoria y Nginx (best effort: un fallo aqui no deja el host inseguro)
   nginx activo con el sandbox de systemd
[7] Servicio
Created symlink '/etc/systemd/system/timers.target.wants/muvautomation-detect.timer' → '/etc/systemd/system/muvautomation-detect.timer'.
✗ UMask=          Files created by service are group-readable by default          0.1

→ Overall exposure level for muvautomation-api.service: 1.2 OK 🙂
Listo. […]
```

**Hallazgo 1.** La regla `[1] OpenSSH ALLOW IN Anywhere` queda **antes** que `[3] 22/tcp LIMIT IN 192.168.61.0/24`. Como `ufw` aplica la primera regla que coincide, SSH seguía abierto a cualquier origen. El script no la borraba.

Antes de cerrar esa regla se comprobó que se podía abrir una segunda sesión con llave:

```bash
sudo journalctl -u ssh --since '10 minutes ago' --no-pager | grep Accepted
```

```text
oct 11 14:56:37 lab3-server sshd-session[9517]: Accepted key ED25519 SHA256:IeuV32rF[…] found at /home/ubuntu/.ssh/authorized_keys:1
oct 11 14:56:37 lab3-server sshd-session[9517]: Accepted publickey for ubuntu from 192.168.61.1 port 61270 ssh2: ED25519 SHA256:IeuV32rF[…]
```

Interpretación: las líneas `Accepted key … found at …authorized_keys:1` aparecen porque el hardening activó `LogLevel VERBOSE`; registran qué llave y de qué archivo se aceptó.

Corrección manual:

```bash
sudo ufw delete allow OpenSSH
```

```text
Rule deleted
Rule deleted (v6)
```

### 3.4 Filtrado de salida (G15)

```bash
sudo ufw allow out 53 && sudo ufw allow out 123/udp && sudo ufw allow out 80/tcp && sudo ufw allow out 443/tcp && sudo ufw allow out 67/udp
sudo ufw default deny outgoing && sudo ufw status verbose
```

```text
Default outgoing policy changed to 'deny'
Status: active
Logging: on (medium)
Default: deny (incoming), deny (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW IN    192.168.61.0/24
22/tcp                     LIMIT IN    192.168.61.0/24
443/tcp                    ALLOW IN    192.168.61.0/24

53                         ALLOW OUT   Anywhere
123/udp                    ALLOW OUT   Anywhere
80/tcp                     ALLOW OUT   Anywhere
443/tcp                    ALLOW OUT   Anywhere
67/udp                     ALLOW OUT   Anywhere
[… mismas reglas para IPv6 …]
```

Prueba de que el filtrado actúa:

```bash
curl -sI https://api.abuseipdb.com | head -1; ping -c 2 192.168.61.130
sudo grep 'UFW BLOCK' /var/log/ufw.log | grep 'DST=192.168.61.130' | tail -2
```

```text
HTTP/2 404
2 packets transmitted, 0 received, 100% packet loss, time 1015ms

2026-10-11T15:01:58.094283+00:00 lab3-server kernel: [UFW BLOCK] IN= OUT=ens33 SRC=192.168.61.129 DST=192.168.61.130 […] PROTO=ICMP TYPE=8 CODE=0 ID=42675 SEQ=1
2026-10-11T15:01:59.109385+00:00 lab3-server kernel: [UFW BLOCK] IN= OUT=ens33 SRC=192.168.61.129 DST=192.168.61.130 […] PROTO=ICMP TYPE=8 CODE=0 ID=42675 SEQ=2
```

Interpretación: la salida HTTPS permitida funciona (el `404` es la raíz de esa API, la conexión TLS se estableció) y el ICMP de salida queda bloqueado y registrado.

### 3.5 Repositorio privado con llave de despliegue (G12)

El repositorio se hizo privado. Como el filtrado de salida bloquea el puerto 22 saliente, se usa el acceso SSH de GitHub por el puerto 443 con una llave de solo lectura propia del servidor.

```bash
sudo mkdir -p -m 700 /root/.ssh && sudo ssh-keygen -t ed25519 -N "" -f /root/.ssh/lab3_deploy -C "lab3-server-deploy"
cd /opt/fdsi-lab3 && sudo git remote set-url origin ssh://git@ssh.github.com:443/Valero25/<repositorio>.git
sudo git config core.sshCommand "ssh -i /root/.ssh/lab3_deploy -o IdentitiesOnly=yes"
sudo git pull && sudo git log --oneline -1
```

```text
The authenticity of host '[ssh.github.com]:443 ([140.82.113.35]:443)' can't be established.
ED25519 key fingerprint is: SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
[…]
   c6f5f63..45a1ec3  vm-test    -> origin/vm-test
45a1ec3 (HEAD -> vm-test, origin/vm-test) fix: correcciones tras prueba en VM […]
```

Interpretación: la huella mostrada es la publicada por GitHub para su llave ED25519; se verificó antes de aceptar. La parte pública de la llave se registró en GitHub como *deploy key* sin permiso de escritura.

---

## 4. Verificación del hardening

```bash
sudo ufw status verbose
sudo sshd -T | grep -Ei '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|maxauthtries|x11forwarding) '
systemctl status muvautomation-api --no-pager | head -15
sudo fail2ban-client status; systemctl list-timers muvautomation-detect.timer --no-pager; sudo auditctl -l | head -5
curl -ksi https://127.0.0.1/ | head -20; sudo ls -l /var/lib/muvautomation
```

```text
maxauthtries 3
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
x11forwarding no

● muvautomation-api.service - MuvAutomation Falcon Incident Lab API (Lab 3 - Parte 2, detras de Nginx TLS)
     Active: active (running) since Sun 2026-10-11 14:55:28 UTC; 4min 24s ago
   Main PID: 9130 (uvicorn)
             └─9130 […]/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 […] --no-server-header

|- Number of jail:      2
`- Jail list:   muvautomation, sshd

-w /etc/muvautomation.env -p rwa -k lab3_secrets
-w /etc/ssl/private -p wa -k lab3_tls_key
-w /opt/fdsi-lab3 -p wa -k lab3_code
-w /var/lib/muvautomation -p a -k lab3_data_attr
-w /var/log/muvautomation -p a -k lab3_log_attr

HTTP/2 200
server: nginx
strict-transport-security: max-age=31536000; includeSubDomains
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: no-referrer
content-security-policy: default-src 'none'; frame-ancestors 'none'
permissions-policy: geolocation=(), camera=(), microphone=(), payment=()
cross-origin-resource-policy: same-origin
cross-origin-opener-policy: same-origin
cross-origin-embedder-policy: require-corp
cache-control: no-store
x-request-id: ddbe331e61792184572461d8c3375773

-rw------- 1 muvapi muvapi 20480 Oct  5 06:34 alerts.db
```

| Control | Evidencia | Gap |
|---|---|---|
| SSH solo desde el laboratorio, sin contraseñas ni root | `22/tcp LIMIT IN 192.168.61.0/24`; `passwordauthentication no`; `permitrootlogin no` | G4 |
| HTTPS | `HTTP/2 200` por el 443 | G1 |
| Sin versión del servidor web | `server: nginx` | G7 |
| Cabeceras defensivas | HSTS, CSP, XFO, nosniff, Referrer-Policy, `no-store` | G3, G7 |
| Servicio aislado | Usuario `muvapi`, exposición systemd `1.2 OK` | G11 |
| Datos fuera del código | `alerts.db` en `/var/lib/muvautomation`, `600 muvapi` | G12 |
| Filtrado de salida | `deny (outgoing)` con cinco excepciones | G15 |
| Bloqueo automático, detección y auditoría | 2 jails, timer activo, reglas `lab3_*` | — |

---

## 5. Ronda Red Team

Ejecutada desde Kali (`192.168.61.130`) entre las **15:04:51** y las **15:05:48 UTC**. Alcance: solo `192.168.61.129`; sin denegación de servicio ni intentos de adivinar credenciales.

### 5.1 Reconocimiento de servicios

Hipótesis: los banners revelan tecnología y versión.

```bash
date -u; nmap -sV -p 22,80,443 192.168.61.129
```

```text
Sun Oct 11 03:04:51 PM UTC 2026
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 10.2p1 Ubuntu 2ubuntu3.6 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx
443/tcp open  ssl/http nginx
MAC Address: 00:0C:29:09:B3:39 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Interpretación: Nginx ya no revela versión (G7). **Hallazgo 2:** SSH revela versión, distribución y nivel de parche del paquete.

### 5.2 Peticiones HTTP

Hipótesis: el puerto 80 sirve contenido en claro y `/docs` publica el mapa de la API.

```bash
curl -i http://192.168.61.129/; curl -ki https://192.168.61.129/docs
```

```text
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Sun, 11 Oct 2026 15:05:12 GMT
Location: https://192.168.61.129/

HTTP/2 404
server: nginx
date: Sun, 11 Oct 2026 15:05:12 GMT
strict-transport-security: max-age=31536000; includeSubDomains
[… resto de cabeceras defensivas …]
x-request-id: 36c471b69cef093c97121465edc42ab9
```

Interpretación: el puerto 80 solo redirige (G1) y la documentación de la API no es pública (G6).

### 5.3 Enumeración de rutas

Hipótesis: una ruta inexistente produce telemetría.

```bash
for i in 1 2 3 4 5 6; do curl -ks -o /dev/null -w "%{http_code} /no-existe-$i\n" https://192.168.61.129/no-existe-$i; done
```

```text
404 /no-existe-1
404 /no-existe-2
404 /no-existe-3
404 /no-existe-4
404 /no-existe-5
404 /no-existe-6
```

### 5.4 Escaneo SYN de puertos

Hipótesis: solo están expuestos los puertos previstos.

```bash
sudo nmap -sS -p 1-200 192.168.61.129; date -u
```

```text
Not shown: 198 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Sun Oct 11 03:05:48 PM UTC 2026
```

Interpretación: 198 de 200 puertos descartados en silencio por el firewall.

---

## 6. Ronda Blue Team: detección y correlación

### 6.1 Regla de detección

```bash
sudo .venv/bin/python -I scripts/detect.py /var/log/nginx/access.log --ufw-log /var/log/ufw.log; echo "exit=$?"
```

```text
[SENAL] R1-enumeracion-404 ip=192.168.61.130 eventos=11 2026-10-11T15:05:04+00:00 -> 2026-10-11T15:05:24+00:00 ej=['GET /HNAP1 HTTP/1.1', 'GET /docs HTTP/2.0', 'GET /evox/about HTTP/1.1'] request_id=['1da70dc7fda2e3c0e0bd9d291a1765c3', '36c471b69cef093c97121465edc42ab9', '3ccf170df7cbe38764c3171a82502c66']
[SENAL] R4-escaneo-ufw-block ip=192.168.61.130 eventos=10 2026-10-11T15:05:45.655747+00:00 -> 2026-10-11T15:05:45.656994+00:00 ej=['TCP/110', 'TCP/111', 'TCP/113']
exit=2
```

### 6.2 Telemetría de aplicación

```bash
sudo grep '192.168.61.130' /var/log/nginx/access.log | tail -10
```

```text
192.168.61.130 - - [11/Oct/2026:15:05:12 +0000] "GET / HTTP/1.1" 301 162 "-" "curl/8.20.0" rid=5f188f8f91746b3f4e94a38a4eb5c327
192.168.61.130 - - [11/Oct/2026:15:05:12 +0000] "GET /docs HTTP/2.0" 404 146 "-" "curl/8.20.0" rid=36c471b69cef093c97121465edc42ab9
192.168.61.130 - - [11/Oct/2026:15:05:24 +0000] "GET /no-existe-1 HTTP/2.0" 404 22 "-" "curl/8.20.0" rid=e2ec9207ae31761caf3f609d453266f9
[… /no-existe-2 a /no-existe-6, todas 404 a las 15:05:24 …]
```

### 6.3 Telemetría de host

```bash
sudo grep 'UFW BLOCK' /var/log/ufw.log | grep -c 'SRC=192.168.61.130'
```

```text
10
```

### 6.4 Detección automática

```bash
journalctl -u muvautomation-detect --since '15 minutes ago' --no-pager | tail -20
```

```text
oct 11 14:55:29 lab3-server python[9199]: Sin senales con el umbral configurado.
oct 11 15:00:31 lab3-server python[10576]: Sin senales con el umbral configurado.
oct 11 15:05:34 lab3-server python[13001]: [SENAL] R1-enumeracion-404 ip=192.168.61.130 eventos=11 […]
oct 11 15:05:34 lab3-server systemd[1]: muvautomation-detect.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
oct 11 15:05:34 lab3-server systemd[1]: muvautomation-detect.service: Failed with result 'exit-code'.
```

### 6.5 Interpretación

- **R1 detectó la enumeración sin intervención**, 10 segundos después del ataque. Las dos corridas anteriores dicen "Sin señales": es el antes y el después en el mismo registro.
- **R1 contó 11 y no 7:** los cuatro adicionales son sondeos de `nmap -sV` (`/HNAP1`, `/evox/about`). El escaneo de versiones también deja huella en la capa de aplicación.
- **Correlación exacta:** el `x-request-id` que recibió Kali al pedir `/docs` (`36c471b6…`) es el mismo `rid` del `access.log` y de la señal. Responde quién (`192.168.61.130`), cuándo (15:05:12), qué pidió (`GET /docs`) y qué respondió el servicio (`404`).
- **Hallazgo 3:** R4 se disparó sin margen. Nmap tocó 198 puertos, `ufw` registró solo 10 líneas (limita su propio registro) y el umbral era 10.
- **Hallazgo 4:** la unidad queda en `failed` con `status=2/INVALIDARGUMENT` cuando hay señales, y el script relee el log completo: el mismo ataque se reporta de nuevo en cada corrida.

Confirmación de la repetición (corrida de las 15:10:38):

```text
oct 11 15:10:38 lab3-server python[14908]: [SENAL] R1-enumeracion-404 ip=192.168.61.130 eventos=11 2026-10-11T15:05:04+00:00 -> 2026-10-11T15:05:24+00:00 […]
oct 11 15:10:38 lab3-server python[14908]: [SENAL] R4-escaneo-ufw-block ip=192.168.61.130 eventos=10 […]
oct 11 15:10:38 lab3-server systemd[1]: muvautomation-detect.service: Failed with result 'exit-code'.
```

---

## 7. Correcciones y retest

### 7.1 Commit `45a1ec3`: firewall reproducible y detección sin repetición

Tras `git pull` y una nueva ejecución del script:

```text
[4] Firewall: primero allow, luego deny, y se activa (V14)
Skipping adding existing rule
[… todas las reglas ya existían …]
[ 1] 80/tcp                     ALLOW IN    192.168.61.0/24
[ 2] 22/tcp                     LIMIT IN    192.168.61.0/24
[ 3] 443/tcp                    ALLOW IN    192.168.61.0/24
[ 4] 53                         ALLOW OUT   Anywhere                   (out)
[…]
```

El script ya es idempotente y deja el mismo estado que antes se obtuvo a mano. La exclusión de la IP de administración en fail2ban se conserva:

```bash
sudo grep ignoreip /etc/fail2ban/jail.d/*.local
```

```text
/etc/fail2ban/jail.d/muvautomation.local:ignoreip  = 127.0.0.1/8 ::1 192.168.61.1
/etc/fail2ban/jail.d/sshd-lab3.local:ignoreip  = 127.0.0.1/8 ::1 192.168.61.1
```

Retest de la detección:

```bash
journalctl -u muvautomation-detect --since '5 minutes ago' --no-pager | tail -20
```

```text
oct 11 15:43:04 […] [SENAL] R1-enumeracion-404 ip=192.168.61.130 eventos=11 […]
oct 11 15:43:04 […] muvautomation-detect.service: Failed with result 'exit-code'.        <- version anterior
oct 11 15:44:35 […] [SENAL] R1-enumeracion-404 ip=192.168.61.130 eventos=11 […]
oct 11 15:44:35 […] [SENAL] R4-escaneo-ufw-block ip=192.168.61.130 eventos=10 […]
oct 11 15:44:35 […] muvautomation-detect.service: Deactivated successfully.              <- version nueva
oct 11 15:45:34 […] Sin senales con el umbral configurado.
oct 11 15:45:34 […] muvautomation-detect.service: Deactivated successfully.
```

Interpretación: con la versión nueva la unidad ya no queda en `failed`; el ataque se reporta una última vez y la corrida siguiente dice "Sin señales". Hallazgo 4 corregido.

### 7.2 Hallazgo 5: el banner de SSH no se aplicaba

El script terminó en `Listo.` sin avisos, pero la verificación mostró que el control no estaba activo:

```bash
sudo sshd -T | grep -i debianbanner
sudo grep -ci debianbanner /etc/ssh/sshd_config.d/00-lab3.conf
```

```text
debianbanner yes
0
```

Causa, reproducida en las mismas condiciones del script:

```bash
sudo bash -c 'set -o pipefail; sshd -T 2>/dev/null | grep -qi "^debianbanner"; echo "resultado=$? detalle=${PIPESTATUS[*]}"'
```

```text
resultado=141 detalle=141 0
```

Interpretación: `grep` sí encontró la directiva (su `0`), pero al cerrar la lectura en cuanto la halló, `sshd -T` murió por corte de tubería (`141`). Con `pipefail`, el script tomó ese `141` como "no soportado" y omitió la línea. La corrección guarda la salida en una variable antes de buscar.

### 7.3 Commits `4c67526` y `efc0607`: retest

```bash
sudo sshd -T | grep -i debianbanner; systemctl cat muvautomation-detect.service | grep SuccessExitStatus
```

```text
debianbanner no
SuccessExitStatus=10
```

Confirmación desde Kali:

```bash
date -u; nmap -sV -p 22 192.168.61.129
```

```text
Sun Oct 11 04:49:42 PM UTC 2026
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 (protocol 2.0)
```

| Momento | Lo que revela el puerto 22 |
|---|---|
| 15:04 UTC (antes) | `OpenSSH 10.2p1 Ubuntu 2ubuntu3.6 (Ubuntu Linux; protocol 2.0)` |
| 16:49 UTC (después) | `OpenSSH 10.2p1 (protocol 2.0)` |

Interpretación: desaparecen la distribución y el nivel de parche. El número de versión de OpenSSH sigue visible porque el protocolo lo exige (riesgo residual). El código de salida para "hay señales" pasó de 2 a 10, para no confundirse con un error de uso de Python.

---

## 8. Captura de red

Demuestra qué puede ver un observador en la red según el protocolo.

```bash
# Ubuntu
sudo timeout 90 tcpdump -i ens33 -nn -s0 -w /tmp/lab3-red.pcap host 192.168.61.130
# Kali, durante esos 90 segundos
date -u; curl -i http://192.168.61.129/; curl -ki https://192.168.61.129/no-existe-pcap
```

```text
42 packets captured
42 packets received by filter
0 packets dropped by kernel
```

**Puerto 80 (HTTP):**

```bash
sudo tcpdump -nn -A -r /tmp/lab3-red.pcap 'port 80' | head -40
```

```text
16:53:47.794696 IP 192.168.61.130.60738 > 192.168.61.129.80: Flags [P.], […] length 78: HTTP: GET / HTTP/1.1
GET / HTTP/1.1
Host: 192.168.61.129
User-Agent: curl/8.20.0
Accept: */*

16:53:47.800981 IP 192.168.61.129.80 > 192.168.61.130.60738: Flags [P.], […] length 353: HTTP: HTTP/1.1 301 Moved Permanently
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Sun, 11 Oct 2026 16:53:47 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive
Location: https://192.168.61.129/

<html>
<head><title>301 Moved Permanently</title></head>
[…]
```

**Puerto 443 (HTTPS):**

```bash
sudo tcpdump -nn -r /tmp/lab3-red.pcap 'port 443' | head -15
```

```text
16:53:47.826373 IP 192.168.61.130.42626 > 192.168.61.129.443: Flags [S], […] length 0
16:53:47.827668 IP 192.168.61.129.443 > 192.168.61.130.42626: Flags [S.], […] length 0
16:53:47.828327 IP 192.168.61.130.42626 > 192.168.61.129.443: Flags [.], ack 1, […] length 0
16:53:47.853834 IP 192.168.61.130.42626 > 192.168.61.129.443: Flags [P.], […] length 1675
16:53:47.893617 IP 192.168.61.129.443 > 192.168.61.130.42626: Flags [P.], […] length 2839
[… solo tamaños, sin texto …]
```

**Comprobación directa:**

```bash
sudo tcpdump -nn -A -r /tmp/lab3-red.pcap 'port 443' 2>/dev/null | grep -c 'no-existe-pcap'
sudo tcpdump -nn -A -r /tmp/lab3-red.pcap 'port 80' 2>/dev/null | grep -c 'GET / HTTP'
```

```text
0
2
```

Interpretación:

- Por HTTP son legibles el método, la ruta, el `User-Agent`, las cabeceras de respuesta y el cuerpo. El `2` corresponde a una sola petición, que `tcpdump` imprime en la línea de resumen y en el volcado.
- Por HTTPS la ruta `/no-existe-pcap` no aparece en ningún paquete. Lo que TLS no oculta: IP, puertos, momento y tamaño de cada mensaje.
- El archivo contiene solo tráfico entre las dos máquinas del laboratorio. Se conservó en `/home/ubuntu/lab3-red.pcap` (9978 bytes).

---

## 9. Controles de la API desde Kali

Las claves se cargaron en variables de la terminal con `read -rs` y se comprobaron solo por longitud:

```bash
B=https://192.168.61.129; echo ${#EMISOR} ${#ANA} ${#JUAN}
```

```text
64 64 64
```

Pruebas (17:06:43 a 17:07:14 UTC):

```bash
date -u
curl -ks -o /dev/null -w "%{http_code} GET /alerts sin clave\n" $B/alerts
curl -ks -o /dev/null -w "%{http_code} POST /alerts sin clave\n" -X POST $B/alerts -H 'Content-Type: application/json' -d '{}'
ID=$(curl -ks -X POST $B/alerts -H 'Content-Type: application/json' -H "X-API-Key: $EMISOR" \
  -d '{"severity":"critical","tactic":"Exfiltration","technique":"T1041 - Exfiltration Over C2 Channel","hostname":"DB-LAB-01","description":"Validacion en VM"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])'); echo "alerta=$ID"
curl -ks -o /dev/null -w "%{http_code} severidad invalida\n" -X POST $B/alerts -H 'Content-Type: application/json' -H "X-API-Key: $EMISOR" \
  -d '{"severity":"urgente","tactic":"x","technique":"x","hostname":"H","description":"x"}'
curl -ks -o /dev/null -w "%{http_code} lector consulta\n" "$B/alerts?min_score=70" -H "X-Analyst-Key: $JUAN"
for K in "$JUAN" "$ANA" "$ANA"; do curl -ks -o /dev/null -w "%{http_code} close\n" -X POST $B/alerts/$ID/actions \
  -H 'Content-Type: application/json' -H "X-Analyst-Key: $K" -d '{"action":"close"}'; done; date -u
```

```text
Sun Oct 11 05:06:43 PM UTC 2026
401 GET /alerts sin clave
401 POST /alerts sin clave
alerta=79fc84c5-e05f-4462-98e3-b8aa6c799a89
422 severidad invalida
200 lector consulta
403 close
201 close
409 close
Sun Oct 11 05:07:14 PM UTC 2026
```

| Prueba | Resultado | Control |
|---|---|---|
| Consultar o ingresar sin clave | `401` | G10, G16 |
| Ingresar con la clave del emisor | Alerta creada | Emisor autenticado |
| Severidad inexistente | `422` | Validación de entrada (G9) |
| Lector consulta | `200` | Rol `lector` |
| Lector intenta cerrar | `403` | Separación de roles |
| Respondedora cierra | `201` | Rol `respondedor` |
| Cerrar de nuevo | `409` | Estado coherente |

**Registro en el servidor:**

```bash
sudo grep 79fc84c5 /var/log/muvautomation/actions.log
sudo tail -n 2 /var/log/muvautomation/escalations.log
```

```text
{"timestamp": "2026-10-11T17:06:55.869711+00:00", "action": "create_alert", "method": "POST", "path": "/alerts", "client_ip": "192.168.61.130", "alert_id": "79fc84c5-…", "actor": "emisor:falcon-api-key", "result": "ok", "request_id": "c7f4245287da19374b8eec6a58544845"}
{"timestamp": "2026-10-11T17:06:55.894890+00:00", "action": "alert_classified", "alert_id": "79fc84c5-…", "actor": "system:motor-clasificacion", "result": "alta (90)", "request_id": "c7f4245287da19374b8eec6a58544845"}
{"timestamp": "2026-10-11T17:06:55.896576+00:00", "action": "alert_escalated", "alert_id": "79fc84c5-…", "actor": "system:motor-escalamiento", "result": "auto", "request_id": "c7f4245287da19374b8eec6a58544845"}
{"timestamp": "2026-10-11T17:07:14.011012+00:00", "action": "action_close_forbidden", […] "actor": "analyst:juan", "result": "forbidden", "request_id": "b653514b2302205306291735792466f4"}
{"timestamp": "2026-10-11T17:07:14.071082+00:00", "action": "action_close", […] "actor": "analyst:ana", "result": "ok", "request_id": "74769287c18f251bf099c68a3e55d2a6"}
{"timestamp": "2026-10-11T17:07:14.106425+00:00", "action": "action_close", […] "actor": "analyst:ana", "result": "conflict", "request_id": "fc2065095eb364f6df21db5dd63f9a33"}

{"timestamp": "2026-10-11T17:06:55.895792+00:00", "event": "alert_escalated", "reason": "auto: risk_score 90 >= 70", "alert_id": "79fc84c5-…", "severity": "critical", "risk_score": 90, "classification": "alta", "technique": "T1041 - Exfiltration Over C2 Channel", "hostname": "DB-LAB-01"}
```

Interpretación:

- Cada acción tiene autor (`emisor:…`, `analyst:…`, `system:motor-…`) y origen real (`192.168.61.130`, no la IP de Nginx).
- La alerta se clasificó en `alta (90)` y se escaló sola 25 milisegundos después de crearse.
- Creación, clasificación y escalamiento comparten el mismo `request_id`.
- La detección no generó señal (`Sin senales` a las 17:06 y 17:07): dos respuestas 401 y una 403 están por debajo del umbral. El uso normal no produce falsas alarmas.

**Hallazgo 6.** La petición con severidad inválida no dejó entrada en el log de auditoría. Se confirmó siguiendo su `request_id`:

```bash
RID=$(sudo grep '" 422 ' /var/log/nginx/access.log | tail -n 1 | grep -o 'rid=[0-9a-f]*' | cut -d= -f2); echo "rid=$RID"; sudo grep -c "$RID" /var/log/muvautomation/actions.log
```

```text
rid=310244bff57f065bccc0d550094473b4
0
```

Nota de método: una primera comprobación que buscaba el texto `422` dio un falso positivo, porque coincidió con los dígitos de un `request_id` sin relación. Seguir la petición por su identificador resolvió la duda sin ambigüedad.

---

## 10. Rotación de claves y auditoría

Al terminar las pruebas que usaban las claves de analista, se rotaron. El comando no muestra los valores nuevos:

```bash
sudo sed -i "s/^\(MUV_ANALYSTS=ana:respondedor:\)[^;]*\(;juan:lector:\).*/\1$(openssl rand -hex 32)\2$(openssl rand -hex 32)/" /etc/muvautomation.env \
  && sudo systemctl restart muvautomation-api && systemctl is-active muvautomation-api
```

```text
active
```

Registro de auditoría sobre el archivo de secretos:

```bash
sudo ausearch -k lab3_secrets -ts recent -i | grep -E 'type=SYSCALL' | tail -n 3
```

```text
type=SYSCALL msg=audit(11/10/26 17:10:13.702:13866) : arch=x86_64 syscall=rename success=yes exit=0 […] auid=ubuntu uid=root […] comm=sed exe=/usr/bin/sed […] key=lab3_secrets
type=SYSCALL msg=audit(11/10/26 17:10:24.186:13880) : arch=x86_64 syscall=openat success=yes exit=3 […] auid=ubuntu uid=root […] comm=grep exe=/usr/bin/grep […] key=lab3_secrets
```

Interpretación: quedan registradas tanto la modificación (`sed`, `rename`) como la lectura posterior (`grep`, `openat`). El campo `auid=ubuntu` conserva quién inició la sesión aunque el comando corriera como `root`, lo que permite atribuir la acción a una persona.

**Riesgo asociado: exposición de credenciales al usar asistentes de IA.** Al apoyarse en una IA para validar un despliegue es habitual copiarle salidas de comandos; si una incluye secretos, estos salen del entorno controlado. Controles aplicados: revisar cada salida antes de compartirla, comprobar los secretos sin mostrarlos (longitud, conteo de coincidencias), rotar las credenciales tras la fase de pruebas y auditar el acceso al archivo de secretos. Mitigación de fondo: sustituir las claves estáticas por tokens de vida corta.

---

## 11. Validación final de controles

### 11.1 Bloqueo automático

Trece peticiones sin credencial desde Kali. No se intenta adivinar ninguna clave.

```bash
date -u; for i in $(seq 1 13); do curl -ks --max-time 5 -o /dev/null -w "%{http_code} intento $i\n" https://192.168.61.129/alerts; done; date -u
```

```text
Sun Oct 11 05:21:21 PM UTC 2026
401 intento 1
401 intento 2
401 intento 3
401 intento 4
401 intento 5
429 intento 6
[… 429 hasta el intento 13 …]
Sun Oct 11 05:21:21 PM UTC 2026
```

```bash
sudo fail2ban-client status muvautomation; sudo ufw status numbered | head -n 6
journalctl -u muvautomation-detect --since '17:21' --no-pager | grep -E 'SENAL|Sin senales' | tail -n 4
```

```text
   |- Currently banned: 1
   `- Banned IP list:   192.168.61.130
[ 1] Anywhere                   REJECT IN   192.168.61.130             # by Fail2Ban after 10 attempts against muvautomation

oct 11 17:22:21 lab3-server python[64953]: [SENAL] R2-fuerza-bruta-401-429 ip=192.168.61.130 eventos=13 2026-10-11T17:21:21+00:00 -> 2026-10-11T17:21:21+00:00 ej=['GET /alerts HTTP/2.0'] […]
```

Confirmación del veto desde Kali (17:23:20):

```text
000
salida=7
```

Interpretación: la aplicación cortó en el sexto intento; fail2ban vetó la IP en el firewall; la detección generó la señal R2 un minuto después. Las 13 peticiones salieron en el mismo segundo, antes de que fail2ban reaccionara: **fail2ban tiene latencia** y la capa de la aplicación cubre esa ventana. **Hallazgo 7:** el veto usaba `REJECT` (`salida=7`, rechazo explícito) en lugar de descartar en silencio.

Veto levantado al terminar:

```bash
sudo fail2ban-client set muvautomation unbanip 192.168.61.130
```

### 11.2 Versiones de TLS

```bash
date -u; nmap --script ssl-enum-ciphers -p 443 192.168.61.129
```

```text
Sun Oct 11 05:24:35 PM UTC 2026
PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|     compressors:
|       NULL
|     cipher preference: client
|   TLSv1.3:
|     ciphers:
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (X25519MLKEM768) - A
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (X25519MLKEM768) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (X25519MLKEM768) - A
|     cipher preference: client
|_  least strength: A
```

Interpretación: solo TLS 1.2 y 1.3; no se ofrecen TLS 1.0, 1.1 ni SSLv3 (G2). Todos los cifrados son ECDHE con AEAD, sin compresión, calificación A.

### 11.3 Escaneo de puertos con la regla R4 corregida

```bash
# Kali
date -u; sudo nmap -sS -p 1-200 192.168.61.129; date -u
# Ubuntu
journalctl -u muvautomation-detect --since '3 minutes ago' --no-pager | grep -E 'SENAL|Sin senales' | tail -n 4
```

```text
Sun Oct 11 05:25:23 PM UTC 2026
Not shown: 198 filtered tcp ports (no-response)
22/tcp open  ssh
80/tcp open  http
Sun Oct 11 05:25:29 PM UTC 2026

oct 11 17:24:31 […] Sin senales con el umbral configurado.
oct 11 17:25:34 […] [SENAL] R4-escaneo-ufw-block ip=192.168.61.130 eventos=10 2026-10-11T17:25:27.624422+00:00 -> 2026-10-11T17:25:27.628467+00:00 ej=['TCP/110', 'TCP/111', 'TCP/113']
oct 11 17:26:41 […] Sin senales con el umbral configurado.
```

Interpretación: señal nueva con la hora de este escaneo (no la de las 15:05), 10 eventos contra un umbral de 5, y sin repetición. Detección a los 7 segundos; la latencia real va de 0 a unos 70 segundos según el momento del ciclo.

**Bloqueos salientes del propio servidor** (para comprobar que no se le atribuye un escaneo):

```bash
date -u; ping -c 7 -W 1 192.168.61.130 | tail -n 2; sudo grep -c 'UFW BLOCK\] IN= OUT=' /var/log/ufw.log
sleep 75; journalctl -u muvautomation-detect --since '3 minutes ago' --no-pager | grep -E 'SENAL|Sin senales' | tail -n 3
```

```text
dom 11 oct 2026 17:30:04 UTC
7 packets transmitted, 0 received, 100% packet loss, time 6182ms
9
oct 11 17:31:11 lab3-server python[68194]: Sin senales con el umbral configurado.
```

Interpretación: 7 bloqueos salientes nuevos, por encima del umbral, y R4 no señaló al servidor. Hallazgo 3 corregido.

### 11.4 Rotación de logs (simulación)

```bash
sudo logrotate -d /etc/logrotate.d/muvautomation 2>&1 | tail -n 20
```

```text
rotating pattern: /var/log/muvautomation/*.log weekly empty log files are not rotated, log files >= 52428800 are rotated earlier, (8 rotations), old logs are removed
switching euid from 0 to 999 and egid from 0 to 983 (pid 68682)
considering log /var/log/muvautomation/actions.log
  log does not need rotating (log has already been rotated)
considering log /var/log/muvautomation/escalations.log
  log does not need rotating (log has already been rotated)
switching euid from 999 to 0 and egid from 983 to 0 (pid 68682)
```

Interpretación: configuración válida; la rotación se ejecuta con el usuario del servicio (`uid 999`), no como `root`.

### 11.5 Pruebas automatizadas en el servidor

En un entorno temporal, sin privilegios y sin tocar el entorno de producción:

```bash
python3 -m venv /tmp/venv-pruebas && /tmp/venv-pruebas/bin/pip install -q -r /opt/fdsi-lab3/requirements-dev.txt
cd /opt/fdsi-lab3 && MUV_DATA_DIR=$(mktemp -d) MUV_LOG_DIR=$(mktemp -d) PYTHONDONTWRITEBYTECODE=1 /tmp/venv-pruebas/bin/python -m pytest -q -p no:cacheprovider
```

```text
92 passed, 3 warnings in 2.57s
```

Las 3 advertencias eran la misma (`on_event is deprecated`).

### 11.6 Reinicio del servidor

Antes del reinicio se tomó una instantánea en VMware (`lab3-validado-antes-reinicio`) y se confirmó que los servicios arrancan solos:

```bash
systemctl is-enabled nginx muvautomation-api fail2ban auditd ufw muvautomation-detect.timer
sudo reboot
```

```text
enabled
enabled
enabled
enabled
enabled
enabled
```

Verificación tras el arranque:

```bash
uptime -s; systemctl is-active nginx muvautomation-api fail2ban auditd; ip -br a | grep ens33
sudo ufw status verbose | head -n 8; sudo fail2ban-client status | tail -n 2
sudo sshd -T | grep -Ei '^(passwordauthentication|debianbanner) '; sudo auditctl -l | wc -l; sysctl net.ipv4.tcp_syncookies kernel.kptr_restrict
curl -ks -o /dev/null -w "GET=%{http_code}\n" https://127.0.0.1/
journalctl -u muvautomation-detect -b --no-pager | grep -c SENAL; systemctl show nginx -p NoNewPrivileges -p ProtectHome
```

```text
2026-10-11 17:46:20
active
active
active
active
ens33            UP             192.168.61.129/24 […]
Status: active
Logging: on (medium)
Default: deny (incoming), deny (outgoing), disabled (routed)
|- Number of jail:      2
`- Jail list:   muvautomation, sshd
passwordauthentication no
debianbanner no
16
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
GET=200
0
ProtectHome=yes
NoNewPrivileges=yes
```

Interpretación: todos los controles se recuperan solos. El `0` confirma que el estado de la detección sobrevivió al reinicio y no se volvieron a reportar los ataques anteriores. Una petición `HEAD` a la raíz devolvió `405` con `allow: GET` (**hallazgo 8**, menor). El bloqueo por IP de la aplicación vive en memoria y se pierde al reiniciar; los vetos de fail2ban persisten.

---

## 12. Segunda ronda de correcciones y retest

### 12.1 Commits `6f498ce` y `e06b296`

```bash
cd /opt/fdsi-lab3 && sudo git pull && sudo git log --oneline -1
sudo LAB_CIDR=192.168.61.0/24 ADMIN_USER=ubuntu SSH_CLIENT="$SSH_CLIENT" bash deploy/harden-host.sh
```

```text
e06b296 (HEAD -> vm-test, origin/vm-test) fix: veto silencioso (DENY) tambien en el jail sshd
→ Overall exposure level for muvautomation-api.service: 1.2 OK 🙂
Listo. […]
```

Comprobaciones:

```bash
sudo fail2ban-client get muvautomation action ufw blocktype; sudo fail2ban-client get sshd action ufw blocktype
curl -ksI https://127.0.0.1/ | head -n 1
[…] pytest -q -p no:cacheprovider 2>&1 | tail -n 1
journalctl -u muvautomation-detect --since '4 minutes ago' --no-pager | grep -E 'SENAL|Sin senales' | tail -n 4
```

```text
deny
deny
HTTP/2 200
97 passed, 1 warning in 2.70s
oct 11 18:09:55 […] Sin senales con el umbral configurado.
oct 11 18:11:02 […] [SENAL] R5-salida-bloqueada-ufw ip=192.168.61.129 eventos=7 2026-10-11T17:30:04.512206+00:00 -> 2026-10-11T17:30:10.693283+00:00 ej=['ICMP/-->192.168.61.130']
oct 11 18:12:05 […] Sin senales con el umbral configurado.
```

Interpretación: `HEAD /` ya responde `200` (hallazgo 8). La regla nueva R5 reportó una vez los 7 bloqueos salientes de las 17:30, con el destino como evidencia, y no repitió. La advertencia restante de las pruebas es de la herramienta de pruebas (`httpx`), no de la aplicación.

**Errores de validación en el log de auditoría** (hallazgo 6), 18:16:17:

```bash
# Kali
curl -ks -o /dev/null -w "%{http_code} JSON roto sin clave\n" -X POST $B/alerts -H 'Content-Type: application/json' -d '{mal'
curl -ks -o /dev/null -w "%{http_code} severidad invalida con clave\n" -X POST $B/alerts -H 'Content-Type: application/json' -H "X-API-Key: $EMISOR" -d '{"severity":"urgente",[…]}'
# Ubuntu
sudo grep validation_error /var/log/muvautomation/actions.log | tail -n 3
```

```text
422 JSON roto sin clave
422 severidad invalida con clave

{"timestamp": "2026-10-11T18:16:17.685423+00:00", "action": "validation_error", […] "client_ip": "192.168.61.130", "actor": null, "result": "validation_error", "request_id": "d246cb99…", "errors": [{"loc": ["body", "1"], "type": "json_invalid"}]}
{"timestamp": "2026-10-11T18:16:17.749836+00:00", "action": "validation_error", […] "client_ip": "192.168.61.130", "actor": null, "result": "validation_error", "request_id": "9f65a820…", "errors": [{"loc": ["body", "severity"], "type": "literal_error"}]}
```

Interpretación: el error ya queda registrado, con el campo que falló y sin el valor enviado. **Hallazgo 9:** una petición con JSON mal formado y sin clave recibe `422` en vez de `401` y escribe en el log; el cuerpo se analiza antes de comprobar la credencial. Además, ambas entradas dicen `actor: null` y no se distinguen.

**Veto silencioso** (hallazgo 7), 18:29:27:

```bash
date -u; for i in $(seq 1 13); do curl -ks --max-time 5 -o /dev/null -w "%{http_code} intento $i\n" $B/alerts; done; sleep 5
curl -ks --max-time 5 -o /dev/null -w "%{http_code} tras el veto\n" $B/; echo "salida=$?"
```

```text
[… 5 x 401, 8 x 429 …]
000 tras el veto
salida=28

[ 1] Anywhere                   DENY IN     192.168.61.130             # by Fail2Ban after 10 attempts against muvautomation
```

| | Antes | Después |
|---|---|---|
| Regla | `REJECT IN` | `DENY IN` |
| Código de salida de `curl` | `7` (conexión rechazada) | `28` (tiempo agotado) |

### 12.2 Commit `b9e93c1`

```bash
cd /opt/fdsi-lab3 && sudo git pull && sudo git log --oneline -1
[…] pytest -q -p no:cacheprovider 2>&1 | tail -n 1
```

```text
b9e93c1 (HEAD -> vm-test, origin/vm-test) fix: 401 en vez de 422 sin credencial valida; validation_error solo con actor autenticado
102 passed, 1 warning in 2.90s
```

Retest desde Kali (20:30:29):

```bash
date -u
curl -ks -o /dev/null -w "%{http_code} JSON roto sin clave\n" -X POST $B/alerts -H 'Content-Type: application/json' -d '{roto'
curl -ks -o /dev/null -w "%{http_code} JSON roto con clave\n" -X POST $B/alerts -H 'Content-Type: application/json' -H "X-API-Key: $EMISOR" -d '{roto'
```

```text
Sun Oct 11 08:30:29 PM UTC 2026
401 JSON roto sin clave
422 JSON roto con clave
```

```bash
sudo tail -n 2 /var/log/muvautomation/actions.log
```

```text
{"timestamp": "2026-10-11T20:30:30.098466+00:00", "action": "create_alert_unauthorized", "method": "POST", "path": "/alerts", "client_ip": "192.168.61.130", "alert_id": null, "actor": null, "result": "unauthorized", "request_id": "8b2d4ff37cd781923601d5470ed6e2b7"}
{"timestamp": "2026-10-11T20:30:30.135506+00:00", "action": "validation_error", "method": "POST", "path": "/alerts", "client_ip": "192.168.61.130", "actor": "emisor:falcon-api-key", "result": "validation_error", "request_id": "198a58c74985cb358395849a284d9e93", "errors": [{"loc": ["body", "1"], "type": "json_invalid"}]}
```

Interpretación: sin credencial la respuesta es `401` y el intento cuenta para el bloqueo, fail2ban y la regla R2; con credencial válida se registra `validation_error` con el actor real. Hallazgo 9 corregido.

---

## 13. Línea de tiempo Purple Team

| Hora UTC | Acción Red Team (Kali) | Evidencia Blue Team (Ubuntu) | Conclusión |
|---|---|---|---|
| 15:04:51 | `nmap -sV` a 22, 80, 443 | 4 respuestas 404 a rutas de sondeo en `access.log` | El escaneo de versiones deja huella en la aplicación |
| 15:05:12 | `GET /` por HTTP | `301` en `access.log` | El puerto 80 no sirve contenido |
| 15:05:12 | `GET /docs` | `404`, `rid=36c471b6…` igual al `x-request-id` recibido | Correlación exacta confirmada |
| 15:05:24 | 6 rutas inexistentes | 6 × `404` en `access.log` | Telemetría de enumeración |
| 15:05:34 | — | Señal R1 automática, 11 eventos | Detección validada a los 10 s |
| 15:05:45 | `nmap -sS` puertos 1–200 | 10 líneas `[UFW BLOCK]`; nada en `access.log` | Un escaneo SYN solo se ve en la capa de host |
| 15:10:38 | — | Señal R4 automática | Detección de red por el log del firewall |
| 16:53:47 | `GET /` por HTTP y ruta por HTTPS | PCAP: HTTP legible, HTTPS cifrado | El contenido por HTTP es visible en la red |
| 17:06:43 | Peticiones sin clave | 2 × `unauthorized` en `actions.log` | Acceso denegado y registrado |
| 17:06:55 | Alerta crítica con clave del emisor | Creada, clasificada `alta (90)` y escalada, mismo `request_id` | Motores y trazabilidad correctos |
| 17:07:14 | Lector intenta cerrar | `forbidden` con `actor: analyst:juan` | Separación de roles |
| 17:21:21 | 13 peticiones sin credencial | 5 × 401, 8 × 429; veto de fail2ban | Defensa en capas |
| 17:22:21 | — | Señal R2, 13 eventos | Detección al minuto |
| 17:25:27 | `nmap -sS` puertos 1–200 | Señal R4 a las 17:25:34, 10 eventos | Regla corregida, con margen |
| 18:29:27 | 13 peticiones sin credencial | Veto `DENY IN`; cliente sin respuesta | Veto silencioso |
| 20:30:29 | JSON mal formado, sin y con clave | `401` no autorizado; `422` con actor | Sin escritura anónima en el log |

---

## 14. Resumen de hallazgos

Cada hallazgo tiene su ciclo completo: hipótesis o prueba, evidencia, causa, corrección y retest.

| # | Hallazgo | Evidencia | Corrección | Retest |
|---|---|---|---|---|
| 1 | El script no borraba `OpenSSH ALLOW Anywhere`; SSH seguía abierto | Regla en la posición 1, antes del `LIMIT` | El script borra las reglas abiertas tras crear las restringidas | Reglas finales solo con el CIDR |
| 2 | SSH revelaba distribución y nivel de parche | `OpenSSH 10.2p1 Ubuntu 2ubuntu3.6` | `DebianBanner no` | `OpenSSH 10.2p1` |
| 3 | R4 sin margen y sin distinguir dirección | 10 eventos contra umbral 10; `IN=` vacío con origen en el servidor | Umbral 5; solo bloqueos entrantes | 10 contra 5; 7 salientes sin señal |
| 4 | Alertas repetidas y unidad en `failed` | La misma señal a las 15:05:34 y 15:10:38 | Archivo de estado; código de salida 10 | "Sin señales" en la corrida siguiente |
| 5 | El banner de SSH no se aplicaba en silencio | `debianbanner yes`; `resultado=141 detalle=141 0` | Salida de `sshd -T` en variable; aviso si sigue en `yes` | `debianbanner no` |
| 6 | Errores de validación sin registro de auditoría | `rid` del 422 con 0 coincidencias en `actions.log` | Entrada `validation_error` sin el valor enviado | Entrada con `loc` y `type` |
| 7 | fail2ban respondía con rechazo explícito | `REJECT IN`, `salida=7` | `ufw[blocktype=deny]` en ambos jails | `DENY IN`, `salida=28` |
| 8 | `HEAD /` devolvía 405 | `HTTP/2 405`, `allow: GET` | La raíz acepta `GET` y `HEAD` | `HTTP/2 200` |
| 9 | Un anónimo recibía 422 y escribía en el log | `422 JSON roto sin clave`, `actor: null` | 401 sin credencial; `validation_error` solo con actor | `401` y `422` con actor |

Pruebas automatizadas: de 89 a 102, todas aprobadas en el servidor.

Ninguna prueba encontró un acceso indebido a datos. Los hallazgos fueron de despliegue, detección y trazabilidad.

---

## 15. Riesgos residuales y pruebas no realizadas

### Riesgos que permanecen

- **Identidad básica:** claves estáticas por analista y por emisor, sin expiración, segundo factor ni revocación.
- **Sin filtrado de campos por rol:** `/network/devices` entrega `mgmt_ip` a cualquier rol.
- **Sin integridad criptográfica** en la base de datos ni en los logs, y todos residen en el mismo servidor que el servicio.
- **Certificado autofirmado:** los clientes deben confiar en él de forma explícita.
- **IP por DHCP** escrita de forma fija en Nginx y en el certificado.
- **Versión de OpenSSH visible:** lo exige el protocolo; se compensa con acceso por CIDR, llave, límite de conexiones y fail2ban.
- **TLS oculta el contenido**, pero no las IP, los puertos, los tiempos ni los tamaños.
- **Latencia de las defensas:** fail2ban reacciona después de una ráfaga rápida, y la detección tarda entre 0 y unos 70 segundos.
- **Bloqueo por IP en memoria:** se pierde al reiniciar la aplicación.
- **Falsos positivos:** varios usuarios detrás de una misma IP suman sus errores; un enlace roto legítimo genera 404 repetidos.
- **Falsos negativos:** un escaneo lento o repartido entre varias IP no alcanza el umbral.
- **Parches pendientes:** 67 actualizaciones del sistema, 39 de seguridad.
- **Dependencia de pruebas:** la advertencia de `pytest` sugiere un paquete de reemplazo que no se ha verificado; no se instaló.

### Pruebas no realizadas

- **Inspección pasiva con OWASP ZAP** sobre el servicio desplegado.
- **Línea base HTTP en la VM actual:** el servidor ya estaba endurecido, de modo que el "antes" proviene de las capturas de la Parte 1 y de la salida del firewall de la sección 2. La captura de red muestra el `301` en claro, no contenido de la aplicación.
- **Acceso desde fuera del segmento `192.168.61.0/24`:** no hay un tercer equipo en otra red para comprobar el rechazo por origen.
- **Rotación real de logs:** solo se ejecutó en modo simulación, para conservar los registros como evidencia.
