# Servicio de identidad (Etapa D)

Servicio propio y pequeño dentro del proyecto (`app/identity.py`), con bibliotecas probadas: no se
inventa criptografía. Sustituye las claves estáticas de analista por sesiones con token de vida
corta. La clave del emisor (Falcon simulado, identidad de máquina) sigue siendo una API key.

## Decisiones

| Tema | Decisión | Por qué |
|---|---|---|
| Propio vs Keycloak | Propio y pequeño | La VM ya corre Nginx, API, fail2ban y auditd; Keycloak añade Java, ~1 GB de RAM y otro servicio que endurecer. Los claims y endpoints siguen la forma de OIDC para poder migrar |
| Contraseñas | Argon2id (`argon2-cffi`), 12–128 caracteres | El máximo evita usar Argon2 para agotar CPU/memoria |
| Tokens de acceso | JWT **EdDSA** (Ed25519), 10 min, `iss`/`aud`/`exp`/`jti`; el algoritmo se fija al validar | La API solo necesita la clave pública; no hay confusión HS256/none |
| Renovación | Opaco, guardado con hash SHA-256, **rotado en cada uso**; reutilizar uno ya usado revoca toda la sesión | Un token robado se detecta cuando ambos lo usan |
| Segundo factor | TOTP (RFC 6238), secreto **cifrado** (Fernet), código de un solo uso. **Obligatorio para `respondedor`** (puede escalar y cerrar); opcional para `lector` | El rol con más poder no depende de una sola credencial |
| Estado | SQLite (revocaciones, esperas por cuenta, fallos por IP) | Un reinicio ya no deshace un bloqueo ni una revocación |
| Altas | Solo por CLI en el servidor (`deploy/identity-admin.sh`) | Sin usuario por defecto ni registro abierto |
| Claves estáticas de analista | Interruptor `MUV_ALLOW_ANALYST_STATIC_KEYS` (`no` las apaga) | La debilidad original no debe quedar viva indefinidamente |

## Flujo

1. `POST /auth/login` `{username, password, otp?}` → `{access_token, refresh_token, expires_in}`.
2. Peticiones con `Authorization: Bearer <access_token>`. Rol y estado salen de la base, no del
   token: deshabilitar a un usuario surte efecto de inmediato.
3. `POST /auth/refresh` `{refresh_token}` → par nuevo; el anterior queda inservible.
4. `POST /auth/logout` (Bearer) → cierra **siempre** la sesión completa (el token de acceso lleva el
   identificador de sesión `sid`; el de renovación muere aunque el cliente no lo envíe).

**Sesiones.** Cada renovación emite un token de acceso nuevo, pero la sesión tiene un límite
absoluto de 12 h desde el login: al vencer hay que autenticarse de nuevo (contraseña y TOTP).
El token de acceso solo vale mientras su sesión siga viva: cambiar la contraseña, reiniciar el TOTP,
deshabilitar al usuario, cerrar sesión o detectar la reutilización de un token de renovación lo
invalidan **de inmediato**, no a los 10 minutos.

## Protecciones del login

- **Respuesta uniforme:** usuario inexistente, contraseña o código incorrectos devuelven el mismo
  `401 {"detail":"Invalid credentials"}`; un usuario inexistente cuesta lo mismo (hash ficticio).
- **Espera creciente por cuenta e IP** (no bloqueo duro): tras 3 fallos seguidos desde una misma IP
  contra una misma cuenta, 1 s, 2 s, 4 s… tope 120 s; el contador se reinicia tras 15 min sin
  fallos. Durante la espera ni la contraseña correcta pasa, **pero solo para esa IP**: quien conoce un
  usuario no puede dejarlo fuera desde otra dirección. Misma respuesta para cuentas que no existen.
- **Puntería contra una cuenta (regla R6 de `detect.py`):** ≥10 `login_failed` contra la misma cuenta
  en 1 h, de una o de muchas IP, genera una señal. Cubre el ataque lento o distribuido que ni el
  bloqueo por IP ni la espera frenan; **alerta, no bloquea** (bloquear la cuenta permitiría dejar
  fuera al titular).
- **Bloqueo por IP** (el de siempre, 5 fallos en 5 min) y **límite de tasa en Nginx**
  (`/auth/login` y `/auth/refresh`: 20 por minuto por IP): el login es costoso a propósito.
- **Argon2 acotado:** como máximo 2 verificaciones a la vez (≈64 MiB cada una) y **fuera de toda
  transacción**, de modo que la ingesta de alertas no espera a un login; sin hueco en 5 s → 429.
  La unidad systemd limita la memoria (`MemoryHigh=384M`, `MemoryMax=512M`).
- Un cuerpo mal formado en login cuenta como intento fallido (no escribe `validation_error`).
- El log de auditoría registra `login_ok`, `login_failed`, `login_throttled`, `refresh_ok`,
  `refresh_failed`, `refresh_reuse_detected` y `logout`; **nunca** contraseñas, códigos ni tokens.

## Operación

```bash
cd /opt/fdsi-lab3 && sudo git pull && sudo .venv/bin/pip install -r app/requirements.txt

# 1. Claves (se agregan al archivo de secretos sin mostrarlas)
sudo bash deploy/identity-admin.sh gen-keys | sudo tee -a /etc/muvautomation.env >/dev/null
sudo systemctl restart muvautomation-api

# 2. Usuarios (la contraseña se pide sin eco; el TOTP se muestra una sola vez)
sudo bash deploy/identity-admin.sh create-user marta --role lector
sudo bash deploy/identity-admin.sh create-user rosa  --role respondedor
sudo bash deploy/identity-admin.sh list-users

# 3. Verificado el acceso con tokens, apagar las claves estáticas de analista.
#    Agrega la línea si no existe (un archivo creado antes de esta variable no la tiene) o la reemplaza.
sudo bash deploy/identity-admin.sh static-keys off
sudo systemctl restart muvautomation-api
sudo grep -c '^MUV_ALLOW_ANALYST_STATIC_KEYS=' /etc/muvautomation.env   # debe decir 1
# Comprobación: con una clave estática antigua ya debe responder 401
curl -sk -o /dev/null -w "%{http_code}\n" -H "X-Analyst-Key: <clave-antigua>" https://192.168.61.129/alerts
```

`gen-keys` se niega a ejecutarse si el archivo ya tiene `MUV_JWT_PRIVATE_KEY` o `MUV_TOTP_KEY`:
generar otras dejaría a los usuarios enrolados con una clave de TOTP y al servicio descifrando con otra.
Si una variable aparece repetida, el script lee la **última** (igual que systemd).

Reseteo: `set-password` y `enroll-totp` (secreto nuevo) cierran las sesiones abiertas; `disable-user`
cierra todo. No hay recuperación autónoma: el administrador del host es quien la hace.

## Riesgos residuales

- **Un solo servidor:** identidad, API y datos comparten máquina; si se compromete, cae todo.
- **Sin recuperación autónoma:** el administrador es un punto único de dependencia.
- **Reloj:** la expiración de tokens y el TOTP dependen de NTP (ya permitido en la salida filtrada).
- **TOTP:** el secreto cifrado vive en la misma base que la clave que lo descifra (`MUV_TOTP_KEY`
  está en el archivo de entorno); una fuga de ambos compromete el segundo factor.
- **Firma:** la clave privada comparte proceso con la API hasta que el servicio de identidad se separe.
- **Espera por (cuenta, IP):** un atacante que comparte IP con el titular (NAT) lo afecta mientras
  dure su espera (tope 120 s). Un ataque distribuido contra una cuenta no se bloquea: lo señala R6.
- **Sin SSO ni federación:** un único directorio local.
- **Revocación de acceso:** los tokens duran 10 min; el logout y deshabilitar al usuario los
  invalidan de inmediato porque se consulta la base en cada petición.
