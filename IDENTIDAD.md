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
4. `POST /auth/logout` (Bearer, opcionalmente `{refresh_token}`) → revoca el token de acceso y la sesión.

## Protecciones del login

- **Respuesta uniforme:** usuario inexistente, contraseña o código incorrectos devuelven el mismo
  `401 {"detail":"Invalid credentials"}`; un usuario inexistente cuesta lo mismo (hash ficticio).
- **Espera creciente por cuenta** (no bloqueo duro): tras 3 fallos seguidos 1 s, 2 s, 4 s… tope 120 s,
  con la misma respuesta para cuentas que no existen. Durante la espera ni la contraseña correcta pasa.
- **Bloqueo por IP** (el de siempre, 5 fallos en 5 min) y **límite de tasa en Nginx**
  (`/auth/login` y `/auth/refresh`: 20 por minuto por IP): el login es costoso a propósito.
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

# 3. Verificado el acceso con tokens, apagar las claves estáticas de analista
sudo sed -i 's/^MUV_ALLOW_ANALYST_STATIC_KEYS=.*/MUV_ALLOW_ANALYST_STATIC_KEYS=no/' /etc/muvautomation.env
sudo systemctl restart muvautomation-api
```

Reseteo: `set-password` (cierra las sesiones abiertas), `enroll-totp` (secreto nuevo),
`disable-user` (cierra todo). No hay recuperación autónoma: el administrador del host es quien la hace.

## Riesgos residuales

- **Un solo servidor:** identidad, API y datos comparten máquina; si se compromete, cae todo.
- **Sin recuperación autónoma:** el administrador es un punto único de dependencia.
- **Reloj:** la expiración de tokens y el TOTP dependen de NTP (ya permitido en la salida filtrada).
- **TOTP:** el secreto cifrado vive en la misma base que la clave que lo descifra (`MUV_TOTP_KEY`
  está en el archivo de entorno); una fuga de ambos compromete el segundo factor.
- **Firma:** la clave privada comparte proceso con la API hasta que el servicio de identidad se separe.
- **Espera por cuenta:** quien conoce un usuario puede mantenerlo en espera (tope 120 s). Se acepta a
  cambio de no bloquear de forma dura; el límite de tasa por IP limita la capacidad del atacante.
- **Sin SSO ni federación:** un único directorio local.
- **Revocación de acceso:** los tokens duran 10 min; el logout y deshabilitar al usuario los
  invalidan de inmediato porque se consulta la base en cada petición.
