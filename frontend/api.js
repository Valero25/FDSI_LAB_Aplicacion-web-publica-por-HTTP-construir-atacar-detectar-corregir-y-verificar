// Sesion y llamadas a la API (mismo origen, sin CORS).
//
// Los tokens viven SOLO en estas variables del modulo: nada en localStorage, sessionStorage, cookies,
// IndexedDB ni en la URL, y nunca se muestran ni se escriben en la consola. Recargar la pagina obliga a
// iniciar sesion de nuevo (decision aceptada: un XSS o una extension no encuentran tokens guardados).
let accessToken = null;
let refreshToken = null;
let refreshTimer = null;
let refreshInFlight = null;
let onSessionEnd = () => {};

// Se renueva el token de acceso este margen antes de que caduque (el servidor lo emite por 10 min).
const REFRESH_MARGIN_S = 60;
const MIN_REFRESH_DELAY_S = 5;

export class ApiError extends Error {
  constructor(status, detail, retryAfter) {
    super("HTTP " + status);
    this.status = status; // 0 = sin respuesta del servidor
    this.detail = detail; // texto "detail" del servidor (solo para elegir el mensaje)
    this.retryAfter = retryAfter; // segundos de Retry-After, o null
  }
}

export function setSessionEndHandler(handler) {
  onSessionEnd = handler;
}

export function hasSession() {
  return accessToken !== null;
}

// Usuario y rol tomados de los claims publicos del token de acceso, SOLO para adaptar la interfaz
// (p. ej. que acciones ofrecer). La autorizacion real la decide el servidor en cada peticion.
export function sessionInfo() {
  if (accessToken === null) {
    return null;
  }
  try {
    const part = accessToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = part.padEnd(Math.ceil(part.length / 4) * 4, "=");
    const claims = JSON.parse(atob(padded));
    const roles = Array.isArray(claims.roles) ? claims.roles : [];
    return { username: String(claims.sub || ""), role: String(roles[0] || "") };
  } catch {
    return { username: "", role: "" };
  }
}

function retryAfterSeconds(response) {
  const value = Number.parseInt(response.headers.get("Retry-After") || "", 10);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

// Unica llamada a fetch del frontend.
async function send(method, path, { body, auth = true } = {}) {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new ApiError(0, "ruta no valida", null); // solo rutas del mismo origen
  }
  const headers = { Accept: "application/json" };
  const init = {
    method,
    headers,
    credentials: "omit", // sin cookies: la API se autentica solo con el token
    mode: "same-origin",
    cache: "no-store",
    redirect: "error",
    referrerPolicy: "no-referrer",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json"; // la API responde 415 a cualquier otro tipo (F-1)
    init.body = JSON.stringify(body);
  }
  if (auth && accessToken !== null) {
    headers.Authorization = "Bearer " + accessToken;
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError(0, null, null);
  }
  let data = null;
  if (response.status !== 204 && (response.headers.get("Content-Type") || "").startsWith("application/json")) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  }
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : null;
    throw new ApiError(response.status, detail, retryAfterSeconds(response));
  }
  return data;
}

function storeTokens(data) {
  if (!data || typeof data.access_token !== "string" || typeof data.refresh_token !== "string") {
    throw new ApiError(0, "respuesta de identidad no valida", null);
  }
  accessToken = data.access_token;
  refreshToken = data.refresh_token;
  clearTimeout(refreshTimer);
  const ttl = Number(data.expires_in) || 0;
  const delay = Math.max(MIN_REFRESH_DELAY_S, ttl - REFRESH_MARGIN_S);
  refreshTimer = setTimeout(() => {
    refreshSession().catch(() => {}); // si falla, refreshSession ya cerro la sesion
  }, delay * 1000);
}

function endSession(reason) {
  const hadSession = accessToken !== null || refreshToken !== null;
  accessToken = null;
  refreshToken = null;
  clearTimeout(refreshTimer);
  refreshTimer = null;
  if (hadSession) {
    onSessionEnd(reason); // una sola vez por sesion: sin bucles de vuelta al login
  }
}

// Una sola renovacion en curso; si falla (token reutilizado, sesion de 12 h vencida, bloqueo), la
// sesion termina y se vuelve al login. No se reintenta.
function refreshSession() {
  if (refreshInFlight === null) {
    refreshInFlight = (async () => {
      try {
        if (refreshToken === null) {
          throw new ApiError(401, null, null);
        }
        storeTokens(await send("POST", "/auth/refresh", { body: { refresh_token: refreshToken }, auth: false }));
      } catch (error) {
        endSession("expired");
        throw error;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

async function request(method, path, body) {
  try {
    return await send(method, path, { body });
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 401) {
      throw error;
    }
  }
  // Token de acceso vencido o revocado: una renovacion (si falla, cierra la sesion) y un unico
  // reintento. Un segundo 401 tambien termina la sesion: nunca hay bucle.
  await refreshSession();
  try {
    return await send(method, path, { body });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      endSession("expired");
    }
    throw error;
  }
}

export async function login(username, password, otp) {
  const body = { username, password };
  if (otp) {
    body.otp = otp;
  }
  storeTokens(await send("POST", "/auth/login", { body, auth: false }));
}

export async function logout() {
  const pending = refreshToken;
  if (accessToken !== null) {
    try {
      await send("POST", "/auth/logout", { body: pending ? { refresh_token: pending } : undefined });
    } catch {
      // Aunque el servidor no responda, la sesion local se borra igual.
    }
  }
  endSession("logout");
}

export function get(path) {
  return request("GET", path);
}

export function post(path, body) {
  return request("POST", path, body);
}
