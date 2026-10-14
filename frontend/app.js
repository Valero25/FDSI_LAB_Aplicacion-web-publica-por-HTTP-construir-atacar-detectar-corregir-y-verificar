// Consola del analista: vistas de login, alertas e inventario. Todo el contenido que viene de la API
// se pinta con dom.el (textContent): ver dom.js. Las llamadas y los tokens estan en api.js.
import * as api from "./api.js";
import { byId, clear, el, show } from "./dom.js";

const ALERT_ID_RE = /^[0-9a-fA-F-]{36}$/;
const DEVICE_ID_RE = /^[A-Z0-9-]{3,32}$/;
const OTP_RE = /^[0-9]{6}$/;

const SEVERITY = { low: "Baja", medium: "Media", high: "Alta", critical: "Crítica" };
const STATUS = {
  new: "Nueva",
  classified: "Clasificada",
  escalated: "Escalada",
  acknowledged: "Reconocida",
  closed: "Cerrada",
};
const ACTIONS = { acknowledge: "Reconocer", comment: "Comentar", escalate: "Escalar", close: "Cerrar" };
// Solo para decidir que opciones mostrar: la autorizacion real la hace el servidor (403 si no).
const ROLE_ACTIONS = {
  lector: ["acknowledge", "comment"],
  respondedor: ["acknowledge", "comment", "escalate", "close"],
};
const ROLE_NAMES = { lector: "lector", respondedor: "respondedor" };

const DEVICE_COLUMNS = [
  ["id", "ID"],
  ["hostname", "Hostname"],
  ["type", "Tipo"],
  ["vendor", "Fabricante"],
  ["model", "Modelo"],
  ["location", "Ubicación"],
  ["zone", "Zona"],
  ["criticality", "Criticidad"],
  ["owner", "Responsable"],
];

let currentAlertId = null;
let loginBlockedUntil = 0;

// --- Mensajes -------------------------------------------------------------------------------------

function message(error, context) {
  if (!(error instanceof api.ApiError)) {
    return "Error inesperado en la aplicación.";
  }
  const wait = error.retryAfter !== null ? " Espere " + error.retryAfter + " s." : " Espere un momento.";
  switch (error.status) {
    case 0:
      return "No se pudo contactar con el servidor.";
    case 401:
      return context === "login"
        ? "Usuario, contraseña o código incorrectos." // nunca se distingue cual de los tres fallo
        : "La sesión terminó. Inicie sesión de nuevo.";
    case 403:
      return "Su rol no permite esta acción (lo decide el servidor).";
    case 404:
      return "No encontrado.";
    case 409:
      if (error.detail === "Alert is closed") {
        return "La alerta está cerrada: solo admite comentarios.";
      }
      if (error.detail === "Action limit reached for this alert") {
        return "La alerta alcanzó el máximo de acciones registradas.";
      }
      return "La acción entra en conflicto con el estado actual de la alerta.";
    case 413:
      return "La petición es demasiado grande.";
    case 415:
      return "Tipo de contenido no admitido.";
    case 400:
    case 422:
      return context === "login" ? "Usuario, contraseña o código incorrectos." : "Datos no válidos. Revise los campos.";
    case 429:
      return "Demasiados intentos o peticiones." + wait;
    case 503:
      return "Servicio no disponible en este momento.";
    default:
      return "Error del servidor (HTTP " + error.status + ").";
  }
}

function showError(node, text) {
  node.textContent = text;
  show(node, Boolean(text));
}

function notice(text) {
  showError(byId("notice"), text);
}

// --- Formato --------------------------------------------------------------------------------------

function formatDate(value) {
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("es-CO");
}

function display(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (Array.isArray(value)) {
    return value.map(display).join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value); // como texto: nunca se interpreta
  }
  if (typeof value === "boolean") {
    return value ? "sí" : "no";
  }
  return String(value);
}

function addField(list, label, value) {
  list.append(el("dt", { text: label }), el("dd", { text: display(value) }));
}

// --- Navegacion -----------------------------------------------------------------------------------

function showView(name) {
  show(byId("login-view"), name === "login");
  show(byId("alerts-view"), name === "alerts");
  show(byId("devices-view"), name === "devices");
  show(byId("session-bar"), name !== "login");
  byId("nav-alerts").setAttribute("aria-current", name === "alerts" ? "page" : "false");
  byId("nav-devices").setAttribute("aria-current", name === "devices" ? "page" : "false");
}

function resetData() {
  currentAlertId = null;
  for (const id of ["alerts-body", "alert-fields", "alert-enrichment", "alert-actions", "devices-head",
    "devices-body", "device-fields", "action-name"]) {
    clear(byId(id));
  }
  show(byId("alert-detail"), false);
  show(byId("device-detail"), false);
  byId("session-user").textContent = "";
}

api.setSessionEndHandler((reason) => {
  resetData();
  showView("login");
  notice(reason === "logout" ? "Sesión cerrada." : "La sesión terminó. Inicie sesión de nuevo.");
  byId("login-username").focus();
});

// --- Login ----------------------------------------------------------------------------------------

async function onLogin(event) {
  event.preventDefault();
  const errorNode = byId("login-error");
  const submit = byId("login-submit");
  const username = byId("login-username").value.trim();
  const passwordInput = byId("login-password");
  const otpInput = byId("login-otp");
  const otp = otpInput.value.trim();
  if (Date.now() < loginBlockedUntil) {
    return;
  }
  if (!username || !passwordInput.value || (otp && !OTP_RE.test(otp))) {
    showError(errorNode, "Usuario, contraseña o código incorrectos.");
    return;
  }
  showError(errorNode, "");
  notice("");
  submit.disabled = true;
  try {
    await api.login(username, passwordInput.value, otp);
    passwordInput.value = "";
    otpInput.value = "";
    const info = api.sessionInfo();
    byId("session-user").textContent = info.username + " (" + (ROLE_NAMES[info.role] || "rol desconocido") + ")";
    showView("alerts");
    await loadAlerts();
  } catch (error) {
    passwordInput.value = "";
    otpInput.value = "";
    showError(errorNode, message(error, "login"));
    if (error instanceof api.ApiError && error.status === 429 && error.retryAfter) {
      loginBlockedUntil = Date.now() + error.retryAfter * 1000;
      setTimeout(() => {
        submit.disabled = false;
      }, error.retryAfter * 1000);
      return;
    }
  }
  submit.disabled = false;
}

// --- Alertas --------------------------------------------------------------------------------------

async function loadAlerts() {
  const errorNode = byId("alerts-error");
  const params = new URLSearchParams({ limit: "100" });
  const severity = byId("filter-severity").value;
  const status = byId("filter-status").value;
  if (severity in SEVERITY) {
    params.set("severity", severity);
  }
  if (status in STATUS) {
    params.set("status", status);
  }
  showError(errorNode, "");
  let alerts;
  try {
    alerts = await api.get("/alerts?" + params.toString());
  } catch (error) {
    if (api.hasSession()) {
      showError(errorNode, message(error, "alerts"));
    }
    return;
  }
  const body = byId("alerts-body");
  clear(body);
  if (!Array.isArray(alerts) || alerts.length === 0) {
    body.append(el("tr", {}, [el("td", { text: "No hay alertas con este filtro.", attrs: { colspan: 7 } })]));
    return;
  }
  for (const alert of alerts) {
    const open = el("button", { text: "Ver", className: "link", attrs: { type: "button" } });
    open.addEventListener("click", () => loadAlert(alert.id));
    body.append(
      el("tr", {}, [
        el("td", { text: formatDate(alert.created_at) }),
        el("td", { text: SEVERITY[alert.severity] || display(alert.severity), className: "sev sev-" + safeClass(alert.severity) }),
        el("td", { text: STATUS[alert.status] || display(alert.status) }),
        el("td", { text: display(alert.risk_score) }),
        el("td", { text: display(alert.hostname) }),
        el("td", { text: display(alert.technique) }),
        el("td", {}, [open]),
      ]),
    );
  }
}

// Las clases CSS solo toman valores de una lista cerrada (nunca texto de la alerta).
function safeClass(value) {
  return value in SEVERITY ? value : "unknown";
}

async function loadAlert(alertId) {
  if (!ALERT_ID_RE.test(String(alertId))) {
    return;
  }
  const errorNode = byId("alerts-error");
  let alert;
  try {
    alert = await api.get("/alerts/" + encodeURIComponent(alertId));
  } catch (error) {
    if (api.hasSession()) {
      showError(errorNode, message(error, "alert"));
    }
    return;
  }
  currentAlertId = alert.id;
  const fields = byId("alert-fields");
  clear(fields);
  addField(fields, "ID", alert.id);
  addField(fields, "Creada", formatDate(alert.created_at));
  addField(fields, "Actualizada", alert.updated_at ? formatDate(alert.updated_at) : null);
  addField(fields, "Estado", STATUS[alert.status] || alert.status);
  addField(fields, "Severidad", SEVERITY[alert.severity] || alert.severity);
  addField(fields, "Riesgo", alert.risk_score);
  addField(fields, "Clasificación", alert.classification);
  addField(fields, "Táctica", alert.tactic);
  addField(fields, "Técnica", alert.technique);
  addField(fields, "Host", alert.hostname);
  addField(fields, "IP de origen", alert.source_ip);
  // Texto libre de terceros: se muestra literal, con saltos de linea (CSS white-space: pre-wrap).
  addDescription(fields, alert.description);

  const enrichment = byId("alert-enrichment");
  clear(enrichment);
  const data = alert.enrichment && typeof alert.enrichment === "object" ? alert.enrichment : {};
  const mitre = data.mitre && typeof data.mitre === "object" ? data.mitre : {};
  addField(enrichment, "MITRE ATT&CK", [mitre.technique_id, mitre.name].filter(Boolean).join(" · ") || mitre.status);
  addField(enrichment, "Tácticas de la técnica", mitre.tactics);
  addField(enrichment, "Referencia", mitre.url); // como texto, no como enlace
  const abuse = data.abuseipdb && typeof data.abuseipdb === "object" ? data.abuseipdb : {};
  addField(enrichment, "AbuseIPDB", abuse.status === "ok" ? "puntuación " + abuse.abuse_confidence_score : abuse.status);
  addField(enrichment, "Motivos del riesgo", data.score_reasons);
  addField(enrichment, "Marcas", data.flags);

  const actionList = byId("alert-actions");
  clear(actionList);
  const actions = Array.isArray(alert.actions) ? alert.actions : [];
  if (actions.length === 0) {
    actionList.append(el("li", { text: "Sin acciones todavía." }));
  }
  for (const action of actions) {
    actionList.append(
      el("li", {}, [
        el("strong", { text: ACTIONS[action.action] || display(action.action) }),
        " · " + display(action.analyst) + " (" + display(action.role) + ") · " + formatDate(action.created_at),
        action.note ? el("span", { text: display(action.note), className: "note" }) : null,
      ]),
    );
  }

  const select = byId("action-name");
  clear(select);
  const info = api.sessionInfo();
  for (const name of ROLE_ACTIONS[info && info.role] || []) {
    select.append(el("option", { text: ACTIONS[name], attrs: { value: name } }));
  }
  showError(byId("action-result"), "");
  show(byId("action-form"), select.options.length > 0);
  show(byId("alert-detail"), true);
}

function addDescription(fields, description) {
  fields.append(el("dt", { text: "Descripción" }), el("dd", { text: display(description), className: "free-text" }));
}

async function onAction(event) {
  event.preventDefault();
  const resultNode = byId("action-result");
  const action = byId("action-name").value;
  const note = byId("action-note").value;
  if (!currentAlertId || !(action in ACTIONS)) {
    return;
  }
  try {
    await api.post("/alerts/" + encodeURIComponent(currentAlertId) + "/actions", { action, note });
  } catch (error) {
    if (api.hasSession()) {
      showError(resultNode, message(error, "action"));
    }
    return;
  }
  byId("action-note").value = "";
  const alertId = currentAlertId;
  await loadAlert(alertId);
  showError(resultNode, "");
  notice("Acción registrada.");
  await loadAlerts();
}

// --- Inventario de red ----------------------------------------------------------------------------

async function loadDevices() {
  const errorNode = byId("devices-error");
  const type = byId("filter-type").value;
  const query = ["firewall", "router", "switch"].includes(type) ? "?type=" + type : "";
  showError(errorNode, "");
  let devices;
  try {
    devices = await api.get("/network/devices" + query);
  } catch (error) {
    if (api.hasSession()) {
      showError(errorNode, message(error, "devices"));
    }
    return;
  }
  devices = Array.isArray(devices) ? devices : [];
  // mgmt_ip solo se muestra si el servidor la envia (rol respondedor): el frontend no la deduce.
  const withMgmt = devices.some((d) => Object.prototype.hasOwnProperty.call(d, "mgmt_ip"));
  const columns = withMgmt ? [...DEVICE_COLUMNS, ["mgmt_ip", "IP de gestión"]] : DEVICE_COLUMNS;
  const head = byId("devices-head");
  clear(head);
  head.append(el("tr", {}, [...columns.map(([, label]) => el("th", { text: label, attrs: { scope: "col" } })), el("th", {})]));
  const body = byId("devices-body");
  clear(body);
  for (const device of devices) {
    const open = el("button", { text: "Ver", className: "link", attrs: { type: "button" } });
    open.addEventListener("click", () => loadDevice(device.id));
    body.append(el("tr", {}, [...columns.map(([key]) => el("td", { text: display(device[key]) })), el("td", {}, [open])]));
  }
  show(byId("device-detail"), false);
}

async function loadDevice(deviceId) {
  if (!DEVICE_ID_RE.test(String(deviceId))) {
    return;
  }
  let device;
  try {
    device = await api.get("/network/devices/" + encodeURIComponent(deviceId));
  } catch (error) {
    if (api.hasSession()) {
      showError(byId("devices-error"), message(error, "device"));
    }
    return;
  }
  const fields = byId("device-fields");
  clear(fields);
  for (const [key, label] of DEVICE_COLUMNS) {
    addField(fields, label, device[key]);
  }
  if (Object.prototype.hasOwnProperty.call(device, "mgmt_ip")) {
    addField(fields, "IP de gestión", device.mgmt_ip);
  }
  show(byId("device-detail"), true);
}

// --- Arranque -------------------------------------------------------------------------------------

function start() {
  byId("login-form").addEventListener("submit", onLogin);
  byId("logout-button").addEventListener("click", () => api.logout());
  byId("nav-alerts").addEventListener("click", () => {
    showView("alerts");
    loadAlerts();
  });
  byId("nav-devices").addEventListener("click", () => {
    showView("devices");
    loadDevices();
  });
  byId("alerts-filter").addEventListener("submit", (event) => {
    event.preventDefault();
    loadAlerts();
  });
  byId("devices-filter").addEventListener("submit", (event) => {
    event.preventDefault();
    loadDevices();
  });
  byId("action-form").addEventListener("submit", onAction);
  showView("login");
  byId("login-username").focus();
}

start(); // los modulos se ejecutan diferidos: el DOM ya esta cargado
