// Unico punto del frontend que crea nodos del DOM. Todo el texto entra con textContent o como nodo de
// texto (append de una cadena): nunca se interpreta como HTML. Los campos de las alertas son texto
// escrito por terceros que describe ataques reales ("<img src=x onerror=...>", "<script>..."): asi se
// muestran tal cual, sin ejecutarse.

// Atributos que podrian ejecutar codigo o cargar recursos: no se aceptan nunca desde aqui.
const FORBIDDEN_ATTR = /^(on|style$|src$|srcdoc$|href$|action$|formaction$|xlink:href$)/i;

export function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.text !== undefined && options.text !== null) {
    node.textContent = String(options.text);
  }
  if (options.className) {
    node.className = options.className;
  }
  for (const [name, value] of Object.entries(options.attrs || {})) {
    if (FORBIDDEN_ATTR.test(name)) {
      throw new Error("atributo no permitido: " + name);
    }
    node.setAttribute(name, String(value));
  }
  for (const child of children) {
    if (child !== null && child !== undefined) {
      node.append(child); // una cadena se convierte en nodo de texto
    }
  }
  return node;
}

export function clear(node) {
  node.replaceChildren();
}

export function show(node, visible) {
  node.hidden = !visible;
}

export function byId(id) {
  const node = document.getElementById(id);
  if (!node) {
    throw new Error("falta el elemento " + id);
  }
  return node;
}
