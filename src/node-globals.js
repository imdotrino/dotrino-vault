/**
 * Instala los globals del navegador que los paquetes del ecosistema esperan
 * cuando corren headless en Node: `WebSocket` (paquete `ws`) y un `localStorage`
 * respaldado en archivo (lo usa `@dotrino/proxy-client` para su keypair de
 * transporte estable). Mismo patrón que `dotrino-bots/src/core/node-globals.js`
 * — NO se reimplementa nada, solo se inyecta el entorno.
 */
import fs from 'node:fs'
import path from 'node:path'
import WebSocket from 'ws'

/** localStorage síncrono respaldado por un archivo JSON (solo lo que usan los paquetes). */
export function fileLocalStorage (filePath) {
  let data = {}
  try { if (fs.existsSync(filePath)) data = JSON.parse(fs.readFileSync(filePath, 'utf8')) || {} } catch (_) {}
  const flush = () => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
    fs.writeFileSync(filePath, JSON.stringify(data), { mode: 0o600 })
  }
  return {
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => { data[k] = String(v); flush() },
    removeItem: (k) => { delete data[k]; flush() },
    clear: () => { data = {}; flush() },
    key: (i) => Object.keys(data)[i] ?? null,
    get length () { return Object.keys(data).length }
  }
}

let _installed = false
export function installNodeGlobals (dir) {
  if (_installed) return
  if (typeof globalThis.WebSocket === 'undefined') globalThis.WebSocket = WebSocket
  // Node ≥22 expone un `localStorage` no funcional sin flag → forzamos el shim.
  globalThis.localStorage = fileLocalStorage(path.join(dir, 'transport.json'))
  _installed = true
}
