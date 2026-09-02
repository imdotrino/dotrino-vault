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
import { atRestFor } from './atrest.js'

/**
 * localStorage síncrono respaldado por un archivo JSON (solo lo que usan los paquetes)
 * **y cifrado en reposo**.
 *
 * Lo de cifrarlo no es celo: aquí `@dotrino/proxy-client` guarda su par de transporte, y
 * ese par lleva su PRIVADA. Era el único archivo del vault con una llave privada en claro
 * en el disco. No firma nada que el acta reconozca —quien habla por la bóveda es la llave
 * de comunicación (`commKey.js`)—, pero sí es la identidad con la que esta bóveda se
 * sienta en el proxio: con ella se ocupa su sitio y su cola de mensajes.
 */
export function fileLocalStorage (filePath) {
  const atRest = atRestFor(path.dirname(filePath))
  let data = {}
  try { if (fs.existsSync(filePath)) data = JSON.parse(atRest.decrypt(fs.readFileSync(filePath, 'utf8'))) || {} } catch (_) {}
  const flush = () => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true })
    fs.writeFileSync(filePath, atRest.encrypt(JSON.stringify(data)), { mode: 0o600 })
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
