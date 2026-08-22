/**
 * AGENTE SSH: un socket Unix con el protocolo de `ssh-agent` (draft-miller-ssh-agent)
 * cuyas llaves viven SOLO EN MEMORIA — se las dio la bóveda al arrancar (`dotrino-env
 * ssh-agent`, con la aprobación del teléfono si el aparato la pide). En el disco no hay
 * nada. No acepta que le añadan llaves (`ssh-add` de un archivo se rechaza: la idea es
 * justo que no haya archivos) ni hace de proxy de nada más.
 *
 *   export SSH_AUTH_SOCK=…   # lo imprime dotrino-env ssh-agent
 *   ssh-add -L               # las llaves del cajón
 *   ssh mi-servidor          # firma en local, con la llave en memoria
 */
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { sshString, readStrings, signSsh } from './sshKeys.js'

const AGENT_FAILURE = 5
const AGENT_SUCCESS = 6
const REQUEST_IDENTITIES = 11
const IDENTITIES_ANSWER = 12
const SIGN_REQUEST = 13
const SIGN_RESPONSE = 14

/** Dónde va el socket: en el directorio de ejecución del usuario si lo hay (se limpia solo). */
export function defaultSocketPath (dir) {
  const run = process.env.XDG_RUNTIME_DIR
  return run ? path.join(run, 'dotrino-vault', 'ssh-agent.sock') : path.join(dir, 'ssh-agent.sock')
}

const frame = (type, payload = Buffer.alloc(0)) => {
  const body = Buffer.concat([Buffer.from([type]), payload])
  const len = Buffer.alloc(4); len.writeUInt32BE(body.length)
  return Buffer.concat([len, body])
}

/**
 * @param {{ socketPath: string, keys: () => any[], log?: Function }} opts
 *   `keys()`: las llaves cargadas (`loadPrivateKey` de sshKeys.js), con su privada en memoria.
 */
export function startSshAgent ({ socketPath, keys, log = () => {} }) {
  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o700 })
  try { fs.unlinkSync(socketPath) } catch (_) {}

  async function handle (type, payload) {
    const list = keys() || []
    if (type === REQUEST_IDENTITIES) {
      const n = Buffer.alloc(4); n.writeUInt32BE(list.length)
      const parts = list.map((k) => Buffer.concat([sshString(k.blob), sshString(Buffer.from(k.comment || ''))]))
      return frame(IDENTITIES_ANSWER, Buffer.concat([n, ...parts]))
    }
    if (type === SIGN_REQUEST) {
      const [blob, data] = readStrings(payload, 2)
      const flags = payload.length >= 4 ? payload.readUInt32BE(payload.length - 4) : 0
      const key = list.find((k) => k.blob.equals(blob))
      if (!key) return frame(AGENT_FAILURE)
      try { return frame(SIGN_RESPONSE, sshString(signSsh(key, data, flags))) } catch (e) {
        log('[ssh-agent] not signed: ' + e.message)
        return frame(AGENT_FAILURE)
      }
    }
    // Añadir/quitar llaves, candado, extensiones: nada de eso vive aquí.
    return frame(AGENT_FAILURE)
  }

  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0)
    let busy = Promise.resolve()
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk])
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0)
        if (len < 1 || len > 256 * 1024) { sock.destroy(); return }
        if (buf.length < 4 + len) break
        const type = buf[4]; const payload = buf.subarray(5, 4 + len)
        buf = buf.subarray(4 + len)
        // En orden: el protocolo es petición-respuesta, y un cliente que encadena dos
        // firmas espera las respuestas en el mismo orden.
        busy = busy.then(() => handle(type, payload)).then((out) => { if (!sock.destroyed) sock.write(out) }).catch(() => { if (!sock.destroyed) sock.write(frame(AGENT_FAILURE)) })
      }
    })
    sock.on('error', () => {})
  })
  server.on('error', (e) => log('[ssh-agent] ' + e.message))
  server.listen(socketPath, () => {
    try { fs.chmodSync(socketPath, 0o600) } catch (_) {}
    log(`[ssh-agent] listening at ${socketPath}`)
  })
  return {
    socketPath,
    close () { try { server.close() } catch (_) {} try { fs.unlinkSync(socketPath) } catch (_) {} }
  }
}

export default { startSshAgent, defaultSocketPath, AGENT_SUCCESS }
