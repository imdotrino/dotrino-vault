/**
 * AGENTE SSH del daemon: un socket Unix con el protocolo de `ssh-agent` (draft-miller-
 * ssh-agent), para que el `ssh` del usuario firme con la llave que vive en su TELÉFONO.
 *
 * Lo que hace es poco a propósito: listar las llaves públicas registradas y, en cada
 * `SIGN_REQUEST`, pedirle la firma al aparato que aprueba (`vault.requestSshSign`) y
 * devolverla. No guarda llaves privadas, no acepta que le añadan (`ssh-add` de una llave
 * del disco se rechaza: la idea es justo que no haya llaves en el disco) y no hace de
 * proxy de nada más.
 *
 *   export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/dotrino-vault/ssh-agent.sock
 *   ssh-add -L          # las llaves del teléfono
 *   ssh mi-servidor     # el teléfono pide tu «sí» y firma
 */
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { sshString, readStrings } from './sshKeys.js'

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
 * @param {{ socketPath: string, vault: () => { sshKeys: () => any[], requestSshSign: (a: { keyId: string, data: Buffer }) => Promise<Buffer> }, log?: Function }} opts
 */
export function startSshAgent ({ socketPath, vault, log = () => {} }) {
  fs.mkdirSync(path.dirname(socketPath), { recursive: true, mode: 0o700 })
  try { fs.unlinkSync(socketPath) } catch (_) {}

  async function handle (type, payload) {
    const v = vault()
    if (type === REQUEST_IDENTITIES) {
      const keys = v.sshKeys()
      const n = Buffer.alloc(4); n.writeUInt32BE(keys.length)
      const parts = keys.map((k) => Buffer.concat([sshString(Buffer.from(k.blob, 'base64')), sshString(Buffer.from(k.comment || ''))]))
      return frame(IDENTITIES_ANSWER, Buffer.concat([n, ...parts]))
    }
    if (type === SIGN_REQUEST) {
      const [blob, data] = readStrings(payload, 2)
      const key = v.sshKeys().find((k) => k.blob === blob.toString('base64'))
      if (!key) return frame(AGENT_FAILURE)
      try {
        const sig = await v.requestSshSign({ keyId: key.id, data })
        return frame(SIGN_RESPONSE, sshString(sig))
      } catch (e) {
        log('[vault] ssh-agent: not signed: ' + e.message)
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
  server.on('error', (e) => log('[vault] ssh-agent: ' + e.message))
  server.listen(socketPath, () => {
    try { fs.chmodSync(socketPath, 0o600) } catch (_) {}
    log(`[vault] ssh-agent listening at ${socketPath}  (export SSH_AUTH_SOCK=${socketPath})`)
  })
  return {
    socketPath,
    close () { try { server.close() } catch (_) {} try { fs.unlinkSync(socketPath) } catch (_) {} }
  }
}

export default { startSshAgent, defaultSocketPath, AGENT_SUCCESS }
