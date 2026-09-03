/**
 * localdesk.js — HABLARLE A LA BÓVEDA SIN SALIR DE LA MÁQUINA.
 *
 * Un servicio en el mismo equipo que la bóveda daba la vuelta por `proxy.dotrino.com`:
 * salía a internet, volvía, y si el proxio tenía un mal momento el arranque se retrasaba
 * cinco segundos por nada. Absurdo cuando los dos procesos comparten disco (dueño,
 * 2026-09-03: «estando en la misma máquina debería ser inmediato»).
 *
 * Es EL MISMO PROTOCOLO. Lo que viaja es idéntico —`{type, data, signature, cert}`— y la
 * bóveda lo comprueba igual, contra el certificado y contra el acta. **Alcanzar el socket
 * no autoriza nada**: es la misma puerta por un camino más corto, no una puerta de atrás.
 *
 * Se hace pasar por un cliente del proxio (`send`, `sendByPubkey`, `on('message')`,
 * `close`) para que quien lo use no tenga que saber por dónde va. `sendByPubkey` ignora a
 * quién se dirige, y es correcto: al otro lado del socket solo hay una bóveda, la de esta
 * máquina — si hubiera que elegir destinatario, este no sería el camino.
 */
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import os from 'node:os'

/**
 * DÓNDE ESTÁ EL SOCKET, y por qué se nombra por la LLAVE de la bóveda.
 *
 * Una máquina puede tener varias bóvedas (varios perfiles), y un servicio no sabe nada de
 * perfiles: lo único que conoce de la suya es su llave maestra, que lleva pineada desde
 * que se enroló. Así que el nombre sale de ahí y los dos lados lo calculan igual, sin
 * mirar ningún índice ni depender de cómo estén repartidos los datos en el disco.
 *
 * Y va en el directorio de EJECUCIÓN del usuario, no entre los datos: un socket es algo
 * vivo, no algo guardado. Se lo lleva el reinicio, que es lo correcto.
 */
export function socketDir () {
  const base = process.env.XDG_RUNTIME_DIR || os.tmpdir()
  return path.join(base, 'dotrino-vault')
}

export function localSocketPath (masterId) {
  if (process.env.DOTRINO_VAULT_SOCKET) return process.env.DOTRINO_VAULT_SOCKET
  return path.join(socketDir(), String(masterId) + '.sock')
}

/** ¿Hay una bóveda escuchando aquí mismo? Mirar el archivo es barato y no conecta nada. */
export const hasLocalVault = (masterId) => {
  try { return fs.statSync(localSocketPath(masterId)).isSocket() } catch (_) { return false }
}

/**
 * Se conecta al mostrador local y devuelve algo con la forma de un cliente del proxio.
 * Si no hay socket, o no acepta, LANZA — no se queda callado: quien llama decide si sale
 * por el proxio, y esa decisión tiene que ser explícita y no un silencio.
 */
export async function connectLocal ({ masterId, timeoutMs = 3000 } = {}) {
  const socketPath = localSocketPath(masterId)
  const sock = await new Promise((resolve, reject) => {
    const s = net.createConnection(socketPath)
    const t = setTimeout(() => { s.destroy(); reject(new Error('the local vault desk did not answer')) }, timeoutMs)
    s.once('connect', () => { clearTimeout(t); resolve(s) })
    s.once('error', (e) => { clearTimeout(t); reject(new Error('no local vault desk at ' + socketPath + ': ' + e.message)) })
  })

  const oyentes = new Set()
  let buf = ''
  sock.setEncoding('utf8')
  sock.on('data', (chunk) => {
    buf += chunk
    let i
    while ((i = buf.indexOf('\n')) >= 0) {
      const linea = buf.slice(0, i); buf = buf.slice(i + 1)
      if (!linea.trim()) continue
      let p = null
      try { p = JSON.parse(linea) } catch (_) { continue }
      // `from` es el mismo para todo: al otro lado solo hay una bóveda.
      for (const fn of oyentes) { try { fn('local', p) } catch (_) {} }
    }
  })

  const enviar = (obj) => { sock.write(JSON.stringify(obj) + '\n') }
  return {
    local: true,
    token: 'local',
    send: (_to, obj) => enviar(obj),
    sendByPubkey: (_pub, obj) => enviar(obj),
    // El mostrador local no pide identificarse: la puerta la abre el certificado que va
    // dentro de cada mensaje, igual que por el proxio. Identificarse ahí sirve para ser
    // DIRECCIONABLE, y aquí no hay a quién direccionar.
    identify: async () => ({ ok: true }),
    on: (ev, fn) => {
      if (ev !== 'message') return () => {}
      oyentes.add(fn)
      return () => oyentes.delete(fn)
    },
    close: () => { try { sock.destroy() } catch (_) {} }
  }
}
