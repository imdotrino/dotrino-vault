/**
 * LO QUE EL BINARIO PONE PARA CORRER LA BÓVEDA (`lib/src/core/vault.js`): el disco del
 * perfil, la identidad leída de su directorio, `/proc`, el nombre de la máquina y el
 * mostrador local por socket de archivo. El navegador pone lo suyo en
 * `lib/src/core/browserPlatform.js`; el núcleo es el mismo.
 */
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { Identity } from '@dotrino/identity/node'
import { MSG } from '../lib/src/protocol.js'
import { readProcContext } from '../lib/src/proc.js'
import { localSocketPath, socketDir } from '../lib/src/localdesk.js'
import { kekFor, migrateFile, encryptText, decryptText, atRestFor } from './atrest.js'
import { assertKeyOwnsDir } from './keyowner.js'
import { installNodeGlobals } from './node-globals.js'
import { nodeDisk } from './disk.js'
import { VERSION } from './version.js'

/**
 * EL MOSTRADOR LOCAL: el mismo protocolo, sin salir de la máquina.
 *
 * Un servicio en ESTA máquina hablaba con la bóveda dando la vuelta por
 * `proxy.dotrino.com`: sale a internet, vuelve, y si el proxio tiene un mal momento el
 * arranque se retrasa cinco segundos por nada. Absurdo cuando los dos procesos comparten
 * disco (dueño, 2026-09-03: «estando en la misma máquina debería ser inmediato»).
 *
 * Es EL MISMO PROTOCOLO y el mismo enrutador: llega `{type, data, signature, cert}` y se
 * comprueba igual, contra el certificado y contra el acta. **Alcanzar el socket no
 * autoriza nada** — es la misma puerta por un camino más corto, no una puerta de atrás.
 * Por eso no hay un solo `if` de «viene de local» en ningún handler, y no debe haberlo.
 *
 * Y no es un puerto: es un socket de archivo, en modo 0600 y bajo el directorio del
 * usuario. No se alcanza desde otra máquina ni desde otro usuario, así que la promesa
 * del `docker-compose` —«la bóveda no escucha nada»— sigue siendo cierta donde importa.
 */
function openLocalDesk ({ name, onMessage, channels: channels, maxBytes: MAX_REPLY_BYTES, log }) {
  const socketPath = localSocketPath(name)
  let n = 0
  const server = net.createServer((sock) => {
    const id = 'local:' + (++n)
    let buf = ''
    const send = (obj) => { try { sock.write(JSON.stringify(obj) + '\n') } catch (_) {} }
    channels.set(id, send)
    sock.on('data', (chunk) => {
      buf += chunk
      // UN TOPE, y por lo mismo que en las respuestas: sin él, quien se conecte puede
      // hacer crecer este buffer hasta tumbar la bóveda mandando y sin saltos de línea.
      if (buf.length > MAX_REPLY_BYTES) { buf = ''; send({ type: MSG.ERROR, error: 'request too big' }); return }
      let i
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1)
        if (!line.trim()) continue
        let p = null
        try { p = JSON.parse(line) } catch (_) { send({ type: MSG.ERROR, error: 'malformed request' }); continue }
        onMessage(id, p).catch((e) => send({ type: MSG.ERROR, error: e.message }))
      }
    })
    const close = () => channels.delete(id)
    sock.on('close', close)
    sock.on('error', close)
  })
  server.on('error', (e) => log('[vault] the local desk could not open (' + e.message + '): services will use the proxy'))
  // EL DIRECTORIO ES EL CONTROL, no el modo del socket.
  //
  // `mkdir` con `mode` NO corrige un directorio que ya existe, y sin `XDG_RUNTIME_DIR`
  // —un servicio de sistema, un contenedor— esto cae en `/tmp`, donde cualquiera puede
  // haberlo creado antes con permiso de escritura para todos. Quien sea dueño del
  // directorio puede borrar el socket y poner el suyo: los servicios de esta máquina
  // acabarían hablando con él. No leería nada (la respuesta va firmada por una llave que
  // nombra el acta y el cliente la comprueba), pero los deja sin arrancar.
  //
  // Y el `chmod 0600` de abajo llega DESPUÉS de `listen`, así que por sí solo deja una
  // rendija. Lo que la cierra de verdad es que el directorio sea nuestro y solo nuestro.
  const dir = socketDir()
  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }) } catch (_) {}
  try {
    const st = fs.statSync(dir)
    const foreign = typeof process.getuid === 'function' && st.uid !== process.getuid()
    const isOpen = (st.mode & 0o077) !== 0
    if (foreign || isOpen) {
      return log(`[vault] the local desk stays closed: ${dir} is ${foreign ? 'owned by another user' : 'writable by others'} ` +
        '— services on this machine will use the proxy instead')
    }
  } catch (e) {
    return log('[vault] the local desk stays closed: could not check ' + dir + ' (' + e.message + ')')
  }
  try { fs.rmSync(socketPath, { force: true }) } catch (_) {}
  server.listen(socketPath, () => {
    try { fs.chmodSync(socketPath, 0o600) } catch (_) {}
    log('[vault] local desk at ' + socketPath + ' (same machine, no round trip)')
  })
  server.unref?.()
  return server
}

/**
 * @param {string} dir  el directorio del perfil
 */
export function nodePlatform (dir) {
  const disk = nodeDisk(dir)
  // El transporte del ecosistema guarda su par en `localStorage`, y en Node no lo hay.
  installNodeGlobals(dir)
  return {
    disk,
    product: 'vaultd',
    version: VERSION,
    hostname: () => os.hostname(),
    readProcContext,
    openLocalDesk,
    noticeGroupMs: Number(process.env.DOTRINO_VAULT_NOTICE_MS) || 3000,
    async openIdentity ({ openKey = null, log = console.log } = {}) {
      // CIFRADO EN REPOSO ligado a esta máquina: ningún archivo del dir queda en claro, así
      // que copiarlos a otro equipo no sirve de nada. La identidad se migra AQUÍ (verificando
      // antes de reemplazar); el resto lo hace su propio almacén al abrirse.
      try {
        const r = migrateFile(path.join(dir, 'identity.json'), kekFor(dir))
        if (r === 'migrated') log('[vault] identity encrypted at rest (bound to this machine)')
      } catch (e) { log('[vault] could not encrypt the identity at rest:', e.message) }
      /**
       * EL CANDADO DE LA MAESTRA. La mitad privada se guarda sellada con la llave que sale de
       * la contraseña del perfil (`openKey`), no con la de la máquina: cerrada, la maestra no
       * está en memoria y no hay con qué sacarla del disco. Un perfil sin contraseña no tiene
       * `openKey`: se queda bajo la llave de máquina, y la consola lo dice en voz alta.
       */
      const keyLock = {
        seal: async (text) => { const k = openKey?.(); return k ? encryptText(text, k) : null },
        open: async (blob) => { const k = openKey?.(); if (!k) return null; try { return decryptText(blob, k) } catch (_) { return null } }
      }
      const identity = await Identity.connect({ dir, atRest: atRestFor(dir), keyLock })
      // ESTE DIRECTORIO ES DE ESTA LLAVE: varias bóvedas en un disco, cada una con el suyo.
      assertKeyOwnsDir(dir, identity.me?.publickey || null)
      return identity
    }
  }
}

export default { nodePlatform }
