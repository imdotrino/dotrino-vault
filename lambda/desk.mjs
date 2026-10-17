/**
 * LA BÓVEDA QUE ATIENDE PETICIONES: el mostrador de la Lambda, sin nada de AWS dentro.
 *
 * Lo usan el handler de la Lambda (`./handler.mjs`) y la prueba en local. Hace tres cosas:
 *
 *   1. al abrir, baja el perfil del almacén a un directorio y arranca la bóveda del
 *      binario sobre él (`src/vault.js`, la misma plataforma, el mismo núcleo);
 *   2. por cada petición, pasa el mensaje por `vault.localChannel` —el mismo enrutador y
 *      las mismas comprobaciones que por el proxio— y espera la respuesta;
 *   3. después de cada petición, sube al almacén lo que cambió.
 *
 * LO QUE TODAVÍA NO HACE (prueba de concepto, ver `README.md`):
 *   · lo que la bóveda manda DESPUÉS de contestar (el resultado de una aprobación, un aviso)
 *     no vuelve por esta petición;
 *   · lo que se escribe en disco cuando la respuesta ya salió se sube en la siguiente
 *     petición, y si el contenedor muere antes, se pierde.
 */
import fs from 'node:fs'
import path from 'node:path'
import { createMirror } from './mirror.mjs'
import { configFromEnv, probe as probeKek, writeConfig as writeKekConfig, CONFIG_FILE } from '../src/atrest.js'

/** El mismo tope que las respuestas de la bóveda (`MAX_REPLY_BYTES` del núcleo). */
export const MAX_REQUEST_BYTES = 768 * 1024

/**
 * @param {object} opts
 * @param {object} opts.store       el almacén (`./mirror.mjs`)
 * @param {string} opts.dir         el directorio local del perfil (en Lambda, bajo `/tmp`)
 * @param {Function} opts.startVault `src/vault.js#startVault`
 * @param {string} [opts.proxyUrl]
 * @param {Function} [opts.log]
 */
export async function openDesk ({ store, dir, startVault, proxyUrl, log = () => {} }) {
  const mirror = createMirror({ store, dir })
  const pulled = await mirror.pull()
  log(`[vault-lambda] profile pulled from the store: ${pulled} file(s)`)
  // UN PERFIL NUEVO NACE CON LA LLAVE FUERA DE LA MÁQUINA, o no nace. Aquí la «máquina» es
  // un contenedor que cambia en cada frío: con la llave derivada de ella, la cuenta quedaría
  // ilegible en el siguiente arranque. Uno que ya existe manda con su propio `atrest.json`.
  if (!fs.existsSync(path.join(dir, CONFIG_FILE))) {
    if (pulled) throw Object.assign(new Error(`the stored profile has no ${CONFIG_FILE}: refusing to guess how its disk is encrypted`), { code: 'no-kek-config' })
    const kek = configFromEnv()
    if (!kek) throw Object.assign(new Error('a new profile here needs a key service: set DOTRINO_KMS_KEY_ID or DOTRINO_KEK_CMD'), { code: 'no-kms' })
    probeKek(dir, kek)
    writeKekConfig(dir, kek)
  }
  const vault = await startVault({ dir, proxyUrl, log })
  // Una cuenta recién nacida escribe su identidad al arrancar: se sube YA, antes de atender
  // nada, o una muerte del contenedor se llevaría la cuenta entera.
  const created = await mirror.push()
  if (created) log(`[vault-lambda] profile pushed after start: ${created} file(s)`)

  return {
    vault,
    /**
     * Atiende UN mensaje y devuelve lo que la bóveda contestó. Lanza con `code` si no
     * contesta a tiempo o si no se pudo guardar lo que cambió: una respuesta cuyo efecto no
     * quedó guardado no se entrega como si nada.
     */
    async handle (payload, { timeoutMs = 25000 } = {}) {
      const replies = []
      let ch
      const first = new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(Object.assign(new Error('the vault did not answer in time'), { code: 'vault-timeout' })), timeoutMs)
        ch = vault.localChannel((obj) => { replies.push(obj); clearTimeout(t); resolve() })
      })
      try {
        ch.send(payload)
        await first
        // Lo que el handler escribe justo al contestar (la bitácora, una marca) llega en el
        // mismo turno o en el siguiente: se le da ese turno antes de subir.
        await new Promise((resolve) => setImmediate(resolve))
      } finally {
        ch.close()
      }
      await mirror.push()
      return replies
    },
    /** Sube lo que cambió fuera de una petición (la consola del mismo proceso, en local). */
    sync: () => mirror.push(),
    close () { try { vault.close() } catch (_) {} }
  }
}

/**
 * UNA PETICIÓN HTTP, DE PRINCIPIO A FIN: valida, la pasa al mostrador y arma la respuesta.
 * Es lo único que hay entre el HTTP y la bóveda, y lo comparten la Lambda y la prueba.
 *
 * @param {() => Promise<object>} getDesk  el mostrador abierto (lo abre quien llama)
 * @param {{ method: string, body: string }} req
 * @param {{ onConflict?: Function, log?: Function }} [opts]
 * @returns {Promise<{ statusCode: number, body: object }>}
 */
export async function answerHttp (getDesk, { method, body }, { onConflict = () => {}, log = () => {} } = {}) {
  if (method !== 'POST') return { statusCode: 405, body: { error: 'POST only' } }
  if (Buffer.byteLength(body || '') > MAX_REQUEST_BYTES) return { statusCode: 413, body: { error: 'request too big' } }
  let payload
  try { payload = JSON.parse(body || '') } catch (_) { return { statusCode: 400, body: { error: 'malformed request' } } }

  let d
  try { d = await getDesk() } catch (e) {
    log(`[vault-lambda] could not open the vault: ${e.code || ''} ${e.message}`)
    return { statusCode: 500, body: { error: 'the vault could not open', code: e.code || null } }
  }
  try {
    return { statusCode: 200, body: { replies: await d.handle(payload) } }
  } catch (e) {
    if (e.code === 'store-conflict') {
      // Otro escritor cambió el perfil: lo que hay en memoria ya no es el estado bueno. Se
      // tira entero y la próxima petición arranca desde el almacén.
      log(`[vault-lambda] ${e.message}: dropping this state`)
      d.close(); onConflict()
      return { statusCode: 503, body: { error: 'the vault changed underneath, retry', code: e.code } }
    }
    log(`[vault-lambda] request failed: ${e.code || ''} ${e.message}`)
    return { statusCode: 500, body: { error: e.message, code: e.code || null } }
  }
}

export default { openDesk, answerHttp, MAX_REQUEST_BYTES }
