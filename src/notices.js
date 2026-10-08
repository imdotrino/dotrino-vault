/**
 * LO QUE LA BÓVEDA TIENE QUE CONTARLE A QUIEN APRUEBA, y que no es un pedido.
 *
 * Hoy es uno: «me actualicé» —la bóveda o uno de sus aparatos— (`ev: 'updated'`, dueño 2026-10-08: «las actualizaciones, que se
 * envíe una notificación de que ocurrieron a los aprobadores»). Sale como aviso por el
 * proxio, pero el timbre de una app nativa llega VACÍO —lo leen Google y Apple—, así que la
 * app pregunta por su lista (`op: 'approvals'`) y lo lee de aquí, en `notices`.
 *
 * Caduca a las 24 h: es una noticia, no un registro (eso es la bitácora).
 *
 * Cifrado en reposo como lo demás. Un archivo que existe y no se puede leer se LANZA: callar
 * sería decir «no pasó nada» de algo que sí pasó.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

export const NOTICES_FILE = 'notices.json'
/** Cuánto se sigue contando un aviso. */
export const NOTICE_TTL_MS = 24 * 60 * 60 * 1000

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ dir: string, atRest: { encrypt: (s: string) => string, decrypt: (s: string) => string }, now?: () => number }} opts
 */
export function openNotices ({ dir, atRest, now = Date.now }) {
  const file = path.join(dir, NOTICES_FILE)
  let items = load()

  function load () {
    if (!fs.existsSync(file)) return []
    try {
      const d = JSON.parse(atRest.decrypt(fs.readFileSync(file, 'utf8')))
      if (!d || !Array.isArray(d.items)) throw new Error('not a list')
      return d.items.filter((n) => n && typeof n.id === 'string' && typeof n.ts === 'number')
    } catch (e) { throw fail('notices-unreadable', `${NOTICES_FILE} cannot be read: ${e.message}`) }
  }

  function save () {
    const tmp = file + '.tmp'
    fs.writeFileSync(tmp, atRest.encrypt(JSON.stringify({ v: 1, items })), { mode: 0o600 })
    fs.renameSync(tmp, file)
  }

  const alive = (n) => now() - n.ts < NOTICE_TTL_MS

  return {
    /**
     * Apunta que algo se actualizó. Devuelve el aviso tal como viaja. `product`: qué
     * (`@dotrino/vaultd` es la propia bóveda); `deviceId`/`label`: el aparato, si fue uno.
     */
    updated ({ version, from = null, product = '@dotrino/vaultd', deviceId = null, label = null }) {
      if (typeof version !== 'string' || !version) throw fail('bad-notice', 'updated: a version is required')
      if (typeof product !== 'string' || !product) throw fail('bad-notice', 'updated: a product is required')
      const n = {
        id: crypto.randomBytes(8).toString('hex'), ev: 'updated', product, version, from: typeof from === 'string' ? from : null,
        ...(typeof deviceId === 'string' && deviceId ? { deviceId, label: typeof label === 'string' ? label : '' } : {}),
        ts: now()
      }
      items = [...items.filter(alive), n]
      save()
      return n
    },
    /** Los avisos vivos, del más viejo al más nuevo. */
    list () { return items.filter(alive).map((n) => ({ ...n })) }
  }
}
