/**
 * QUÉ APROBADORES PUEDEN RECIBIR UN AVISO: lo dice cada uno, y caduca.
 *
 * Un aparato con `approve` que no recibe avisos es un aprobador solo en el papel: el pedido
 * no le suena y solo lo ve si abre la app por su cuenta. Para la ACTUALIZACIÓN eso era un
 * bloqueo mudo — la bóveda pedía cada día, nadie se enteraba y se quedaba atrás para siempre
 * (dueño, 2026-10-07).
 *
 * Así que el aprobador lo declara: al pedir su lista de pedidos (`op: 'approvals'`, que ya
 * manda firmado cada vez que se abre) dice `notify: true` si tiene los avisos encendidos.
 * Aquí se apunta CUÁNDO lo dijo por última vez, y vale `NOTIFIABLE_TTL_MS`: una app que se
 * desinstala deja de renovarlo y sale sola de la cuenta.
 *
 * SOLO DECIDE LA ACTUALIZACIÓN. Las claves, las contraseñas y guardar variables siguen
 * pidiendo aprobación mientras haya un aparato con `approve` en el acta, pueda o no recibir
 * avisos: ahí «nadie se entera» se resuelve esperando, no entregando.
 *
 * Y NO SE LE PREGUNTA AL PROXIO, que es quien guarda las suscripciones: es la pieza de la
 * que el diseño no se fía, y creerle sería dejarle decidir cuándo no hace falta permiso.
 *
 * Cifrado en reposo como lo demás. Un archivo que existe y no se puede leer NO es «nadie
 * puede recibir avisos» (eso saltaría la aprobación): se lanza.
 */
import fs from 'node:fs'
import path from 'node:path'

export const NOTIFIABLE_FILE = 'notifiable.json'
/** Cuánto vale un «puedo recibir avisos» sin renovarse. */
export const NOTIFIABLE_TTL_MS = 30 * 24 * 60 * 60 * 1000

const fail = (code, message) => Object.assign(new Error(message), { code })

/**
 * @param {{ dir: string, atRest: { encrypt: (s: string) => string, decrypt: (s: string) => string }, now?: () => number }} opts
 */
export function openNotifiable ({ dir, atRest, now = Date.now }) {
  const file = path.join(dir, NOTIFIABLE_FILE)
  /** pub → ms de la última vez que dijo que sí */
  const items = load()

  function load () {
    let raw
    try { raw = fs.readFileSync(file, 'utf8') } catch (e) {
      if (e.code === 'ENOENT') return new Map()
      throw fail('notifiable-unreadable', `cannot read ${NOTIFIABLE_FILE}: ${e.message}`)
    }
    let d
    try { d = JSON.parse(atRest.decrypt(raw)) } catch (e) { throw fail('notifiable-unreadable', `${NOTIFIABLE_FILE} cannot be opened: ${e.message}`) }
    if (d?.v !== 1 || !d.items || typeof d.items !== 'object') throw fail('notifiable-unreadable', `${NOTIFIABLE_FILE} has an unknown shape`)
    return new Map(Object.entries(d.items))
  }

  function save () {
    const tmp = file + '.tmp'
    fs.writeFileSync(tmp, atRest.encrypt(JSON.stringify({ v: 1, items: Object.fromEntries(items) })), { mode: 0o600 })
    fs.renameSync(tmp, file)
  }

  return {
    /**
     * Lo que acaba de decir un aprobador. `true` lo apunta (o lo renueva); `false` lo quita
     * ya, sin esperar a que caduque. Cualquier otra cosa no dice nada y no cambia nada: un
     * cliente viejo, que no manda el campo, no borra lo que dijo uno nuevo.
     */
    declare (pub, canNotify) {
      if (typeof pub !== 'string' || !pub) throw fail('bad-pub', 'declare: a device key is required')
      if (canNotify === true) { items.set(pub, now()); save() } else if (canNotify === false && items.delete(pub)) save()
    },
    /** Cuándo lo dijo por última vez, o `null` si nunca o si ya caducó. */
    since (pub) {
      const t = items.get(pub)
      return typeof t === 'number' && now() - t < NOTIFIABLE_TTL_MS ? t : null
    }
  }
}
