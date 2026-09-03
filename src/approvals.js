/**
 * PEDIDOS DE APROBACIÓN (puro: sin red ni disco).
 *
 * Un aparato marcado con `approval on` no recibe claves privadas solo por tener el cert: el
 * vault apunta el pedido, avisa a los aparatos con `approve` (el teléfono), y solo su firma
 * libera los secretos. No hay ventana: cada petición es un pedido, y para un servicio bien
 * hecho eso es UNA por arranque (pide al iniciar, se queda las claves en memoria). Lo que
 * nadie aprueba vence solo a los 5 min.
 *
 * Lo que se guarda de cada pedido es lo justo para contestar después: el cajón, quién pide
 * y su llave efímera `ek` (a la que se sella la respuesta). Nunca un valor.
 */
const rnd = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('')

export const PENDING_TTL_MS = 5 * 60 * 1000

export function createApprovals ({ now = Date.now, pendingTtlMs = PENDING_TTL_MS } = {}) {
  /** id → { id, ns, device, deviceId, label, ek, ts, exp } */
  const pending = new Map()
  const publicOf = (p) => ({ id: p.id, ns: p.ns, deviceId: p.deviceId, label: p.label, ts: p.ts, exp: p.exp })

  return {
    /** Apunta un pedido. Uno por cajón y aparato: pedir otra vez reemplaza al anterior. */
    /**
     * `from` es POR DÓNDE ENTRÓ la pregunta. La respuesta llega más tarde —cuando alguien
     * apruebe— y tiene que volver por el mismo sitio: desde que la bóveda atiende también
     * por un socket local, mandarla siempre por el proxio la dejaba en el vacío.
     */
    request ({ ns, device, deviceId, label = '', ek, from = null }) {
      for (const [id, p] of pending) if (p.ns === ns && p.device === device) pending.delete(id)
      const ts = now()
      const p = { id: rnd(), ns, device, deviceId, label, ek, ts, exp: ts + pendingTtlMs, from }
      pending.set(p.id, p)
      return publicOf(p)
    },
    /** Los pedidos vivos, sin la `ek` (no hace falta fuera de aquí). */
    list () { this.sweep(); return [...pending.values()].map(publicOf) },
    /** Saca un pedido para resolverlo (aprobar o denegar). `null` si no existe o venció. */
    take (id) {
      this.sweep()
      const p = pending.get(id)
      if (p) pending.delete(id)
      return p || null
    },
    /** Tira lo vencido; devuelve los pedidos que vencieron, para anotarlos. */
    sweep () {
      const t = now(); const gone = []
      for (const [id, p] of pending) if (p.exp <= t) { pending.delete(id); gone.push(publicOf(p)) }
      return gone
    }
  }
}

export default { createApprovals, PENDING_TTL_MS }
