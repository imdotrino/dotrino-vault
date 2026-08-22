/**
 * PEDIDOS DE APROBACIÓN y VENTANAS de un cajón con `approval` (puro: sin red ni disco).
 *
 * Cuando un cajón exige aprobación por uso, leerlo ya no depende solo de tener el cert:
 * el vault apunta el pedido, avisa a los aparatos con `approve` (el teléfono), y solo su
 * firma libera los secretos. Aprobado, se abre una VENTANA para ese aparato y ese cajón
 * (15 min): una sesión de trabajo no pide veinte veces. Lo que nadie aprueba vence solo.
 *
 * Lo que se guarda de cada pedido es lo justo para contestar después: el cajón, quién
 * pide y su llave efímera `ek` (a la que se sella la respuesta). Nunca un valor.
 */
const rnd = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('')

export const PENDING_TTL_MS = 5 * 60 * 1000
export const GRANT_TTL_MS = 15 * 60 * 1000

export function createApprovals ({ now = Date.now, pendingTtlMs = PENDING_TTL_MS, grantTtlMs = GRANT_TTL_MS } = {}) {
  /** id → { id, ns, device, deviceId, label, ek, ts, exp } */
  const pending = new Map()
  /** `${ns}|${device}` → exp */
  const grants = new Map()
  const gkey = (ns, device) => ns + '|' + device

  const publicOf = (p) => ({ id: p.id, kind: p.kind, ns: p.ns, deviceId: p.deviceId, label: p.label, ts: p.ts, exp: p.exp, ...(p.ssh ? { ssh: p.ssh } : {}) })

  return {
    /**
     * Apunta un pedido. `kind`: `secrets` (leer un cajón; uno por cajón y aparato: pedir
     * otra vez reemplaza al anterior) o `ssh` (firmar un reto SSH con la llave del
     * teléfono; cada firma es un pedido, con `ssh: { key, data }` y sus callbacks).
     */
    request ({ kind = 'secrets', ns, device = null, deviceId, label = '', ek = null, ssh = null, resolve = null, reject = null }) {
      if (kind === 'secrets') for (const [id, p] of pending) if (p.kind === 'secrets' && p.ns === ns && p.device === device) pending.delete(id)
      const ts = now()
      const p = { id: rnd(), kind, ns, device, deviceId, label, ek, ssh, resolve, reject, ts, exp: ts + pendingTtlMs }
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
    /** Abre la ventana de ese aparato sobre ese cajón. */
    grant (ns, device) { const exp = now() + grantTtlMs; grants.set(gkey(ns, device), exp); return exp },
    /** ¿Sigue abierta la ventana? */
    has (ns, device) {
      const exp = grants.get(gkey(ns, device))
      if (exp == null) return false
      if (exp <= now()) { grants.delete(gkey(ns, device)); return false }
      return true
    },
    /** Cierra las ventanas de un aparato (al revocarlo, por ejemplo). */
    forget (device) { for (const k of [...grants.keys()]) if (k.endsWith('|' + device)) grants.delete(k) },
    /** Tira lo vencido; devuelve los pedidos que vencieron, para anotarlos. */
    sweep () {
      const t = now(); const gone = []
      for (const [id, p] of pending) if (p.exp <= t) { pending.delete(id); gone.push(publicOf(p)); try { p.reject?.(new Error('approval: nobody approved the request in time')) } catch (_) {} }
      for (const [k, exp] of grants) if (exp <= t) grants.delete(k)
      return gone
    }
  }
}

export default { createApprovals, PENDING_TTL_MS, GRANT_TTL_MS }
