/**
 * admin.js — CONSOLA REMOTA: administrar el perfil desde un dispositivo emparejado.
 *
 * Diseño: `dotrino-vault/docs/consola-remota.md`. Módulo PURO (sin `node:*`, sin red,
 * sin disco), igual que `enroll.js`, para que lo puedan usar el daemon del PC y «este
 * dispositivo es bóveda» sin duplicar la regla.
 *
 * QUÉ SE DELEGA Y QUÉ NO — esto es el módulo entero, el resto es plomería:
 *
 *   sí  · ver el acta y la bitácora · iniciar un emparejamiento (mostrar el QR)
 *       · APROBAR o rechazar a quien entra · REVOCAR a un miembro
 *   no  · cambiar permisos · traspasar el mando · conceder `admin`
 *       · nada de los secretos de servicios
 *
 * La frontera no es un capricho: un admin puede **admitir y expulsar**, pero no
 * reescribir quién manda. Así un aparato con `admin` robado hace daño **acotado y
 * reversible** (se le revoca) en vez de poder traspasarse el mando y dejar al dueño
 * fuera de su propia cuenta, que no tiene vuelta atrás. Las operaciones que no se
 * delegan **no existen como mensaje**: no hay nada que autorizar mal.
 *
 * POR QUÉ APROBAR A DISTANCIA NO DEBILITA EL EMPAREJAMIENTO: el código de 6 dígitos es
 * un COMPROMISO (`enroll.js`) — lo genera y lo MUESTRA el aparato que entra, y la bóveda
 * solo firma si el código tecleado lo recompone. Aprobar exige haber leído la pantalla
 * del aparato nuevo, se haga desde el PC o desde el teléfono. Lo que cambia es dónde
 * está el humano, no qué tiene que demostrar.
 */

/** Las únicas operaciones que existen a distancia. Lista cerrada, como las capacidades. */
export const ADMIN_OPS = Object.freeze(['pending', 'pair', 'approve', 'reject', 'revoke', 'audit'])

/** Cuánto se recuerda un nonce ya usado (el doble de la ventana de frescura). */
export const ADMIN_NONCE_TTL_MS = 10 * 60 * 1000

/** Tope de entradas de bitácora por petición. */
export const AUDIT_MAX = 500

/**
 * @param {Object} o
 * @param {Object} o.desk                mostrador de emparejamiento (`createEnrollDesk`).
 * @param {(scope:string[])=>Promise<any>} o.verify  verifica cadena+cert; devuelve `{ok, device, reason}`.
 * @param {(limit:number)=>any[]} o.readActivity     últimas entradas de la bitácora.
 * @param {(pub:string)=>Promise<string>} o.deviceIdOf
 * @param {(ev:string, info?:object)=>Promise<void>} [o.notify]  aviso a todos los miembros.
 * @param {(op:string, info?:object)=>void} [o.audit]
 * @param {string[]} [o.defaultScope]    lo que recibe un dispositivo emparejado a distancia.
 * @param {number} [o.ttlMs]             vida del cert que se emita.
 */
export function createAdminDesk ({
  desk, verify, readActivity = () => [], deviceIdOf,
  notify = async () => {}, audit = () => {},
  defaultScope = ['vault:sign', 'vault:read', 'vault:store'],
  ttlMs, now = () => Date.now()
}) {
  const ops = new Set(ADMIN_OPS)

  // NONCE de un solo uso. `sign`/`get` son idempotentes y les basta la ventana de ±5
  // min; `approve` y `revoke` CAMBIAN ESTADO, así que reproducir uno dentro de esa
  // ventana sí importa (re-aprobar un enrolamiento que el dueño ya rechazó, por
  // ejemplo). Por eso el nonce, y por eso es obligatorio en todas las ops: una lista
  // de excepciones es una invitación a equivocarse.
  const seen = new Map()
  function nonceAlreadyUsed (nonce) {
    const t = now()
    for (const [n, exp] of seen) if (exp <= t) seen.delete(n)
    if (seen.has(nonce)) return true
    seen.set(nonce, t + ADMIN_NONCE_TTL_MS)
    return false
  }

  /**
   * Atiende una petición ya verificada como *fresca*. Devuelve `{ ok, result }` o
   * `{ ok: false, error }` — quien llama se encarga de responder por el transporte.
   */
  async function handle (data, { signature, cert } = {}) {
    if (!data || !ops.has(data.op)) return { ok: false, error: 'admin: invalid operation' }
    if (typeof data.nonce !== 'string' || data.nonce.length < 16) {
      return { ok: false, error: 'admin: missing single-use nonce' }
    }

    const chk = await verify({ data, signature, cert })
    if (!chk?.ok) {
      audit('rejected', { what: 'admin', op: data.op, reason: chk?.reason })
      return { ok: false, error: 'unauthorized: ' + (chk?.reason || 'cert') }
    }
    const by = await deviceIdOf(chk.device).catch(() => null)

    // El nonce se marca DESPUÉS de autorizar: si no, cualquiera podría quemarle los
    // nonces a un admin legítimo mandando basura firmada por nadie.
    if (nonceAlreadyUsed(data.nonce)) {
      audit('rejected', { what: 'admin', op: data.op, by, reason: 'replay' })
      return { ok: false, error: 'admin: nonce already used' }
    }

    try {
      if (data.op === 'pending') return { ok: true, result: { pending: desk.listPending() } }

      if (data.op === 'audit') {
        const limit = Math.min(Math.max(Number(data.limit) || 100, 1), AUDIT_MAX)
        return { ok: true, result: { entries: readActivity(limit) } }
      }

      if (data.op === 'pair') {
        // Un admin NO empareja servicios ni crea otros admins. Se corta aquí, en la
        // bóveda, no en la interfaz: una pantalla no es un control de seguridad.
        const scope = Array.isArray(data.scope) && data.scope.length ? data.scope : defaultScope
        const forbidden = scope.find((s) => s === 'vault:admin' || String(s).startsWith('vault:secrets:'))
        if (forbidden) {
          audit('rejected', { what: 'admin', op: 'pair', by, reason: 'forbidden-scope', scope: forbidden })
          return { ok: false, error: 'admin: cannot grant admin or service secrets from here; do that on the vault machine' }
        }
        const label = String(data.label || '').slice(0, 60) || 'remoto'
        const r = await desk.startPairing({ scope, label, ...(ttlMs ? { ttlMs } : {}) })
        audit('admin.pair', { by })
        return { ok: true, result: r }
      }

      if (data.op === 'approve') {
        const r = await desk.approve(String(data.code || ''), { deviceId: data.deviceId })
        audit('admin.approve', { by, device: data.deviceId || null })
        await notify('enrolled', { deviceId: r?.deviceId || data.deviceId || null, by })
        return { ok: true, result: r || { ok: true } }
      }

      if (data.op === 'reject') {
        desk.reject(data.deviceId)
        audit('admin.reject', { by, device: data.deviceId || null })
        return { ok: true, result: { ok: true } }
      }

      // QUITAR UN DISPOSITIVO se hace por `sub` (su llave): sale del acta Y se le retiran
      // todos los certificados. Las dos cosas o ninguna.
      //
      // `certNonce` retira UN PAPEL y nada más — el aparato sigue siendo miembro. Sirve
      // para eso y solo para eso, y se conserva por compatibilidad, pero no es «quitar»:
      // usarlo para quitar dejaba un miembro sin certificados al que la bóveda ya nunca le
      // mandaba el aviso de expulsión (mientras siga en el acta, un papel retirado
      // significa «renueva»). Ese era el dispositivo fantasma.
      if (data.op === 'revoke') {
        if (data.sub) {
          const deviceId = await deviceIdOf(String(data.sub)).catch(() => null)
          const r = await desk.revokeDevice(String(data.sub))
          audit('admin.revoke-device', { by, device: deviceId, certs: r?.nonces?.length ?? null })
          // Con el `deviceId`: el aviso a los demás dispositivos tiene que decir a QUIÉN
          // quitaron, o no se puede saber si el que sobra eres tú.
          await notify('revoked', { deviceId, by })
          return { ok: true, result: r || { ok: true } }
        }
        const r = await desk.revoke(String(data.certNonce || ''))
        audit('admin.revoke', { by, certNonce: data.certNonce })
        await notify('revoked', { certNonce: data.certNonce, by })
        return { ok: true, result: r || { ok: true } }
      }
    } catch (e) {
      audit('rejected', { what: 'admin', op: data.op, by, reason: e.message })
      return { ok: false, error: e.message }
    }
    return { ok: false, error: 'admin: invalid operation' }
  }

  return { handle, get nonceCount () { return seen.size } }
}

export default { createAdminDesk, ADMIN_OPS, ADMIN_NONCE_TTL_MS }
