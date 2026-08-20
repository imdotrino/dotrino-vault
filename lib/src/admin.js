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
 *       · VARIABLES DE ENTORNO: crearlas y darles valor (de un scope o de un aparato),
 *         y ver el valor de las marcadas PÚBLICAS
 *   no  · cambiar permisos · traspasar el mando · conceder `admin`
 *       · ver el valor de una variable PRIVADA · borrar variables
 *
 * SOBRE LAS VARIABLES, que es la rendija más nueva: lo que cruza la frontera no es «los
 * secretos» sino los que su dueño MARCÓ como mostrables. Una privada se puede reescribir
 * a ciegas desde la consola, pero su valor no sale de la máquina de la bóveda ni para un
 * aparato tuyo con `admin`. Y los valores que sí salen viajan CIFRADOS con la clave de
 * contenido del perfil (quien llama sella y abre): el proxy transporta y no ve nada.
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
export const ADMIN_OPS = Object.freeze([
  'pending', 'pair', 'approve', 'reject', 'revoke', 'audit',
  // Variables de entorno: verlas (nombres siempre; valor solo de las públicas) y
  // ponerles valor (de las dos). Borrar NO está, y es a propósito: un aparato robado
  // no debe poder dejar sin configuración a los servicios.
  // `var.setMany` es la MISMA operación con varias variables dentro de un solo sobre: no
  // añade permisos, quita reinicios (ver el enrutado abajo).
  'vars', 'var.set', 'var.setMany',
  // VER un valor y sus versiones anteriores. Entran aquí —y no en la lista de lo que la
  // bóveda hace por su cuenta— porque la bóveda NO abre nada: entrega el sobre y la
  // envoltura dirigida a ESE aparato, que lo abre con su propia llave (§8.2). Sin esto,
  // administrar a distancia obligaba a teclear la contraseña del perfil en un navegador.
  'var.reveal', 'var.history'
])

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
 * @param {{list:(a:object)=>Promise<any>, set:(a:object)=>Promise<any>, setMany?:(a:object)=>Promise<any>}} [o.vars]
 *   mostrador de VARIABLES DE ENTORNO. Va inyectado porque aquí no hay cripto ni disco:
 *   quien lo implementa (la bóveda) es quien sella con la clave de contenido del perfil y
 *   quien decide qué valor puede salir. Sin él, las ops de variables responden que esta
 *   bóveda no las atiende, en vez de fingir que se aplicaron.
 * @param {(ev:string, info?:object)=>Promise<void>} [o.notify]  aviso a todos los miembros.
 * @param {(op:string, info?:object)=>void} [o.audit]
 * @param {string[]} [o.defaultScope]    lo que recibe un dispositivo emparejado a distancia.
 * @param {number} [o.ttlMs]             vida del cert que se emita.
 */
export function createAdminDesk ({
  desk, verify, readActivity = () => [], deviceIdOf, vars = null,
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

      // VARIABLES DE ENTORNO. El módulo solo enruta y audita: qué valor puede salir y con
      // qué se cifra lo decide la bóveda (`vars`), que es la que tiene la clave y el disco.
      if (data.op === 'vars' || data.op === 'var.set' || data.op === 'var.setMany') {
        if (!vars) return { ok: false, error: 'admin: this vault does not serve environment variables' }
        // Un destino y solo uno: o un scope, o un aparato. Sin esto, mandar los dos dejaría
        // que quien llama adivine dónde acabó su variable.
        // Booleanos a propósito: comparar los VALORES («proxy» vs una pubkey) nunca da
        // igual, así que mandar los dos destinos se colaba por el hueco.
        const toScope = typeof data.ns === 'string' && !!data.ns
        const toDevice = typeof data.pub === 'string' && !!data.pub
        if (data.op === 'vars') {
          const result = await vars.list({ by })
          audit('admin.vars', { by })
          return { ok: true, result }
        }
        if (toScope === toDevice) return { ok: false, error: 'admin: var.set needs exactly one target (ns or pub)' }

        // VARIAS DE UNA VEZ. Mismo permiso y misma frontera que una sola: lo que cambia es
        // que la bóveda las guarda juntas y manda UN aviso de cambio en vez de uno por
        // variable — o sea, el servicio se reinicia una vez, con la configuración entera,
        // en lugar de arrancar a medias mientras quien administra sigue escribiendo.
        // Los nombres viajan DENTRO del sobre, igual que los valores: el proxy tampoco
        // tiene por qué aprender cómo se llaman las variables de un servicio.
        if (data.op === 'var.setMany') {
          // Una bóveda anterior a esto sabe guardar de una en una y nada más. Decirlo es
          // mejor que reventar con un TypeError que no explica qué falta actualizar.
          if (typeof vars.setMany !== 'function') return { ok: false, error: 'admin: this vault cannot save several variables at once (update it)' }
          if (!data.enc || typeof data.enc !== 'object') {
            return { ok: false, error: 'admin: var.setMany needs the variables sealed with the profile content key' }
          }
          const result = await vars.setMany({
            ns: toScope ? data.ns : null,
            pub: toDevice ? data.pub : null,
            enc: data.enc,
            public: typeof data.public === 'boolean' ? data.public : undefined,
            by
          })
          const keys = result?.keys || []
          audit('admin.var.set', { by, ns: toScope ? data.ns : null, device: toDevice ? await deviceIdOf(data.pub).catch(() => null) : null, keys })
          await notify('vars', { by, keys, ns: toScope ? data.ns : null })
          return { ok: true, result: result || { ok: true } }
        }

        if (typeof data.key !== 'string' || !data.key) return { ok: false, error: 'admin: var.set needs a key' }
        if (!data.enc || typeof data.enc !== 'object') {
          // El valor NUNCA viaja en claro: si llega sin sobre, es un error de quien llama,
          // no algo que se pueda «arreglar» aceptándolo.
          return { ok: false, error: 'admin: var.set needs the value sealed with the profile content key' }
        }
        const result = await vars.set({
          ns: toScope ? data.ns : null,
          pub: toDevice ? data.pub : null,
          key: data.key,
          enc: data.enc,
          public: typeof data.public === 'boolean' ? data.public : undefined,
          by
        })
        audit('admin.var.set', { by, ns: toScope ? data.ns : null, device: toDevice ? await deviceIdOf(data.pub).catch(() => null) : null, key: data.key })
        // Cambiar la configuración de un servicio a distancia no puede ser invisible: es
        // la contrapartida de delegar (F3 de docs/consola-remota.md).
        await notify('vars', { by, key: data.key, ns: toScope ? data.ns : null })
        return { ok: true, result: result || { ok: true } }
      }

      // VER un valor (y sus versiones anteriores). La bóveda entrega material sellado a
      // ESTE aparato; abrirlo es cosa suya. Se AUDITA, porque leer un secreto a distancia
      // es exactamente lo que hay que poder revisar después.
      if (data.op === 'var.reveal' || data.op === 'var.history') {
        if (!vars) return { ok: false, error: 'admin: this vault does not serve environment variables' }
        if (typeof vars.reveal !== 'function') return { ok: false, error: 'admin: this vault cannot show values (update it)' }
        const toScope = typeof data.ns === 'string' && !!data.ns
        const toDevice = typeof data.pub === 'string' && !!data.pub
        if (toScope === toDevice) return { ok: false, error: 'admin: it needs exactly one target (ns or pub)' }
        const target = { ns: toScope ? data.ns : null, pub: toDevice ? data.pub : null }

        if (data.op === 'var.history') {
          const result = await vars.history({ ...target, key: typeof data.key === 'string' ? data.key : null })
          audit('admin.var.history', { by, ns: target.ns, key: data.key || null })
          return { ok: true, result }
        }
        if (typeof data.key !== 'string' || !data.key) return { ok: false, error: 'admin: var.reveal needs a key' }
        const result = await vars.reveal({
          ...target,
          key: data.key,
          ts: Number.isFinite(data.ts) ? data.ts : null,
          device: chk.device,
          by
        })
        audit('admin.var.reveal', { by, ns: target.ns, key: data.key, ...(data.ts ? { ts: data.ts } : {}) })
        return { ok: true, result }
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
