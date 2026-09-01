/**
 * admin.js — CONSOLA REMOTA: administrar el perfil desde un dispositivo emparejado.
 *
 * Diseño: `dotrino-vault/docs/consola-remota.md`. Módulo PURO (sin `node:*`, sin red,
 * sin disco), igual que `enroll.js`, para que lo puedan usar el daemon del PC y «este
 * dispositivo es bóveda» sin duplicar la regla.
 *
 * QUÉ SE DELEGA Y QUÉ NO — esto es el módulo entero, el resto es plomería:
 *
 *   sí  · ver el acta y la bitácora · REVOCAR a un miembro
 *       · VARIABLES DE ENTORNO: crearlas y darles valor (de un scope o de un aparato),
 *         y ver el valor de las marcadas PÚBLICAS
 *   no  · AGREGAR UN APARATO (quitado 2026-08-31, ver abajo)
 *       · cambiar permisos · traspasar el mando · conceder `admin`
 *       · ver el valor de una variable PRIVADA · borrar variables
 *       · NADA que cambie algo mientras el perfil está CERRADO (ver
 *         `ADMIN_OPS_WHILE_LOCKED`): el candado es de la consola, y esto es la consola.
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
 * POR QUÉ AGREGAR APARATOS YA NO SE HACE DESDE AQUÍ (dueño, 2026-08-31). Existía para
 * ahorrarse ir hasta la máquina de la bóveda. El **multivault** quita esa fricción de raíz
 * —cualquier otra selladora abierta admite el aparato— así que esto dejó de comprar nada y
 * se quedaba pidiendo lo caro: que la maestra pudiera firmar a distancia.
 *
 * Y era incompatible con la regla dura del acta: la maestra solo sella el acta y reenvuelve
 * sobres, y con la bóveda cerrada no firma nada. Admitir a alguien es emitir un certificado
 * Y sellar el acta: las dos cosas son de una selladora abierta, y esta consola no lo es.
 *
 * **Quitado de raíz, no escondido**: no existe la operación, ni el mensaje, ni el botón.
 * Una funcionalidad escondida sigue siendo superficie de ataque y vuelve sola en el
 * siguiente refactor.
 */

/** Las únicas operaciones que existen a distancia. Lista cerrada, como las capacidades. */
export const ADMIN_OPS = Object.freeze([
  // `pending`, `pair`, `approve` y `reject` NO están, y no es un olvido: agregar aparatos
  // a distancia se quitó (ver la cabecera). Lo que queda es mirar, quitar y configurar.
  'revoke', 'audit',
  // Variables de entorno: verlas (nombres siempre; valor solo de las públicas) y
  // ponerles valor (de las dos). Borrar NO está, y es a propósito: un aparato robado
  // no debe poder dejar sin configuración a los servicios.
  // `var.setMany` es la MISMA operación con varias variables dentro de un solo sobre: no
  // añade permisos, quita reinicios (ver el enrutado abajo).
  // Ver un valor, su histórico o volver a una versión NO están, y es a propósito: un
  // aparato que administra no tiene sobres de lo privado (solo el servicio dueño y la
  // recuperación). Eso lo hace la bóveda en su máquina (`secret show/history/revert`).
  // No lo cablees.
  'vars', 'var.set', 'var.setMany'
])

/**
 * QUÉ SE ATIENDE CON EL CANDADO ECHADO.
 *
 * No es «solo mirar», y confundirlo fue un error: **guardar una variable NO necesita la
 * maestra**. Sellar un valor usa las llaves PÚBLICAS de quien va a leerlo, así que la
 * bóveda puede hacerlo sin ningún secreto suyo (`docs/secretos-sellados.md` §8.1) — es
 * justo lo que hace barata la rotación. Meterlo en el mismo saco que revocar dejaba la
 * consola sin poder configurar nada con el perfil cerrado, que es su trabajo diario.
 *
 * Lo que SÍ se queda fuera es `revoke`: reescribe el acta, y sellar el acta es de la
 * maestra. Cerrada no hay con qué.
 *
 * (Si el cajón tiene su llave sellada con la frase, repartirla a los miembros puede quedar
 * a deber hasta que alguien abra: eso ya lo dice la bóveda y se salda solo. Guardar el
 * valor, que es lo que se pidió, se hace igual.)
 *
 * El candado ES de la consola —los aparatos ya emparejados siguen leyendo, guardando y
 * firmando con SU llave— así que cerrar el perfil tiene que cerrar exactamente esto. No
 * estaba: `admin.pair` y `admin.approve` pasaban con el perfil bloqueado, y `approve`
 * firmaba un certificado de 30 días CON LA MAESTRA. Esas dos ya no existen —agregar
 * aparatos se quitó de aquí—, pero la regla se queda para las que quedan: revocar reescribe
 * el acta y configurar toca los secretos.
 *
 * Se dejan las de LEER a propósito: si se cortaran todas, la consola no podría ni
 * enterarse de por qué no funciona y parecería rota. Así puede decir «está cerrada».
 */
export const ADMIN_OPS_WHILE_LOCKED = Object.freeze(['audit', 'vars', 'var.set', 'var.setMany'])

/** Cuánto se recuerda un nonce ya usado (el doble de la ventana de frescura). */
export const ADMIN_NONCE_TTL_MS = 10 * 60 * 1000

/** Tope de entradas de bitácora por petición. */
export const AUDIT_MAX = 500

/**
 * @param {Object} o
 * @param {Object} o.desk                `createEnrollDesk`, del que aquí solo se usa REVOCAR
 *   (`revoke`/`revokeDevice`). Emparejar y aprobar ya no se atienden a distancia.
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
 * @param {()=>boolean} [o.isLocked]  candado del perfil. Cerrado, solo se atiende
 *   `ADMIN_OPS_WHILE_LOCKED`; lo demás responde con el código `vault-locked`.
 */
export function createAdminDesk ({
  desk, verify, readActivity = () => [], deviceIdOf, vars = null,
  notify = async () => {}, audit = () => {}, isLocked = () => false,
  now = () => Date.now()
}) {
  const ops = new Set(ADMIN_OPS)
  const mientrasCerrada = new Set(ADMIN_OPS_WHILE_LOCKED)

  // NONCE de un solo uso. `sign`/`get` son idempotentes y les basta la ventana de ±5
  // min; `revoke` y `var.set` CAMBIAN ESTADO, así que reproducir uno dentro de esa
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

    // CERRADA NO SE SELLA EL ACTA. Va después de autorizar (el candado es estado del perfil,
    // y a un desconocido no se le cuenta) y ANTES de quemar el nonce: quien reintente
    // tras abrir la bóveda no tiene por qué generar otro.
    //
    // El código va aparte del texto porque el texto se traduce y el código no: quien
    // llama distingue «está cerrada, ábrela» de «no tienes permiso» sin leer la frase.
    if (isLocked() && !mientrasCerrada.has(data.op)) {
      audit('rejected', { what: 'admin', op: data.op, by, reason: 'locked' })
      return {
        ok: false,
        code: 'vault-locked',
        error: 'vault locked: unlock the profile on the vault machine (dotrino-vault unlock) to administer it'
      }
    }

    // El nonce se marca DESPUÉS de autorizar: si no, cualquiera podría quemarle los
    // nonces a un admin legítimo mandando basura firmada por nadie.
    if (nonceAlreadyUsed(data.nonce)) {
      audit('rejected', { what: 'admin', op: data.op, by, reason: 'replay' })
      return { ok: false, error: 'admin: nonce already used' }
    }

    try {

      if (data.op === 'audit') {
        const limit = Math.min(Math.max(Number(data.limit) || 100, 1), AUDIT_MAX)
        return { ok: true, result: { entries: readActivity(limit) } }
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

export default { createAdminDesk, ADMIN_OPS, ADMIN_OPS_WHILE_LOCKED, ADMIN_NONCE_TTL_MS }
