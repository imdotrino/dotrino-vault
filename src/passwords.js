/**
 * LA BÓVEDA DE CONTRASEÑAS del dueño, atendida por el vault.
 *
 * `dotrino-passmanager serve` es la versión mínima: bóveda propia, aprobación por
 * consola, bitácora propia. Esto es lo mismo pero dentro del vault, que ya tiene lo
 * que allí había que improvisar:
 *
 *   · el ACTA dice qué aparatos existen y qué puede cada uno
 *   · la APROBACIÓN ya sabe avisar al teléfono y esperar su firma (`caps +aprueba`)
 *   · la BITÁCORA ya existe y es la misma que audita firmas y enrolamientos
 *
 * Lo que NO cambia es el protocolo: un aparato pide una credencial por dominio y
 * recibe esa sola. `list` sigue sin existir en remoto.
 *
 * Módulo aislado a propósito: recibe todo lo que necesita y no toca el núcleo. Un
 * fallo aquí no puede tumbar la CA.
 */

import { LocalVault, VaultResponder } from '@dotrino/passmanager'

export const PASSWORDS_CAP = 'passwords'

/**
 * @param {object} opts
 *   `client`      cliente del proxio del vault, ya identificado
 *   `store`       `{ get(k), set(k,v) }` donde viven las entradas cifradas
 *   `cek`         la llave de la bóveda de contraseñas (CryptoKey AES-GCM)
 *   `isAllowed(pubkey)`   qué aparatos pueden pedir — lo decide el acta, no esto
 *   `encPubOf(pubkey)`    su llave de cifrado, para sellarle la respuesta
 *   `needsApproval(pubkey)`  si ese aparato está marcado para aprobar
 *   `approve({ pubkey, op })`  pide el visto bueno (el teléfono) y espera
 *   `devices()` / `unlink(pubkey)`   administración, opcional
 *   `audit(op, info)`  la bitácora del vault
 */
export function createPasswordDesk (opts = {}) {
  const {
    client, store, cek,
    isAllowed = () => false,
    encPubOf = () => null,
    needsApproval = () => true,
    approve = async () => false,
    devices = null,
    unlink = null,
    audit = () => {},
    log = () => {},
  } = opts

  const vault = new LocalVault(store)
  if (cek) vault.unlock(cek)

  const responder = new VaultResponder({
    client,
    vault,
    isAllowed,
    encPubOf,
    // La aprobación es del APARATO y dura mientras el vault siga encendido, igual que
    // los cajones de secretos: una por arranque, sin ventana que vigilar.
    needsApproval: (op, _payload, pubkey) => op === 'get' && needsApproval(pubkey),
    approve,
    admin: devices && unlink ? { devices, unlink } : null,
    onRequest: (r) => {
      // La bitácora NO lleva qué credencial se pidió: eso es contenido del usuario y
      // el criterio del vault es apuntar la operación, no el payload.
      audit('passwords', { op: r.op, outcome: r.outcome, device: (r.from || '').slice(0, 24) })
      if (r.outcome !== 'served') {
        log('[vault] passwords: %s %s', r.op, r.outcome)
      }
    },
  })

  return {
    start () { responder.start(); return this },
    stop () { responder.stop() },
    /** Al bloquear el perfil, la bóveda de contraseñas se cierra con él. */
    lock () { vault.lock() },
    unlock (nuevaCek) { vault.unlock(nuevaCek) },
    /** Para la consola local: aquí SÍ se puede listar, porque aquí está la llave. */
    vault,
    responder,
  }
}
