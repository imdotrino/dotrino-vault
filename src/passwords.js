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
 *   `needsApproval(pubkey)`  (async) si ese aparato tiene que pedir aprobación según el
 *                            ACTA (`unattended`). Se compone con el
 *                        criterio del propio protocolo: solo lo PRIVADO pregunta
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
    // Dos condiciones, y las dos tienen que darse:
    //
    //   · que ese APARATO esté marcado para aprobar (la política del vault: se pide una
    //     vez y dura mientras el vault siga encendido, igual que los cajones de secretos);
    //   · y que lo que pide sea PRIVADO — una contraseña, un código de dos pasos, o un
    //     campo que el usuario marcó. Rellenar un nombre no es sacar un secreto, y pedir
    //     permiso para todo enseña a decir que sí sin mirar.
    //
    // El segundo criterio se toma del propio responder (`wantsPrivate`) en vez de
    // reescribirlo aquí: si cada bóveda tuviera su idea de qué es privado, serían tres
    // bóvedas distintas otra vez.
    needsApproval: async (op, payload, pubkey) =>
      // `await` OBLIGATORIO: `needsApproval` pasó a ser asíncrona (lee el acta en vivo), y
      // una promesa SIEMPRE es verdadera. Sin el await esto decía «sí, pide aprobación»
      // para todo el mundo, y en el otro sentido —si algún día devuelve false— diría que
      // no hace falta. Un `&&` sobre una promesa es una comprobación que no comprueba.
      await needsApproval(pubkey) && await responder.wantsPrivate(op, payload),
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
