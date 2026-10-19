/**
 * LA PUERTA DEL ADMIN: la llave del perfil `K` envuelta con lo que sale de una contraseña
 * (`docs/abrir-a-distancia.md`), y el freno de intentos que la protege.
 *
 * La usan las dos bóvedas que se abren desde la consola: la de escritorio (`profiles.js`, el
 * sobre `kdf2` junto a la puerta principal) y la alojada en la Lambda (`lambda/lock.mjs`, donde
 * es la ÚNICA puerta). Vive aquí para que la regla sea una: si el freno o el sobre cambiaran en
 * un sitio y no en el otro, la misma contraseña abriría en una y no en la otra.
 *
 * El molino (scrypt) lo hace quien teclea, en el navegador: aquí solo llega la derivada.
 */
import { encryptText, decryptText } from '../lib/src/atrest.js'

/**
 * Los números del molino. El navegador tiene que derivar con EXACTAMENTE estos, así que se le
 * mandan (`params`) en vez de que los copie.
 */
export const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, len: 32 })

/** El freno olvida los fallos viejos: estorba a una ráfaga, no a quien vuelve al día siguiente. */
export const TRIES_FORGET_MS = 15 * 60 * 1000

const b64 = (u8) => Buffer.from(u8).toString('base64')

/** Un salt nuevo para una puerta (32 bytes, base64). */
export const newSalt = () => b64(crypto.getRandomValues(new Uint8Array(32)))

/** Envuelve la llave del perfil con la derivada de la contraseña. */
export function wrapKey (key, derived) {
  if (!(derived instanceof Uint8Array) || derived.length !== 32) throw new Error('the admin key must be 32 bytes')
  return encryptText(b64(key), Buffer.from(derived))
}

/**
 * La desenvuelve. AES-GCM autentica, así que una derivada equivocada NO descifra: eso ES la
 * comprobación, y no hace falta un verificador aparte. `null` si no abre.
 */
export function unwrapKey (wrapped, derived) {
  let key = null
  try { key = Buffer.from(decryptText(wrapped, Buffer.from(derived)), 'base64') } catch (_) { key = null }
  return key && key.length === 32 ? new Uint8Array(key) : null
}

/**
 * EL FRENO. Recibe los intentos guardados (`{ n, at }` o nada) y devuelve los vigentes: los
 * vencidos vuelven a cero (`reset`). Cinco fallos y espera exponencial, hasta cinco minutos;
 * mientras dure, lanza `TOO_MANY_TRIES` con `waitSec`.
 */
export function checkTries (saved, now = Date.now()) {
  let tries = saved || { n: 0, at: 0 }
  let reset = false
  if (tries.at && now - tries.at > TRIES_FORGET_MS) { tries = { n: 0, at: 0 }; reset = !!saved }
  const waitMs = tries.n >= 5 ? Math.min(2 ** (tries.n - 4) * 1000, 5 * 60 * 1000) : 0
  const left = tries.at + waitMs - now
  if (left > 0) {
    throw Object.assign(new Error(`too many tries: wait ${Math.ceil(left / 1000)} s`),
      { code: 'TOO_MANY_TRIES', waitSec: Math.ceil(left / 1000) })
  }
  return { tries, reset }
}

export default { SCRYPT, TRIES_FORGET_MS, newSalt, wrapKey, unwrapKey, checkTries }
