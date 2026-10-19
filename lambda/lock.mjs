/**
 * EL CANDADO DE LA BÓVEDA ALOJADA (`dotrino-accounts/docs/DISENO.md` §5).
 *
 * La maestra va sellada con la llave del perfil `K`, y `K` solo existe envuelta con lo que
 * sale de la contraseña que el cliente puso al comprar. Es el mismo sobre que la contraseña
 * del admin de escritorio (`src/adminDoor.js`), así que la consola lo abre con el «abrir a
 * distancia» de siempre; aquí es la ÚNICA puerta: no hay contraseña principal ni llave de
 * máquina que abra la maestra.
 *
 * `lock.json` vive en el directorio del perfil (se refleja en el almacén con lo demás) y va
 * además cifrado en reposo con el servicio de llaves: el sobre solo no da para probar
 * contraseñas sin pasar por KMS.
 *
 * `K` está en memoria desde que se abre (o nace) hasta que se cierra la sesión: `close()`.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { atRestFor } from '../lib/src/atrest.js'
import { SCRYPT, newSalt, wrapKey, unwrapKey, checkTries } from '../src/adminDoor.js'

export const LOCK_FILE = 'lock.json'
/** Lo mínimo, como en escritorio: la contraseña es la llave de la maestra. */
export const PASSWORD_MIN = 12

/**
 * @param {string} dir  el directorio del perfil
 */
export function openLock (dir) {
  const file = path.join(dir, LOCK_FILE)
  const atRest = () => atRestFor(dir)
  const read = () => fs.existsSync(file) ? JSON.parse(atRest().decrypt(fs.readFileSync(file, 'utf8'))) : null
  const write = (rec) => { fs.writeFileSync(file, atRest().encrypt(JSON.stringify(rec)), { mode: 0o600 }) }
  let key = null

  return {
    exists: () => fs.existsSync(file),
    /** Lo que el navegador necesita para derivar (`unlock.begin`). `null` si no hay candado. */
    params () { const rec = read(); return rec ? { salt: rec.salt, ...SCRYPT } : null },
    isLocked: () => !key,
    openKey: () => key,

    /**
     * NACE: una `K` nueva envuelta con la derivada que trajo el cliente. Solo si no había
     * candado: uno que ya existe no se pisa nunca (sería cambiar la contraseña sin la vieja).
     */
    create ({ salt, derived }) {
      if (fs.existsSync(file)) throw Object.assign(new Error('this vault already has a lock'), { code: 'lock-exists' })
      if (typeof salt !== 'string' || !salt) throw Object.assign(new Error('the lock needs the salt the key was derived with'), { code: 'no-salt' })
      const k = new Uint8Array(crypto.randomBytes(32))
      write({ v: 1, salt, wrapped: wrapKey(k, derived) })
      key = k
      return { ok: true }
    },

    /** ABRE con la derivada, con el mismo freno que escritorio (persistido en el candado). */
    open (derived) {
      const rec = read()
      if (!rec) throw Object.assign(new Error('this vault has no lock'), { code: 'NO_SECONDARY' })
      const { tries, reset } = checkTries(rec.tries)
      if (reset) { delete rec.tries; write(rec) }
      const k = unwrapKey(rec.wrapped, derived)
      if (!k) {
        rec.tries = { n: tries.n + 1, at: Date.now() }
        write(rec)
        throw Object.assign(new Error('wrong password'), { code: 'WRONG_PASSWORD', tries: rec.tries.n })
      }
      if (rec.tries) { delete rec.tries; write(rec) }
      key = k
      return { ok: true, locked: false }
    },

    close () { if (key) key.fill(0); key = null }
  }
}

export { newSalt, SCRYPT }
export default { openLock, LOCK_FILE, PASSWORD_MIN, newSalt, SCRYPT }
