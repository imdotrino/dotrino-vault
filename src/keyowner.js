/**
 * keyowner.js — ESTE DIRECTORIO ES DE ESTA LLAVE, Y DE NINGUNA OTRA.
 *
 * Es lo único que hay que proteger (dueño, 2026-08-30): *«cada proceso tenga un directorio
 * alusivo a su llave para que nunca se mezclen»*.
 *
 * Y lo que hay detrás es que **no hay datos compartidos**. Cada bóveda tiene su directorio
 * entero —su identidad, sus perfiles, sus sobres— así que dos procesos nunca escriben el
 * mismo archivo. No hace falta fusionar nada ni repartir carpetas por dentro: hace falta
 * que nadie acabe, por accidente, arrancando con la identidad de otro.
 *
 * Cómo se accidenta uno: un `docker compose` duplicado, un `DOTRINO_VAULT_DIR` copiado de
 * otro servicio, un respaldo restaurado encima. Sin esto, el proceso arranca tan tranquilo
 * con una maestra que no es la suya y se identifica en el proxio como otro.
 *
 * La marca va EN CLARO a propósito: es una pubkey, no un secreto, y tiene que poder
 * leerse antes de abrir nada.
 */
import fs from 'node:fs'
import path from 'node:path'
import { pubkeyId } from '@dotrino/identity/capabilities'

export const OWNER_FILE = 'key.json'

/**
 * EL NOMBRE DE LA CARPETA SALE DE LA LLAVE.
 *
 * Una llave, una carpeta (dueño, 2026-08-30): un proceso con varios perfiles tiene varias
 * llaves maestras y, por tanto, varias carpetas. Con el nombre derivado de la llave eso
 * deja de ser algo que se comprueba y pasa a ser imposible por construcción — dos llaves
 * no pueden caer en la misma carpeta porque no se llaman igual.
 *
 * Empieza por la huella que se le enseña a una persona (`AB12-CD34`, la misma que sale en
 * `members` y en `profile ls`), para poder mirar el disco y reconocer de quién es cada
 * una; y sigue con 16 hex más, porque para *garantizar* que no chocan hacen falta más bits
 * de los que caben en algo que se lee en voz alta. Quitándole los guiones, el nombre
 * EMPIEZA por el mismo id que la bóveda imprime al arrancar (`listo · id 0571465f61a2fac8`),
 * así que se puede casar el log con la carpeta de un vistazo.
 *
 * Ojo con la palabra «maestra»: cuando esta bóveda se une a la cuenta de otra (`join`), su
 * llave sigue siendo la misma pero pasa a ser MIEMBRO del acta ajena, no su master. Lo que
 * nombra la carpeta es la llave que esta bóveda tiene para ese perfil, que no cambia
 * nunca; lo que cambia es su papel.
 */
export async function keyDirName (pub) {
  const h = await pubkeyId(pub)                 // SHA-256 del JWK canónico, 64 hex
  const label = h.slice(0, 8).toUpperCase()
  return `${label.slice(0, 4)}-${label.slice(4, 8)}-${h.slice(8, 24)}`
}

/** De quién es este directorio, o `null` si todavía no lo dice. */
export function keyOwnerOf (dir) {
  try { return JSON.parse(fs.readFileSync(path.join(dir, OWNER_FILE), 'utf8'))?.pub || null } catch (_) { return null }
}

/**
 * Comprueba que este directorio es de esta llave, o lo marca si está por estrenar.
 * Lanza con `code: 'key-mismatch'` si es de otra — sin tocar nada.
 */
export function assertKeyOwnsDir (dir, pub) {
  if (!pub) return null            // sin llave todavía: no hay nada que comparar
  const previo = keyOwnerOf(dir)

  if (previo && previo !== pub) {
    const e = new Error(
      'this data directory belongs to a DIFFERENT identity. Two vaults must never share one: ' +
      'each process needs its own directory, or one ends up running with the other\'s master key. ' +
      'Point this one at its own DOTRINO_VAULT_DIR. Nothing was modified.'
    )
    e.code = 'key-mismatch'
    throw e
  }

  if (!previo) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
      fs.writeFileSync(path.join(dir, OWNER_FILE), JSON.stringify({ pub, at: Date.now() }, null, 2) + '\n', { mode: 0o600 })
    } catch (_) { /* si no se puede marcar, no se bloquea el arranque */ }
  }
  return pub
}

export default { assertKeyOwnsDir, keyOwnerOf, keyDirName, OWNER_FILE }
