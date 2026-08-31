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

export const OWNER_FILE = 'key.json'

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

export default { assertKeyOwnsDir, keyOwnerOf, OWNER_FILE }
