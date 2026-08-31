/**
 * lock.js — UN SOLO PROCESO POR DIRECTORIO, también entre máquinas.
 *
 * Es la otra mitad de la invariante que pidió el dueño (la primera está en
 * `src/keyowner.js`): cada proceso con su directorio, y **uno solo** dentro de cada uno.
 *
 * El candado que había miraba un pid: si el proceso seguía vivo, no arrancábamos. Sirve
 * cuando las dos bóvedas son procesos del mismo sistema, y **no sirve para nada** en
 * cuanto dejan de serlo:
 *
 *   · **Contenedores.** Cada uno tiene su espacio de pids. El segundo pregunta por el pid
 *     del primero en el suyo, no lo encuentra y concluye que está muerto. Comprobado con
 *     Docker: dos contenedores sobre el mismo volumen arrancaban los dos, sanos, con la
 *     misma cuenta.
 *   · **Un disco de red (EFS, NFS).** Peor todavía: son dos máquinas distintas. El pid del
 *     otro host o no existe aquí, o existe y es un proceso que no tiene nada que ver.
 *
 * Y dos daemons sobre el mismo directorio no son dos bóvedas: son la misma corriendo dos
 * veces. Cargan la misma maestra, se identifican igual en el proxio y sellan actas las dos
 * como el mismo sellador — el caso que `acta-de-perfil.md` §2.4.1 llama «el master
 * mintiendo» y del que dice que no hay defensa.
 *
 * LA IDEA: un archivo que se crea con `O_EXCL` (crear-o-fallar, atómico también en NFS)
 * más un LATIDO. Quien lo tiene lo va tocando; quien llega lo mira:
 *
 *   · latido fresco  → hay alguien vivo, no arrancamos.
 *   · latido viejo   → se cortó la luz, se le quita el candado y se sigue.
 *
 * El plazo no es un reloj compartido —eso no existe entre máquinas— sino la EDAD del
 * archivo medida por quien mira. Un reloj desajustado alarga o acorta la espera, pero no
 * rompe la exclusión: la exclusión la da `O_EXCL`, el latido solo decide cuándo se
 * considera abandonado.
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

export const LOCK_FILE = 'vault.lock'
/** Cada cuánto se toca el archivo. */
export const HEARTBEAT_MS = 10_000
/** Sin latido durante esto, se da por abandonado. Holgado a propósito: una máquina con
 *  carga o un disco de red lento no pueden costar que otro le quite el candado a uno vivo. */
export const STALE_MS = 60_000

const quienSoy = () => ({ pid: process.pid, host: os.hostname(), desde: Date.now() })

/**
 * Toma el candado del directorio, o explica quién lo tiene y se rinde.
 * @returns {{release:()=>void}}
 */
export function takeLock (dir, { staleMs = STALE_MS, heartbeatMs = HEARTBEAT_MS } = {}) {
  const f = path.join(dir, LOCK_FILE)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })

  const intentar = () => {
    try {
      // 'wx' = O_CREAT|O_EXCL: o lo creo yo, o alguien lo tiene. Esa atomicidad es lo
      // único que aquí hace de exclusión.
      const fd = fs.openSync(f, 'wx', 0o600)
      fs.writeSync(fd, JSON.stringify(quienSoy()))
      fs.closeSync(fd)
      return true
    } catch (e) {
      if (e.code !== 'EEXIST') throw e
      return false
    }
  }

  if (!intentar()) {
    const edad = (() => {
      try { return Date.now() - fs.statSync(f).mtimeMs } catch (_) { return Infinity }
    })()
    let dueño = null
    try { dueño = JSON.parse(fs.readFileSync(f, 'utf8')) } catch (_) {}

    if (edad <= staleMs) {
      const e = new Error(
        `another vault is running on this data (host ${dueño?.host || '?'}, process ${dueño?.pid ?? '?'}, ` +
        `last heartbeat ${Math.round(edad / 1000)}s ago)`
      )
      e.code = 'vault-locked'
      e.owner = dueño
      throw e
    }
    // Abandonado: se quita y se vuelve a intentar UNA vez. Si en ese hueco entró otro,
    // pierde este — que es lo correcto: dos que ven el candado viejo a la vez, solo uno
    // gana el `O_EXCL`.
    try { fs.unlinkSync(f) } catch (_) {}
    if (!intentar()) {
      const e = new Error('another vault took this data first')
      e.code = 'vault-locked'
      throw e
    }
  }

  const latido = setInterval(() => {
    // `utimes` y no reescribir: tocar la fecha basta y no puede dejar el archivo a medias.
    try { fs.utimesSync(f, new Date(), new Date()) } catch (_) {}
  }, heartbeatMs)
  latido.unref?.()

  let suelto = false
  const release = () => {
    if (suelto) return
    suelto = true
    clearInterval(latido)
    // Solo se borra SI SIGUE SIENDO MÍO. Si otro me lo quitó por viejo, borrarlo aquí le
    // quitaría a él un candado que sí es suyo.
    try {
      const d = JSON.parse(fs.readFileSync(f, 'utf8'))
      if (d?.pid === process.pid && d?.host === os.hostname()) fs.unlinkSync(f)
    } catch (_) {}
  }
  return { release }
}

export default { takeLock, LOCK_FILE, STALE_MS, HEARTBEAT_MS }
