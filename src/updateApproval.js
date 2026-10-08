/**
 * PEDIR PERMISO PARA ACTUALIZARSE, EN TODOS LOS PERFILES A LA VEZ.
 *
 * El ajuste es de la BÓVEDA, no de un perfil (dueño, 2026-10-08): «si se activa funciona si
 * cualquier perfil tiene aprobador, afecta a todos los perfiles y se envía notificación a
 * todos los perfiles». El binario es uno solo, así que quien aprueba en cualquiera de las
 * cuentas que viven aquí decide por la máquina.
 *
 * Sin estado y sin red: recibe los perfiles en marcha y lo que cada uno sabe hacer, para
 * poder probarse sin daemon (`test/actualizar-todos-los-perfiles.test.mjs`).
 */
import fs from 'node:fs'
import path from 'node:path'
import { ipcRead, ipcWrite } from './ipc.js'

/**
 * Quién aprueba, en todos los perfiles. SI UNO NO SE PUEDE LEER, SE LANZA: una lista a medias
 * sería decidir con menos aprobadores de los que hay, que es el repliegue que abre la puerta
 * justo cuando algo se rompió.
 * @param {{ id: string, name?: string, vault: { approvers: () => Promise<any[]> } }[]} profiles
 * @returns {Promise<{ profile: string, profileId: string, id: string, label: string, pub: string, notifiedAt: number|null }[]>}
 */
export async function approversOfAll (profiles) {
  const out = []
  for (const p of profiles) {
    let list
    try { list = await p.vault.approvers() } catch (e) {
      throw Object.assign(new Error(`profile ${p.name || p.id}: ${e?.message || e}`), { code: 'approvers-unreadable' })
    }
    for (const a of list) out.push({ ...a, profile: p.name || p.id, profileId: p.id })
  }
  return out
}

/**
 * Pide en cada perfil y espera: EL PRIMER «SÍ» BASTA; es «no» cuando todos dijeron que no o
 * vencieron. Al resolverse se RETIRAN los pedidos que quedaron vivos en los demás, para que
 * no se queden un día en la lista de quien aprueba pidiendo algo que ya se decidió.
 * @param {{ answer: Promise<boolean>, withdraw: () => void }[]} asks
 * @returns {Promise<boolean>}
 */
export function firstYes (asks) {
  if (!asks.length) return Promise.resolve(false)
  return new Promise((resolve) => {
    let left = asks.length
    let done = false
    const finish = (ok, winner) => {
      if (done) return
      done = true
      for (const a of asks) { if (a !== winner) { try { a.withdraw() } catch (_) { /* retirar es limpieza: no cambia la respuesta */ } } }
      resolve(ok)
    }
    for (const a of asks) {
      Promise.resolve(a.answer).then((ok) => {
        if (ok === true) return finish(true, a)
        if (--left === 0) finish(false, null)
      }, () => { if (--left === 0) finish(false, null) })
    }
  })
}

/**
 * EL PEDIDO SE HACE UNA VEZ POR VERSIÓN (dueño, 2026-10-08): «dura un día, pero se hace una
 * sola vez; no se reintenta al siguiente día; se asume negado si no se hizo en 24 horas; se
 * dispara nuevamente en la siguiente actualización».
 *
 * Así que se apunta QUÉ versión se preguntó, AL PEDIR, y sobrevive a un reinicio: una bóveda
 * que se reinicia con el pedido a medias no vuelve a timbrar por lo mismo. Va por el canal
 * local (cifrado en reposo), junto al resto del estado del daemon.
 *
 * UN ARCHIVO QUE EXISTE Y NO SE PUEDE LEER NO ES «NUNCA SE PREGUNTÓ» —eso volvería a pedir— ni
 * tampoco «ya se aprobó»: se lanza, y quien llama no actualiza y lo dice.
 */

export const ASKED_FILE = 'update-asked.json'
const RESULTS = ['pending', 'denied', 'expired']
const fail = (code, message) => Object.assign(new Error(message), { code })

/** @returns {{ version: string, askedAt: number, result: 'pending'|'denied'|'expired' } | null} */
export function readAsked (dir) {
  const file = path.join(dir, ASKED_FILE)
  if (!fs.existsSync(file)) return null
  const d = ipcRead(file, null)
  if (!d || typeof d.version !== 'string' || !d.version || typeof d.askedAt !== 'number' || !RESULTS.includes(d.result)) {
    throw fail('asked-unreadable', `${ASKED_FILE} exists but cannot be read`)
  }
  return { version: d.version, askedAt: d.askedAt, result: d.result }
}

export function writeAsked (dir, { version, askedAt, result }) {
  if (typeof version !== 'string' || !version || typeof askedAt !== 'number' || !RESULTS.includes(result)) throw fail('bad-asked', 'writeAsked: version, askedAt and a known result are required')
  ipcWrite(path.join(dir, ASKED_FILE), { v: 1, version, askedAt, result })
}

/** Ya se instaló (o ya no hace falta preguntar): se olvida lo preguntado. */
export function clearAsked (dir) { fs.rmSync(path.join(dir, ASKED_FILE), { force: true }) }

/**
 * ¿Hay que pedir permiso por `version`? Solo si nunca se preguntó, o si es MÁS NUEVA que la
 * que se preguntó. La misma (o una anterior) ya tuvo su pedido: no se repite.
 * @param {(a: string, b: string) => boolean} isNewer  `isNewer(a, b)`: a es más nueva que b
 */
export function shouldAsk (asked, version, isNewer) {
  return !asked || isNewer(version, asked.version)
}

/** Un «no» que llega cuando el pedido ya cumplió su día es un vencimiento; antes, alguien lo denegó. */
export function resultOfNo (askedAt, ttlMs, now = Date.now()) {
  return now - askedAt >= ttlMs - 60_000 ? 'expired' : 'denied'
}

/**
 * «NECESITO PERMISOS DE ADMINISTRADOR» SE DICE UNA VEZ POR VERSIÓN. Una bóveda instalada como
 * paquete del sistema no puede cambiarse el binario: avisa a quien aprueba y espera a que
 * alguien la instale a mano. Sin apuntarlo, lo repetiría en cada pasada y en cada reinicio.
 *
 * Mismas reglas que lo preguntado: sobrevive al reinicio, y un archivo que existe y no se
 * puede leer se LANZA (ni «ya se dijo» ni «dilo otra vez»).
 */
export const ROOT_TOLD_FILE = 'update-root-told.json'

/** @returns {{ version: string, at: number } | null} */
export function readRootTold (dir) {
  const file = path.join(dir, ROOT_TOLD_FILE)
  if (!fs.existsSync(file)) return null
  const d = ipcRead(file, null)
  if (!d || typeof d.version !== 'string' || !d.version || typeof d.at !== 'number') throw fail('root-told-unreadable', `${ROOT_TOLD_FILE} exists but cannot be read`)
  return { version: d.version, at: d.at }
}

export function writeRootTold (dir, { version, at }) {
  if (typeof version !== 'string' || !version || typeof at !== 'number') throw fail('bad-root-told', 'writeRootTold: version and at are required')
  ipcWrite(path.join(dir, ROOT_TOLD_FILE), { v: 1, version, at })
}

/** ¿Hay que avisar por `version`? Solo si nunca se avisó, o si es MÁS NUEVA que la avisada. */
export function shouldTellRoot (told, version, isNewer) {
  return !told || isNewer(version, told.version)
}
