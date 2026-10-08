/**
 * AJUSTES DE ESTA BÓVEDA: lo que el dueño elige distinto del comportamiento por defecto.
 *
 * Hoy es uno: `updateApproval`. Por defecto la bóveda se actualiza sola (lo que baja se
 * verifica contra la atestación del release, se pida permiso o no); con `updateApproval:
 * true` antes le pide permiso a los aparatos con `approve` (dueño, 2026-10-08).
 *
 * Va por el canal local (`ipc.js`): lo escribe la CLI (`dotrino-vault update --approval
 * on|off`) y lo lee el daemon cada vez que mira si hay versión nueva, sin señal ni reinicio.
 *
 * UN ARCHIVO QUE EXISTE Y NO SE PUEDE LEER NO ES «EL VALOR POR DEFECTO»: el por defecto es
 * actualizarse sin preguntar, así que tragarse el fallo sería saltarse la aprobación que el
 * dueño pidió justo cuando algo se rompió. Se lanza.
 */
import fs from 'node:fs'
import path from 'node:path'
import { ipcRead, ipcWrite } from './ipc.js'

export const SETTINGS_FILE = 'settings.json'

const fail = (code, message) => Object.assign(new Error(message), { code })

/** @returns {{ updateApproval: boolean }} */
export function readSettings (dir) {
  const file = path.join(dir, SETTINGS_FILE)
  if (!fs.existsSync(file)) return { updateApproval: false }
  const raw = ipcRead(file, null)
  if (!raw || typeof raw !== 'object' || typeof raw.updateApproval !== 'boolean') {
    throw fail('settings-unreadable', `${SETTINGS_FILE} exists but cannot be read`)
  }
  return { updateApproval: raw.updateApproval }
}

export function writeSettings (dir, { updateApproval }) {
  if (typeof updateApproval !== 'boolean') throw fail('bad-setting', 'updateApproval must be true or false')
  ipcWrite(path.join(dir, SETTINGS_FILE), { v: 1, updateApproval })
}
