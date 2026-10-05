/**
 * LLAVES DE HARDWARE (YubiKey y compañía) como PUERTA del perfil — `docs/llaves-de-hardware.md`
 * nivel 2. Esto vive del lado de la CLI y la TUI, **nunca del daemon**: la llave pide un toque
 * (y a veces un PIN) a la persona que está delante, y esa persona está en la terminal.
 *
 * Lo único que sale de aquí hacia el daemon son los 32 (o 20) bytes que devuelve la llave, por
 * el mismo camino que la contraseña. El daemon los convierte en la llave que abre la puerta.
 *
 * DOS SABORES, porque la llave tiene dos funciones que sirven y se comportan distinto:
 *
 *   · `fido2`    — extensión `hmac-secret`. **Siempre pide toque**: la llave contesta
 *                  `FIDO_ERR_UP_REQUIRED` si no lo hay (comprobado con una YubiKey 5.7.4).
 *   · `chalresp` — reto-respuesta HMAC-SHA1 de la ranura OTP 2, programada SIN toque. Abre con
 *                  la llave enchufada y nada más. Es la que pidió el dueño para no tener que
 *                  tocar (2026-10-05). El precio se dice: enchufada, cualquier programa de esta
 *                  máquina puede pedirle la respuesta.
 *
 * SIN MÓDULOS NATIVOS. Se llama a los comandos de libfido2 (`fido2-token`, `fido2-cred`,
 * `fido2-assert`) y de yubikey-personalization (`ykinfo`, `ykchalresp`, `ykpersonalize`), igual
 * que el proveedor de KEK `command` llama a un KMS: el binario único no puede llevar un `.node`.
 * Dónde buscarlos: `DOTRINO_HWKEY_BIN` (carpeta) y si no, el PATH.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'

/** El «relying party» de las credenciales FIDO2 de la bóveda. No es un dominio: nadie lo resuelve. */
export const RP_ID = 'dotrino-vault'

const coded = (msg, code, extra = {}) => Object.assign(new Error(msg), { code, ...extra })

/** Dónde está un comando, o `null`. */
export function findTool (name) {
  const dirs = [process.env.DOTRINO_HWKEY_BIN, ...String(process.env.PATH || '').split(path.delimiter)].filter(Boolean)
  for (const d of dirs) {
    for (const n of process.platform === 'win32' ? [name + '.exe', name] : [name]) {
      const f = path.join(d, n)
      try { fs.accessSync(f, fs.constants.X_OK); return f } catch (_) {}
    }
  }
  return null
}

function tool (name, pkg) {
  const f = findTool(name)
  if (!f) throw coded(`${name} not found: install ${pkg} (or point DOTRINO_HWKEY_BIN at its folder)`, 'HWKEY_TOOLS_MISSING', { tool: name, pkg })
  return f
}

/**
 * Corre un comando y devuelve stdout. La entrada va por ARCHIVO (`-i`), no por stdin: así la
 * terminal queda libre para que la herramienta pida el PIN si la llave tiene uno puesto.
 */
function run (file, args, { timeoutMs = 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(file, args, { stdio: ['inherit', 'pipe', 'pipe'] })
    let out = ''; let err = ''
    p.stdout.on('data', (d) => { out += d })
    p.stderr.on('data', (d) => { err += d })
    const t = setTimeout(() => { try { p.kill() } catch (_) {} }, timeoutMs)
    p.on('error', (e) => { clearTimeout(t); reject(e) })
    p.on('close', (code) => {
      clearTimeout(t)
      if (code === 0) return resolve(out)
      reject(classify(err.trim() || `${path.basename(file)} exited with ${code}`))
    })
  })
}

/** Los fallos de la llave con nombre: cada uno se arregla de una forma distinta. */
function classify (msg) {
  if (/OPERATION_DENIED|ACTION_TIMEOUT|USER_ACTION_TIMEOUT/.test(msg)) return coded('the key was not touched in time', 'HWKEY_NOT_TOUCHED')
  if (/NO_CREDENTIALS|INVALID_CREDENTIAL/.test(msg)) return coded('this key does not hold that credential', 'HWKEY_WRONG_KEY')
  if (/PIN_INVALID|PIN_AUTH_INVALID/.test(msg)) return coded('wrong PIN', 'HWKEY_WRONG_PIN')
  if (/PIN_BLOCKED/.test(msg)) return coded('the key PIN is blocked', 'HWKEY_PIN_BLOCKED')
  if (/no yubikey present|No such device|Device not found/i.test(msg)) return coded('no key plugged in', 'HWKEY_NO_DEVICE')
  return coded(msg, 'HWKEY_FAILED')
}

/** Escribe la entrada en un archivo 0600 de una carpeta propia, y la borra al terminar. */
async function withInput (lines, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-hwkey-'))
  const f = path.join(dir, 'in')
  try {
    fs.writeFileSync(f, lines.join('\n') + '\n', { mode: 0o600 })
    return await fn(f)
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {}
  }
}

const b64 = (b) => Buffer.from(b).toString('base64')
const randomB64 = (n = 32) => b64(crypto.randomBytes(n))

// ----------------------------------------------------------------- FIDO2 (con toque)

/** Las llaves FIDO2 enchufadas: `[{ path, name }]`. */
export async function fido2Devices () {
  const out = await run(tool('fido2-token', 'fido2-tools (libfido2)'), ['-L'])
  return out.split('\n').map((l) => /^(\S+?):\s*(.*)$/.exec(l.trim())).filter(Boolean)
    .map((m) => ({ path: m[1], name: (/\(([^)]*)\)\s*$/.exec(m[2]) || [])[1] || m[2] }))
}

async function oneFido2Device () {
  const devs = await fido2Devices()
  if (!devs.length) throw coded('no FIDO2 key plugged in', 'HWKEY_NO_DEVICE')
  return devs
}

/**
 * Crea la credencial de la puerta (un toque). No es residente: no ocupa sitio en la llave y
 * su id lo guarda la bóveda. Devuelve `{ credId, device }`.
 */
export async function fido2MakeCredential ({ label = 'dotrino-vault' } = {}) {
  const [dev] = await oneFido2Device()
  const out = await withInput([randomB64(), RP_ID, String(label).replace(/[\n\0]/g, ' ').slice(0, 60) || 'dotrino-vault', randomB64()],
    (f) => run(tool('fido2-cred', 'fido2-tools (libfido2)'), ['-M', '-h', '-i', f, dev.path]))
  const credId = out.split('\n')[4]?.trim()
  if (!credId) throw coded('fido2-cred gave no credential id', 'HWKEY_FAILED')
  return { credId, device: dev.name }
}

/** ¿Tiene esta llave la credencial? Sin toque (`up=false`): sirve para elegir puerta sin molestar. */
async function fido2Holds (devPath, credId) {
  try {
    await withInput([randomB64(), RP_ID, credId],
      (f) => run(tool('fido2-assert', 'fido2-tools (libfido2)'), ['-G', '-t', 'up=false', '-i', f, devPath], { timeoutMs: 10_000 }))
    return true
  } catch (e) {
    // Algunas llaves contestan «hace falta toque» en vez de «no la tengo» cuando SÍ la tienen.
    return e.code !== 'HWKEY_WRONG_KEY'
  }
}

/**
 * El secreto de la puerta (un toque): `HMAC(secreto-de-la-credencial, hsalt)`, 32 bytes.
 * Prueba las llaves enchufadas hasta encontrar la que guarda `credId`.
 */
export async function fido2Secret ({ credId, hsalt }) {
  const devs = await oneFido2Device()
  for (const d of devs) {
    if (devs.length > 1 && !(await fido2Holds(d.path, credId))) continue
    const out = await withInput([randomB64(), RP_ID, credId, hsalt],
      (f) => run(tool('fido2-assert', 'fido2-tools (libfido2)'), ['-G', '-h', '-i', f, d.path]))
    const lines = out.split('\n').map((l) => l.trim()).filter(Boolean)
    const secret = Buffer.from(lines[lines.length - 1] || '', 'base64')
    if (secret.length !== 32) throw coded('the key returned no hmac-secret', 'HWKEY_FAILED')
    return new Uint8Array(secret)
  }
  throw coded('none of the plugged keys holds this credential', 'HWKEY_WRONG_KEY')
}

/** De estas credenciales, ¿cuáles tiene alguna llave enchufada? Sin toque. */
export async function fido2Present (credIds) {
  let devs = []
  try { devs = await fido2Devices() } catch (e) { if (e.code === 'HWKEY_TOOLS_MISSING') throw e; return [] }
  const hits = []
  for (const id of credIds) {
    for (const d of devs) { if (await fido2Holds(d.path, id)) { hits.push(id); break } }
  }
  return hits
}

// ------------------------------------------------- reto-respuesta, ranura OTP 2 (sin toque)

const SLOT = '2'

/** El número de serie de la YubiKey enchufada (por la interfaz OTP), o `null` si no hay. */
export async function ykSerial () {
  try {
    const out = await run(tool('ykinfo', 'yubikey-personalization'), ['-s', '-q'], { timeoutMs: 10_000 })
    return out.trim() || null
  } catch (e) {
    if (e.code === 'HWKEY_TOOLS_MISSING') throw e
    return null
  }
}

/** ¿Está ocupada la ranura 2? Programarla encima borraría lo que tenga. */
export async function ykSlot2Busy () {
  const out = await run(tool('ykinfo', 'yubikey-personalization'), ['-a'], { timeoutMs: 10_000 })
  return /slot2_status:\s*1/.test(out)
}

/**
 * Programa la ranura 2 con reto-respuesta HMAC-SHA1 **sin toque** y un secreto al azar que no se
 * guarda en ningún sitio: queda solo dentro de la llave. Se niega si la ranura está ocupada,
 * salvo `overwrite` — sobrescribirla es borrar lo que hubiera ahí, y eso lo decide la persona.
 */
export async function ykProgramSlot2 ({ overwrite = false } = {}) {
  if (!overwrite && await ykSlot2Busy()) {
    throw coded('slot 2 of this key is already programmed: overwriting it erases what is there', 'HWKEY_SLOT_BUSY')
  }
  const secret = crypto.randomBytes(20)
  try {
    await run(tool('ykpersonalize', 'yubikey-personalization'),
      ['-' + SLOT, '-y', '-ochal-resp', '-ochal-hmac', '-ohmac-lt64', '-oserial-api-visible', '-a', secret.toString('hex')])
  } finally { secret.fill(0) }
  return { serial: await ykSerial() }
}

/** La respuesta de la ranura 2 a `challenge` (hex), 20 bytes. Sin toque si se programó así. */
export async function ykChallenge ({ challenge }) {
  const out = await run(tool('ykchalresp', 'yubikey-personalization'), ['-' + SLOT, '-x', challenge], { timeoutMs: 20_000 })
  const resp = Buffer.from(out.trim(), 'hex')
  if (resp.length !== 20) throw coded('the key gave no response (is slot 2 set to challenge-response?)', 'HWKEY_FAILED')
  return new Uint8Array(resp)
}

/**
 * Para ABRIR: le pide a la llave enchufada los bytes de una de las puertas del perfil. Primero
 * la que NO pide toque (reto-respuesta), después la de toque (FIDO2), avisando con `onTouch`
 * justo antes de que la llave parpadee. `null` si ninguna llave de este perfil está enchufada.
 * Devuelve `{ door, secret, withPassword }`.
 */
export async function secretForDoors (doors = [], { onTouch = () => {} } = {}) {
  let last = null
  const cr = doors.filter((d) => d.kind === 'chalresp')
  if (cr.length) {
    const serial = await ykSerial()
    for (const d of cr.filter((x) => serial && (!x.serial || x.serial === serial))) {
      try { return { door: d.id, secret: await ykChallenge({ challenge: d.challenge }), withPassword: !!d.withPassword } } catch (e) { last = e }
    }
  }
  const f = doors.filter((d) => d.kind === 'fido2')
  if (f.length) {
    const present = await fido2Present(f.map((d) => d.credId))
    const d = f.find((x) => present.includes(x.credId))
    if (d) {
      onTouch(d)
      return { door: d.id, secret: await fido2Secret({ credId: d.credId, hsalt: d.hsalt }), withPassword: !!d.withPassword }
    }
  }
  if (last) throw last
  return null
}

/** Las puertas de hardware de un perfil (de su entrada en la lista). */
export const hardwareDoors = (p) => (p?.doors || []).filter((d) => d.kind === 'fido2' || d.kind === 'chalresp')

/** Un reto nuevo para una puerta: 32 bytes en hex (cabe en el modo `hmac-lt64`). */
export const newChallenge = () => crypto.randomBytes(32).toString('hex')
/** Un salt nuevo para `hmac-secret`: 32 bytes en base64. */
export const newHsalt = () => randomB64(32)

