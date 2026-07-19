/**
 * vaultControl.js — API programática de control del daemon del vault.
 *
 * Es la MISMA vía que usa la CLI (`ctl.js`): NO abre la identidad ni el proxy, no
 * toca la maestra. Le da órdenes al daemon (único custodio) escribiendo peticiones
 * en el dir de datos (0600) y disparando señales:
 *
 *   SIGUSR1 → inicia un emparejamiento (vuelca pair.json)
 *   SIGUSR2 → consume approve/reject/revoke/secret/profile/dump-request y vuelca
 *             devices.json / secrets-list.json / profiles-list.json
 *
 * La usa la TUI (`src/tui/`). Se mantiene como capa fina y sin estado para que la
 * TUI y la CLI no dupliquen el protocolo: si el daemon cambia el contrato de
 * archivos/señales, se toca aquí y en `daemon.js`, en ningún otro lado.
 *
 * MULTI-PERFIL: cada función recibe opcionalmente `profile` (id o nombre). Sin él,
 * el daemon apunta al perfil ACTIVO.
 */
import fs from 'node:fs'
import path from 'node:path'
import { pubkeyId } from '@dotrino/identity/capabilities'
import { dataDir, readJson } from './paths.js'

const dir = dataDir()

// Nombres de archivos del contrato con el daemon (ver daemon.js). Único lugar.
const F = {
  state: 'state.json',
  pair: 'pair.json',
  pending: 'pending-enroll.json',
  devices: 'devices.json',
  profilesList: 'profiles-list.json',
  secretsList: 'secrets-list.json',
  // peticiones (las escribe el control; el daemon las consume y borra)
  pairReq: 'pair-request.json',
  approveReq: 'approve-request.json',
  rejectReq: 'reject-request.json',
  revokeReq: 'revoke-request.json',
  secretReq: 'secret-request.json',
  profileReq: 'profile-request.json',
  dumpReq: 'dump-request.json'
}

const p = (name) => path.join(dir, name)
const read = (name, fb = null) => readJson(p(name), fb)
const rm = (name) => { try { fs.rmSync(p(name), { force: true }) } catch (_) {} }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function vaultDir () { return dir }

export function readState () { return read(F.state, null) }

/** ¿El pid está vivo? (kill 0 no envía señal, solo comprueba permiso/existencia). */
export function pidAlive (pid) { try { return !!pid && (process.kill(pid, 0) || true) } catch (_) { return false } }

/** ¿Hay un daemon corriendo? (state.json presente + pid vivo). */
export function daemonAlive () { const s = readState(); return !!(s && pidAlive(s.pid)) }

/** deviceId legible (8 hex agrupados AB12-CD34) a partir del pubkey `sub`. */
export async function deviceIdOf (sub) {
  if (!sub) return '????-????'
  const id = (await pubkeyId(sub)).slice(0, 8).toUpperCase()
  return id.slice(0, 4) + '-' + id.slice(4, 8)
}

class DaemonDownError extends Error {
  constructor () { super('el daemon del vault no está corriendo'); this.code = 'DAEMON_DOWN' }
}

/**
 * Exige el daemon vivo ANTES de escribir cualquier petición. Es clave para las
 * peticiones que llevan secretos (contraseña de perfil, valor de secreto): si el
 * daemon está caído no habría quien las consuma ni borre, y quedarían en claro en
 * disco. Mismo criterio que `requireDaemon()` de la CLI.
 */
function requireAlive () {
  const s = readState()
  if (!s || !pidAlive(s.pid)) throw new DaemonDownError()
}

function writeReq (name, obj, profile) {
  const body = { ...obj, at: Date.now() }
  if (profile) body.profile = profile
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.writeFileSync(p(name), JSON.stringify(body), { mode: 0o600 })
  // `mode` de writeFileSync solo aplica al CREAR: re-chmod por si el archivo ya
  // existía con permisos más laxos (defensa en profundidad; el dir ya es 0700).
  try { fs.chmodSync(p(name), 0o600) } catch (_) {}
}

function signal (sig) {
  const s = readState()
  if (!s || !pidAlive(s.pid)) throw new DaemonDownError()
  process.kill(s.pid, sig)
}

/**
 * Dispara la señal y, si falla (daemon murió entre el chequeo y ahora), BORRA las
 * peticiones que quedaron escritas para no dejar secretos en disco.
 */
function signalOrCleanup (sig, reqFiles) {
  try { signal(sig) } catch (e) { for (const f of reqFiles) rm(f); throw e }
}

/** Espera a que reaparezca un archivo de respuesta (con `.at`) tras borrarlo. */
async function waitFor (name, { tries = 60, interval = 100 } = {}) {
  for (let i = 0; i < tries; i++) {
    await sleep(interval)
    const d = read(name, null)
    if (d && d.at) return d
  }
  return null
}

// ---------------------------------------------------------------------------
// Perfiles / bóvedas + candado
// ---------------------------------------------------------------------------

/**
 * Manda una orden de perfil y espera el volcado. `profile` (id/nombre) es tanto el
 * OPERANDO (para use/rm/rename) como el DESTINO (para unlock/lock/password). La
 * contraseña viaja en un archivo 0600 que el daemon borra al leerlo.
 */
async function profileOp (op, { profile, name, password } = {}) {
  requireAlive() // nunca escribir la contraseña si no hay quien la consuma
  rm(F.profilesList)
  const extra = {}
  if (name != null) extra.name = name
  if (password != null) extra.password = password
  writeReq(F.profileReq, { op, ...extra }, profile)
  signalOrCleanup('SIGUSR2', [F.profileReq])
  const d = await waitFor(F.profilesList)
  if (!d) throw new Error('el daemon no respondió')
  if (d.error) throw new Error(d.error)
  return d // { profiles:[{id,name,protected,locked,current,fingerprint,iss,createdAt}], current, done? }
}

export const listProfiles = () => profileOp('list')
export const addProfile = (name) => profileOp('add', { name })
export const useProfile = (profile) => profileOp('use', { profile })
export const renameProfile = (profile, name) => profileOp('rename', { profile, name })
export const removeProfile = (profile) => profileOp('rm', { profile })
export const unlockProfile = (profile, password) => profileOp('unlock', { profile, password })
export const lockProfile = (profile) => profileOp('lock', { profile })
export const setProfilePassword = (profile, password) => profileOp('password-set', { profile, password })
export const removeProfilePassword = (profile) => profileOp('password-rm', { profile })

// ---------------------------------------------------------------------------
// Volcado de dispositivos + secretos de un perfil
// ---------------------------------------------------------------------------

/**
 * Fuerza el volcado del daemon (devices.json + secrets-list.json + profiles-list.json)
 * para `profile` (o el activo) y devuelve las tres cosas ya parseadas.
 */
export async function snapshot (profile) {
  requireAlive()
  rm(F.devices); rm(F.secretsList); rm(F.profilesList)
  writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.dumpReq])
  const [devices, secrets, profiles] = await Promise.all([
    waitFor(F.devices), waitFor(F.secretsList), waitFor(F.profilesList)
  ])
  return { devices, secrets, profiles }
}

/**
 * Dispositivos enrolados/revocados del perfil, con su deviceId ya calculado.
 * `issued` viene de identity.listDelegations(); el deviceId se deriva del `sub`.
 */
export async function listDevices (profile) {
  const { devices } = await snapshot(profile)
  if (!devices) throw new Error('el daemon no respondió')
  const issued = devices.issued || devices.active || devices.delegations || []
  const withIds = await Promise.all(issued.map(async (d) => ({
    ...d, deviceId: d.sub ? await deviceIdOf(d.sub) : '????-????'
  })))
  return { issued: withIds, revoked: devices.revoked || [], profile: devices.profile || null }
}

/** Revoca un dispositivo por su `nonce` (le ordena autoborrarse) y revuelca. */
export async function revokeDevice (nonce, profile) {
  requireAlive()
  writeReq(F.revokeReq, { nonce }, profile)
  signalOrCleanup('SIGUSR2', [F.revokeReq])
  await sleep(300)
  return listDevices(profile)
}

// ---------------------------------------------------------------------------
// Secretos: scopes (namespaces) y variables (claves)
// ---------------------------------------------------------------------------

/** Scopes→[claves] del perfil (NUNCA los valores; el daemon no los expone). */
export async function listSecrets (profile) {
  const { secrets } = await snapshot(profile)
  if (!secrets) throw new Error('el daemon no respondió')
  return secrets.ns || {}
}

/** Guarda/actualiza una variable. ns: [a-z0-9-]{1,32}. clave: [A-Z0-9_]{1,64}. */
export async function setSecret (ns, key, value, profile) {
  requireAlive() // el VALOR es secreto: no escribirlo si el daemon está caído
  rm(F.secretsList)
  writeReq(F.secretReq, { op: 'set', ns, key, value }, profile)
  writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.secretReq, F.dumpReq])
  const d = await waitFor(F.secretsList)
  if (!d) throw new Error('el daemon no respondió')
  if (!(d.ns?.[ns] || []).includes(key)) throw new Error('el daemon no aplicó el cambio (revisa los logs del servicio)')
  return d.ns
}

/** Borra una variable. Si era la última del scope, el scope desaparece. */
export async function deleteSecret (ns, key, profile) {
  requireAlive()
  rm(F.secretsList)
  writeReq(F.secretReq, { op: 'rm', ns, key }, profile)
  writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.secretReq, F.dumpReq])
  const d = await waitFor(F.secretsList)
  if (!d) throw new Error('el daemon no respondió')
  if ((d.ns?.[ns] || []).includes(key)) throw new Error('el daemon no borró la variable (revisa los logs del servicio)')
  return d.ns
}

/** Borra un scope entero (todas sus variables, una por una). */
export async function deleteScope (ns, profile) {
  const all = await listSecrets(profile)
  const keys = all[ns] || []
  let ns2 = all
  for (const k of keys) ns2 = await deleteSecret(ns, k, profile)
  return ns2
}

// ---------------------------------------------------------------------------
// Emparejamiento de dispositivos (pares)
// ---------------------------------------------------------------------------

const PROFILE_URL = 'https://profile.dotrino.com/#vault='

/** Codifica el QR crudo como URL de profile.dotrino.com (base64url del payload). */
export function pairUrl (qr) {
  const payload = JSON.stringify(qr)
  const b64 = Buffer.from(payload, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return { url: PROFILE_URL + b64, payload }
}

/**
 * Inicia un emparejamiento. `service` (opcional) enrola un SERVICIO con acceso
 * SOLO a `vault:secrets:<service>` (no firma por ti ni lee tus datos).
 * Devuelve { qr, expiresAt, url, payload }.
 */
export async function startPairing ({ profile, service } = {}) {
  requireAlive()
  rm(F.pair); rm(F.pending)
  writeReq(F.pairReq, service ? { service } : {}, profile)
  signalOrCleanup('SIGUSR1', [F.pairReq])
  for (let i = 0; i < 50; i++) {
    await sleep(100)
    const pr = read(F.pair, null)
    if (pr?.expiresAt > Date.now()) {
      const { url, payload } = pairUrl(pr.qr)
      return { qr: pr.qr, expiresAt: pr.expiresAt, url, payload }
    }
  }
  throw new Error('el daemon no inició el emparejamiento')
}

/** Dispositivo pendiente de aprobar (el que se conectó con el QR), o null. */
export function pendingEnroll () {
  const pe = read(F.pending, null)
  return pe?.deviceId ? pe : null
}

/**
 * Aprueba el dispositivo pendiente escribiendo el CÓDIGO que MUESTRA el dispositivo
 * (el vault no lo conoce). Firma el cert y se lo manda. Devuelve la lista de
 * dispositivos ya actualizada.
 */
export async function approvePending (code, profile) {
  requireAlive()
  writeReq(F.approveReq, { code: String(code) }, profile)
  signalOrCleanup('SIGUSR2', [F.approveReq])
  await sleep(400)
  return listDevices(profile)
}

/** Rechaza el dispositivo pendiente. */
export async function rejectPending (deviceId, profile) {
  requireAlive()
  writeReq(F.rejectReq, { deviceId }, profile)
  signalOrCleanup('SIGUSR2', [F.rejectReq])
  await sleep(200)
}
