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
import { encodeInvite, inviteUrl } from '../lib/src/invite.js'

const dir = dataDir()

// Nombres de archivos del contrato con el daemon (ver daemon.js). Único lugar.
const F = {
  state: 'state.json',
  pair: 'pair.json',
  pending: 'pending-enroll.json',
  devices: 'devices.json',
  profilesList: 'profiles-list.json',
  secretsList: 'secrets-list.json',
  me: 'me.json',
  acta: 'acta.json',
  approve: 'approve.json',
  // peticiones (las escribe el control; el daemon las consume y borra)
  pairReq: 'pair-request.json',
  approveReq: 'approve-request.json',
  rejectReq: 'reject-request.json',
  revokeReq: 'revoke-request.json',
  labelReq: 'label-request.json',
  capsReq: 'caps-request.json',
  secretReq: 'secret-request.json',
  profileReq: 'profile-request.json',
  meReq: 'me-request.json',
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
 * Error con `code`: la CLI sigue imprimiendo el mensaje tal cual y la TUI, que es
 * bilingüe (`src/tui/i18n.js`), lo traduce por el código. Los errores que REENVÍA
 * el daemon no llevan código: son diagnósticos del servicio, no copy de interfaz.
 */
const coded = (message, code) => Object.assign(new Error(message), { code })

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

/** Contador de peticiones de ESTE proceso: junto al pid, identifica cada una. */
let reqSeq = 0

/**
 * Escribe una petición y devuelve su `id`.
 *
 * ESPERA A QUE EL DAEMON SE HAYA LLEVADO LA ANTERIOR. Cada tipo de petición es UN
 * archivo con nombre fijo, así que escribir la siguiente antes de que se consuma la
 * primera la BORRABA sin que nadie se enterara. Es exactamente lo que le pasaba al
 * candado: la TUI manda `unlock` y, pegado, el `list` para repintar; si el daemon
 * estaba ocupado, el `list` se comía el `unlock` —contraseña incluida— y la bóveda
 * seguía cerrada sin un solo error por ninguna parte. Se vuelve a preguntar la
 * contraseña, y otra vez lo mismo.
 */
async function writeReq (name, obj, profile) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  // Hasta 3 s por la anterior; pasado eso, se pisa (el daemon no la va a atender ya, y
  // dejar a quien pide esperando para siempre es peor).
  for (let i = 0; i < 30 && fs.existsSync(p(name)); i++) await sleep(100)
  const id = `${process.pid}-${++reqSeq}`
  const body = { ...obj, id, at: Date.now() }
  if (profile) body.profile = profile
  // ATÓMICO (escribir aparte y renombrar), y no por manía: el daemon vigila esta carpeta
  // con `fs.watch`, que avisa al CREAR el archivo — no al terminar de escribirlo. Escrito
  // en el sitio, el daemon podía leerlo a medias, y como una petición sin `id` no es de
  // nadie, se perdía: quien la había pedido esperaba seis segundos y leía «el daemon no
  // respondió», con el daemon sano. `rename` es atómico dentro del mismo sistema de
  // archivos, así que el vigilante o no ve nada, o ve la petición ENTERA.
  const tmp = p(name) + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 })
  fs.renameSync(tmp, p(name))
  // `mode` de writeFileSync solo aplica al CREAR: re-chmod por si el archivo ya
  // existía con permisos más laxos (defensa en profundidad; el dir ya es 0700).
  try { fs.chmodSync(p(name), 0o600) } catch (_) {}
  return id
}

/**
 * Campanita para que el daemon lea la petición YA.
 *
 * Es best-effort A PROPÓSITO: SIGUSR1/SIGUSR2 **no existen en Windows** y ahí
 * `process.kill` con ellas revienta — antes eso tumbaba la TUI entera (el CLI ya se había
 * arreglado; este camino, que es el que usa la TUI, no). El daemon vigila su directorio de
 * datos, así que la petición se atiende igual en cuanto el archivo está escrito; la señal
 * solo ahorra la latencia del vigilante.
 *
 * Lo que SÍ sigue siendo un error es que el daemon no esté: sin él no hay quien atienda.
 */
function signal (sig) {
  const s = readState()
  if (!s || !pidAlive(s.pid)) throw new DaemonDownError()
  try { process.kill(s.pid, sig) } catch (_) { /* Windows: no hay señales; lo verá el vigilante */ }
}

/**
 * Dispara la señal y, si falla (daemon murió entre el chequeo y ahora), BORRA las
 * peticiones que quedaron escritas para no dejar secretos en disco.
 */
function signalOrCleanup (sig, reqFiles) {
  try { signal(sig) } catch (e) { for (const f of reqFiles) rm(f); throw e }
}

/**
 * EL CANDADO, del lado de quien pregunta. El daemon contesta los volcados de un perfil
 * bloqueado con `locked: true` y sin contenido; aquí eso se convierte en un error con
 * código para que la CLI y la TUI digan lo mismo: hay que desbloquearlo, y no es que la
 * bóveda esté vacía o rota.
 */
function assertOpen (d) {
  if (d?.locked) throw coded('profile locked: unlock it with your password (dotrino-vault unlock)', 'PROFILE_LOCKED')
  return d
}

/**
 * Espera a que reaparezca un archivo de respuesta (con `.at`) tras borrarlo.
 *
 * Con `req`, solo vale LA RESPUESTA A ESA PETICIÓN (el daemon devuelve el `id` en
 * `req`). El daemon vuelca la lista de perfiles también por su cuenta —cada repaso, y
 * al atender cualquier otra cosa—, así que sin esto se podía tomar por respuesta un
 * volcado de hace un instante, escrito ANTES de que la petición se atendiera: el
 * `unlock` contestaba con la foto de cuando aún estaba cerrada.
 *
 * Un daemon viejo no devuelve `req`: entonces vale cualquier volcado posterior a la
 * petición (que es lo que se hacía siempre, y sigue siendo mejor que nada).
 */
async function waitFor (name, { tries = 60, interval = 100, req = null, since = 0 } = {}) {
  for (let i = 0; i < tries; i++) {
    await sleep(interval)
    const d = read(name, null)
    if (!d || !d.at || d.at < since) continue
    if (!req || d.req === req) return d
    // Un daemon viejo NO trae el campo. Que venga con `null` significa lo contrario: el
    // daemon sabe marcarlas y este volcado no contesta a nadie (es uno de los suyos), así
    // que se sigue esperando el que sí lleva nuestro id.
    if (!('req' in d)) return d
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
  const since = Date.now()
  const id = await writeReq(F.profileReq, { op, ...extra }, profile)
  signalOrCleanup('SIGUSR2', [F.profileReq])
  const d = await waitFor(F.profilesList, { req: id, since })
  if (!d) throw coded('the daemon did not reply', 'NO_REPLY')
  // p.ej. MASTER_WITH_MEMBERS (freno D12) o WRONG_PASSWORD. Los datos del error viajan
  // pegados (cuánto hay que esperar, cuántos intentos van): quien lo pinta los necesita.
  if (d.error) throw Object.assign(coded(d.error, d.code), { waitSec: d.waitSec, tries: d.tries })
  return d // { profiles:[{id,name,protected,locked,current,fingerprint,iss,createdAt}], current, done? }
}

export const listProfiles = () => profileOp('list')
export const addProfile = (name) => profileOp('add', { name })
export const useProfile = (profile) => profileOp('use', { profile })
export const renameProfile = (profile, name) => profileOp('rename', { profile, name })
export const removeProfile = (profile) => profileOp('rm', { profile })
export const unlockProfile = (profile, password) => profileOp('unlock', { profile, password })
export const lockProfile = (profile) => profileOp('lock', { profile })
// `current`: la contraseña que YA tenía el perfil. Hace falta para abrir la copia
// maestra de los secretos y volver a cerrarla con la nueva — sin ese paso, cambiar la
// contraseña dejaría las variables privadas ilegibles.
export const setProfilePassword = (profile, password, current) => profileOp('password-set', { profile, password, ...(current ? { current } : {}) })
// Quitarla también la pide: se re-sella a la llave de la máquina antes de que se vaya.
export const removeProfilePassword = (profile, password) => profileOp('password-rm', { profile, password })

// ---------------------------------------------------------------------------
// Volcado de dispositivos + secretos de un perfil
// ---------------------------------------------------------------------------

/**
 * Fuerza el volcado del daemon (devices.json + secrets-list.json + profiles-list.json)
 * para `profile` (o el activo) y devuelve las tres cosas ya parseadas.
 */
export async function snapshot (profile) {
  requireAlive()
  rm(F.devices); rm(F.secretsList); rm(F.acta)
  const since = Date.now()
  const id = await writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.dumpReq])
  // El ACTA entra en el volcado normal: es la lista de dispositivos de verdad, y las
  // delegaciones son su reflejo. Sin ella, un miembro sin certificados (revocado a medias,
  // o con el papel caducado) no salía en ninguna pantalla del PC — invisible y, por lo
  // tanto, imposible de quitar desde aquí.
  const [devices, secrets, record] = await Promise.all([
    waitFor(F.devices, { req: id, since }), waitFor(F.secretsList, { req: id, since }),
    waitFor(F.acta, { req: id, since })
  ])
  // El volcado de variables lleva el valor de las PÚBLICAS, así que se borra en cuanto se
  // tiene: en la memoria de quien lo pidió, no esperando en el disco a que copien la
  // carpeta (ahí es donde el cifrado en reposo dejaría de servir de nada).
  rm(F.secretsList)
  assertOpen(devices); assertOpen(secrets); assertOpen(record)
  // LA LISTA DE BÓVEDAS NO SE ESPERA AQUÍ. `profiles-list.json` es la respuesta a una
  // petición de PERFIL (`dumpProfiles`), y el daemon dejó de volcarlo por su cuenta —
  // volcarlo sin que nadie preguntara se llevaba por delante las respuestas de verdad.
  // Seguir esperándolo aquí era esperar seis segundos, los de rendirse, a un archivo que
  // ya no iba a llegar: CADA refresco de la TUI costaba eso, con el daemon contestando lo
  // suyo en 100 ms. Quien necesita la lista llama a `listProfiles()`, que sí la pide.
  return { devices, secrets, record, profiles: read(F.profilesList, null) }
}

/**
 * Dispositivos enrolados/revocados del perfil, con su deviceId ya calculado.
 * `issued` viene de identity.listDelegations(); el deviceId se deriva del `sub`.
 */
export async function listDevices (profile) {
  const { devices, record } = await snapshot(profile)
  if (!devices) throw coded('the daemon did not reply', 'NO_REPLY')
  const issued = devices.issued || devices.active || devices.delegations || []
  const revoked = devices.revoked || []
  const withIds = await Promise.all(issued.map(async (d) => ({
    ...d, deviceId: d.sub ? await deviceIdOf(d.sub) : '????-????'
  })))
  // Los MIEMBROS viajan con la lista: quién es del perfil lo dice el acta, y los
  // certificados son su reflejo. Quien pinte la lista los necesita a la vez, o acaba
  // enseñando solo a los que tienen papel — y el que hay que quitar es justo el que no.
  return {
    issued: groupCertsByDevice(withIds, revoked),
    revoked,
    members: record?.members || [],
    profile: devices.profile || null
  }
}

/**
 * UN APARATO, UNA FILA — y sin los certificados retirados.
 *
 * El daemon lleva la cuenta por CERTIFICADO, que es lo correcto para él: revocar es
 * revocar un papel. Pero al dueño le sobra ese detalle — renovar emite uno nuevo cada 30
 * días, así que un aparato de un año saldría doce veces, y los revocados seguían contando
 * como «enrolados». Se agrupa por llave, se queda el más nuevo y se guardan TODOS sus
 * nonces, que es lo que hace falta para retirarlo entero.
 */
export function groupCertsByDevice (list, revoked = []) {
  const out = new Set(revoked.map((r) => r?.nonce || r))
  const byKey = new Map()
  for (const d of list) {
    if (d.revokedAt || out.has(d.nonce)) continue
    const key = d.sub || d.nonce
    const y = byKey.get(key)
    if (!y) byKey.set(key, { ...d, nonces: [d.nonce] })
    else {
      y.nonces.push(d.nonce)
      if ((d.exp || 0) > (y.exp || 0)) Object.assign(y, { ...d, nonces: y.nonces })
    }
  }
  return [...byKey.values()]
}

/**
 * Renombra un dispositivo. El nombre lo trae el aparato al emparejarse (o, si no le diste
 * ninguno, el apodo que tuvieras ese día), así que se queda desfasado enseguida.
 */
export async function setDeviceLabel (pub, label, profile) {
  requireAlive()
  await writeReq(F.labelReq, { pub, label }, profile)
  signalOrCleanup('SIGUSR2', [F.labelReq])
  await sleep(400)
  return listDevices(profile)
}

/**
 * El ACTA del perfil: quién es miembro y qué puede hacer cada uno. Es lo que manda para los
 * permisos — la lista de dispositivos enseña el SCOPE DEL CERT, que es su reflejo y puede
 * ir por detrás hasta que el aparato renueve.
 */
export async function listMembers (profile) {
  requireAlive()
  rm(F.acta)
  const since = Date.now()
  const id = await writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.dumpReq])
  const d = await waitFor(F.acta, { req: id, since })
  if (!d) throw coded('the daemon did not reply', 'NO_REPLY')
  assertOpen(d)
  return d.members || []
}

/**
 * Cambia lo que PUEDE hacer un dispositivo. La lista es completa (no un delta): lo que no
 * venga, se le quita.
 *
 * `admin` (administrar el perfil a distancia) se concede AQUÍ, en la máquina de la bóveda,
 * y nunca al emparejar: así el QR que circula no puede otorgarla nunca, y darla es un
 * gesto deliberado del dueño que queda escrito en el acta.
 */
export async function setDeviceCaps (pub, caps, profile) {
  requireAlive()
  await writeReq(F.capsReq, { pub, caps }, profile)
  signalOrCleanup('SIGUSR2', [F.capsReq])
  await sleep(600)
  return listDevices(profile)
}

/**
 * Quita un dispositivo por su llave `sub` (le ordena autoborrarse) y revuelca.
 * Se acepta un `nonce` suelto por compatibilidad, pero eso retira UN certificado:
 * un aparato puede tener varios y seguiría entrando con el otro.
 */
export async function revokeDevice (target, profile) {
  requireAlive()
  const req = typeof target === 'string' ? { nonce: target } : { sub: target?.sub, nonce: target?.nonce }
  await writeReq(F.revokeReq, req, profile)
  signalOrCleanup('SIGUSR2', [F.revokeReq])
  await sleep(300)
  return listDevices(profile)
}

// ---------------------------------------------------------------------------
// Perfil del usuario (lo que sincronizan los dispositivos)
// ---------------------------------------------------------------------------

/**
 * El PERFIL del usuario tal como lo tiene la bóveda: nombre, foto y datos. Es lo que se
 * edita en cualquier dispositivo emparejado y se sincroniza aquí, así que sirve para
 * comprobar que lo que cambiaste en el aparato llegó.
 *
 * No es lo mismo que `listProfiles` (las cuentas de ESTE PC) ni que el acta (quién es del
 * perfil): esto es el CONTENIDO. La foto llega resumida (tipo y tamaño), no en bytes:
 * nadie va a mirar un data-URI de 90 KB en una terminal.
 *
 * El volcado es contenido del usuario, así que se lee y se BORRA en el acto.
 */
export async function getMe (profile) {
  requireAlive()
  rm(F.me)
  const since = Date.now()
  const id = await writeReq(F.meReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.meReq])
  const d = await waitFor(F.me, { req: id, since })
  rm(F.me)
  if (!d) throw coded('the daemon did not reply', 'NO_REPLY')
  assertOpen(d)
  return d.me || null
}


// ---------------------------------------------------------------------------
// Variables de entorno: DOS CAJONES
//
//   · por SCOPE   (`ns`)  — las comparten todos los aparatos del perfil que sirven
//                           ese namespace.
//   · por APARATO (`dev`) — solo las lee ese aparato, y PISAN a las del scope.
//
// Las dos listas viajan juntas en el mismo volcado (`secrets-list.json`), así que
// todas estas funciones devuelven lo mismo: `{ ns, dev }`. Nunca hay valores en
// ninguna de las dos: el daemon no los expone.
// ---------------------------------------------------------------------------

/**
 * Da forma al volcado: `{ ns: {<scope>: [{key, public}]}, dev: [{pub,id,label,cn,keys,orphan}] }`.
 * `public` dice si el VALOR puede salir de la máquina de la bóveda hacia la consola remota;
 * el valor en sí no está aquí ni en ningún volcado.
 */
const shapeSecrets = (d) => ({ ns: d?.ns || {}, dev: Array.isArray(d?.dev) ? d.dev : [] })

/** Los dos cajones del perfil (NUNCA los valores). */
export async function listSecrets (profile) {
  const { secrets } = await snapshot(profile)
  if (!secrets) throw coded('the daemon did not reply', 'NO_REPLY')
  return shapeSecrets(secrets)
}

/**
 * Manda una orden de secreto y espera el volcado, comprobando que se aplicó de verdad:
 * el daemon puede rechazarla (clave inválida, aparato que no es un servicio) y quedarse
 * callado, y un «guardado» que no guardó nada es la peor forma de fallar en esto.
 */
async function secretOp (req, profile, check) {
  // `req` puede llevar la CONTRASEÑA del perfil (las operaciones que sellan la
  // necesitan para abrir la copia maestra). Vive un instante en un archivo 0600 del
  // dir del vault y el daemon lo borra al consumirlo.
  requireAlive() // el VALOR es secreto: no escribirlo si el daemon está caído
  rm(F.secretsList)
  await writeReq(F.secretReq, req, profile)
  await writeReq(F.dumpReq, {}, profile)
  signalOrCleanup('SIGUSR2', [F.secretReq, F.dumpReq])
  const d = await waitFor(F.secretsList)
  rm(F.secretsList) // lleva el valor de las públicas: no se queda en el disco (ver `snapshot`)
  if (!d) throw coded('the daemon did not reply', 'NO_REPLY')
  assertOpen(d)
  const out = shapeSecrets(d)
  check(out)
  return out
}

const keysOf = (out, pub) => (out.dev.find((x) => x.pub === pub)?.keys) || []
/** ¿Está esa clave en la lista? Las listas traen `{key, public}`, nunca el valor. */
const has = (list, key) => (list || []).some((x) => x.key === key)
const visibilityOf = (list, key) => !!(list || []).find((x) => x.key === key)?.public

/**
 * Guarda/actualiza una variable de SCOPE. ns: [a-z0-9-]{1,32}. clave: [A-Z0-9_]{1,64}.
 * `isPublic` opcional: sin decir nada conserva la visibilidad que ya tenía (y una nueva
 * nace privada, o sea que su valor no sale de la máquina de la bóveda).
 */
export function setSecret (ns, key, value, profile, isPublic, password) {
  return secretOp({ op: 'set', ns, key, value, ...(password ? { password } : {}), ...(isPublic === undefined ? {} : { public: !!isPublic }) }, profile, (out) => {
    if (!has(out.ns[ns], key)) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

/** Borra una variable de SCOPE. Si era la última, el scope desaparece. */
export function deleteSecret (ns, key, profile) {
  return secretOp({ op: 'rm', ns, key }, profile, (out) => {
    if (has(out.ns[ns], key)) throw coded('the daemon did not delete the variable (check the service logs)', 'NOT_DELETED')
  })
}

/**
 * Cambia SOLO quién puede ver el valor: `public` deja que la consola remota lo vea,
 * `private` lo encierra en esta máquina. No toca el valor (ni hace falta conocerlo).
 */
export function setSecretVisibility (ns, key, isPublic, profile, password) {
  return secretOp({ op: 'vis', ns, key, public: !!isPublic, ...(password ? { password } : {}) }, profile, (out) => {
    if (visibilityOf(out.ns[ns], key) !== !!isPublic) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

export function setDeviceSecretVisibility (pub, key, isPublic, profile, password) {
  return secretOp({ op: 'dev-vis', pub, key, public: !!isPublic, ...(password ? { password } : {}) }, profile, (out) => {
    if (visibilityOf(keysOf(out, pub), key) !== !!isPublic) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

/**
 * CARGA VARIAS DE UNA VEZ: un solo viaje al daemon, un solo guardado y —lo que de
 * verdad importa— UN solo aviso a los servicios de ese scope.
 *
 * De una en una, cada variable es un cambio de configuración: el servicio obedece el
 * primero, sale, lo levanta su supervisor y arranca con lo que hubiera puesto en ese
 * momento, mientras quien administra sigue escribiendo el resto. Por eso cargar
 * configuración tiene que llegar entera hasta abajo, y no romperse en N órdenes.
 *
 * @param {Array<{op:'set'|'rm', key:string, value?:string, public?:boolean}>} items
 */
export function applySecrets (ns, items, profile, password) {
  return secretOp({ op: 'batch', ns, items, ...(password ? { password } : {}) }, profile, (out) => {
    const missing = items.find((it) => (it.op === 'rm' ? has(out.ns[ns], it.key) : !has(out.ns[ns], it.key)))
    if (missing) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

/** Lo mismo para el cajón de UN aparato. */
export function applyDeviceSecrets (pub, items, profile, password) {
  return secretOp({ op: 'batch', pub, items, ...(password ? { password } : {}) }, profile, (out) => {
    const missing = items.find((it) => (it.op === 'rm' ? has(keysOf(out, pub), it.key) : !has(keysOf(out, pub), it.key)))
    if (missing) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

/** Borra un scope entero: todas sus variables juntas, para no avisar una vez por variable. */
export async function deleteScope (ns, profile) {
  const out = await listSecrets(profile)
  const keys = (out.ns[ns] || []).map(({ key }) => ({ op: 'rm', key }))
  if (!keys.length) return out
  return applySecrets(ns, keys, profile)
}

/**
 * Guarda/actualiza una variable de UN APARATO, identificado por su llave (`pub`, la
 * misma que trae el acta). Solo la lee ese aparato, y le gana a la del scope con el
 * mismo nombre.
 */
export function setDeviceSecret (pub, key, value, profile, isPublic, password) {
  return secretOp({ op: 'dev-set', pub, key, value, ...(password ? { password } : {}), ...(isPublic === undefined ? {} : { public: !!isPublic }) }, profile, (out) => {
    if (!has(keysOf(out, pub), key)) throw coded('the daemon did not apply the change (check the service logs)', 'NOT_APPLIED')
  })
}

/** Borra una variable de un aparato. */
export function deleteDeviceSecret (pub, key, profile) {
  return secretOp({ op: 'dev-rm', pub, key }, profile, (out) => {
    if (has(keysOf(out, pub), key)) throw coded('the daemon did not delete the variable (check the service logs)', 'NOT_DELETED')
  })
}

/** Borra TODAS las variables de un aparato, juntas (mismo motivo que `deleteScope`). */
export async function deleteDeviceVars (pub, profile) {
  const out = await listSecrets(profile)
  const keys = keysOf(out, pub).map(({ key }) => ({ op: 'rm', key }))
  if (!keys.length) return out
  return applyDeviceSecrets(pub, keys, profile)
}

// ---------------------------------------------------------------------------
// Emparejamiento de dispositivos (pares)
// ---------------------------------------------------------------------------

/**
 * Codifica el QR crudo para enseñarlo (ver `lib/src/invite.js`).
 *
 * Las dos formas son **la misma invitación compacta**: binario en base64url, ~100
 * caracteres. Sirve igual para el QR (donde cada carácter son módulos, y módulos
 * son filas de terminal) que para copiar y pegar (una sola palabra, sin comillas
 * ni llaves, que sobrevive a un doble clic y a un chat). Antes hacían falta dos
 * codificaciones distintas porque la única forma de achicar el QR era mandar el
 * JSON crudo, ilegible al pegarlo; comprimiendo de verdad, esa disyuntiva
 * desaparece.
 *
 *   · `url`     → el enlace del QR, `…/d#v=<invitación>`.
 *   · `code`    → la invitación suelta, para pegar en la consola.
 *   · `payload` → el JSON crudo. Ya no se emite; se devuelve para diagnóstico.
 */
export function pairUrl (qr) {
  const code = encodeInvite(qr)
  return { url: inviteUrl(qr), code, payload: JSON.stringify(qr), b64: code }
}

export async function startPairing ({ profile, service } = {}) {
  requireAlive()
  rm(F.pair); rm(F.pending)
  await writeReq(F.pairReq, service ? { service } : {}, profile)
  signalOrCleanup('SIGUSR1', [F.pairReq])
  for (let i = 0; i < 50; i++) {
    await sleep(100)
    const pr = read(F.pair, null)
    assertOpen(pr)
    if (pr?.expiresAt > Date.now()) {
      const { url, payload, code } = pairUrl(pr.qr)
      // `profile`/`profileName`: DE QUÉ CUENTA del vault sale este QR. El vault
      // puede tener varias y el emparejamiento mete al dispositivo en UNA; la TUI
      // y la CLI lo muestran para que no se enrole en la equivocada.
      return { qr: pr.qr, expiresAt: pr.expiresAt, url, payload, code, b64: code, profile: pr.profile || null, profileName: pr.profileName || '' }
    }
  }
  throw coded('the daemon did not start the pairing', 'PAIR_FAILED')
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
  rm(F.approve)
  const since = Date.now()
  const id = await writeReq(F.approveReq, { code: String(code) }, profile)
  signalOrCleanup('SIGUSR2', [F.approveReq])
  // SE ESPERA LA RESPUESTA. Antes se daba por hecho: con el código equivocado —que la
  // bóveda rechaza sin firmar nada— la pantalla decía «Dispositivo aprobado» igual, se
  // olvidaba del pendiente y no había forma de reintentar desde aquí.
  const r = await waitFor(F.approve, { req: id, since, tries: 40 })
  // Sin respuesta: un daemon anterior a esto. Se sigue como antes en vez de inventar un
  // error (el emparejamiento pudo salir bien).
  if (r && r.ok === false) throw coded(r.error || 'the code does not match', r.code || 'APPROVE_FAILED')
  await sleep(400)
  // LA LISTA ES UN EXTRA, NO PARTE DE APROBAR. Si el volcado no llega, el aparato ya
  // entró igual: el certificado se firmó y el acta se selló antes de esto. Dejar que ese
  // fallo suba convertía un emparejamiento correcto en «el daemon no respondió», que es
  // lo contrario de lo que pasó — y el dueño se queda sin saber si repetirlo o no.
  // Se devuelve null y quien llama refresca por su cuenta.
  try { return await listDevices(profile) } catch (_) { return null }
}

/** Rechaza el dispositivo pendiente. */
export async function rejectPending (deviceId, profile) {
  requireAlive()
  await writeReq(F.rejectReq, { deviceId }, profile)
  signalOrCleanup('SIGUSR2', [F.rejectReq])
  await sleep(200)
}
