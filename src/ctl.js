/**
 * ctl.js — CLI de control de dotrino-vault.
 *
 * NO abre la identidad ni el proxy: habla con el daemon (único custodio de la
 * maestra) por archivos del dir de datos + señales. Emparejamiento ENDURECIDO
 * (docs/pairing-protocol.md): la maestra solo firma el cert de un dispositivo
 * DESPUÉS de que el dueño compara un código (SAS) y corre `approve`.
 *
 *   status            estado + fingerprint
 *   pair              inicia un emparejamiento (muestra el QR y espera el dispositivo)
 *   pending           muestra el dispositivo pendiente de aprobar + su código
 *   approve <id>      aprueba un dispositivo (tras comparar el código)
 *   reject <id>       rechaza un dispositivo pendiente
 *   devices           lista dispositivos enrolados / revocados
 *   revoke <nonce>    revoca un dispositivo (y le ordena autoborrarse)
 *   profile …         perfiles (varias identidades en el mismo PC) y su contraseña
 *   unlock / lock     candado del perfil (la contraseña solo hace falta para EDITAR)
 *   logs              últimos logs del servicio
 *
 * MULTI-PERFIL: todos los comandos aceptan `--profile <id|nombre>`; sin él van al
 * perfil ACTIVO (`profile use`).
 */
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import tty from 'node:tty'
import { pubkeyId } from '@dotrino/identity/capabilities'
import { dataDir, readJson } from './paths.js'
import { assertVar } from './secretsStore.js'
import { isValidSecretsNs } from './protocol.js'
import { parseEnvText, PAIR_RE } from '../lib/src/envtext.js'
import { qrToString } from './qr.js'
import { encodeInvite, inviteUrl } from '../lib/src/invite.js'
import { VERSION } from './version.js'

const dir = dataDir()
const stateFile = path.join(dir, 'state.json')
const pairFile = path.join(dir, 'pair.json')
const pendingFile = path.join(dir, 'pending-enroll.json')
const devFile = path.join(dir, 'devices.json')
const profilesFile = path.join(dir, 'profiles-list.json')

// `--profile <id|nombre>`: a qué perfil apunta el comando (sin él, el activo).
// Se extrae de los argumentos antes de interpretarlos, así vale para todos.
let PROFILE = null
function takeProfileFlag (args) {
  const i = args.findIndex((a) => a === '--profile' || a === '-p')
  if (i < 0) return args
  const val = args[i + 1]
  if (!val || val.startsWith('-')) { console.error('uso: --profile <id|nombre>'); process.exit(2) }
  PROFILE = val
  return [...args.slice(0, i), ...args.slice(i + 2)]
}
/** Campo `profile` de las peticiones al daemon (omitido = perfil activo). */
const withProfile = (obj) => (PROFILE ? { ...obj, profile: PROFILE } : obj)
/**
 * Deja una petición para el daemon. ATÓMICA (escribir aparte y renombrar): el daemon
 * vigila la carpeta con `fs.watch`, que avisa al CREAR el archivo y no al terminar de
 * escribirlo, así que escrito en el sitio se puede leer a medias — y una petición que no
 * parsea se pierde con todos sus datos.
 */
const writeReq = (name, obj) => {
  const dest = path.join(dir, name)
  const tmp = dest + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(withProfile({ ...obj, at: Date.now() })), { mode: 0o600 })
  fs.renameSync(tmp, dest)
}

const R = '\x1b[31m', B = '\x1b[1m', Z = '\x1b[0m' // rojo / negrita / reset
// La versión se inyecta en build (esbuild --define); en dev cae a 'dev'.

/**
 * Cómo se arranca el vault EN ESTA MÁQUINA. El CLI corre en Linux (servicio systemd),
 * en Windows/macOS (por npm, en primer plano o al inicio de sesión) y dentro de un
 * contenedor, así que decir siempre «systemctl» manda a la mitad de la gente a un
 * comando que no existe.
 */
const IN_DOCKER = !!process.env.DOTRINO_IN_DOCKER
const START_HINT = IN_DOCKER
  ? 'docker start dotrino-vault'
  : process.platform === 'linux'
    ? 'systemctl --user start dotrino-vault'
    : 'dotrino-vaultd   (o: npx -y @dotrino/vaultd)'
const RESTART_HINT = IN_DOCKER
  ? 'docker restart dotrino-vault'
  : process.platform === 'linux'
    ? 'systemctl --user restart dotrino-vault'
    : 'cierra el vault y vuelve a arrancarlo'

function readState () {
  const s = readJson(stateFile, null)
  if (!s) {
    console.error('El vault no parece haber arrancado todavía (no hay state.json en %s).', dir)
    console.error('Arráncalo:  %s', START_HINT)
    process.exit(2)
  }
  return s
}
function alive (pid) { try { return !!pid && (process.kill(pid, 0) || true) } catch { return false } }
/**
 * Campanita para que el daemon lea la petición YA. En Windows no existen SIGUSR1/SIGUSR2
 * y `process.kill` con ellas falla: no es un error, es que ahí no hay señales. El daemon
 * vigila la carpeta igualmente, así que la petición se atiende en cuanto se escribe el
 * archivo; la señal solo se ahorra la latencia del watcher.
 */
function sendSignal (pid, sig) { try { process.kill(pid, sig) } catch (_) { /* Windows, o el daemon ya se enteró */ } }
function sleep (ms) { return new Promise((r) => setTimeout(r, ms)) }
function requireDaemon () {
  const s = readState()
  if (!alive(s.pid)) { console.error('El daemon no está corriendo. Arráncalo: %s', START_HINT); process.exit(1) }
  return s
}
function deviceIdOf (sub) {
  // mismo formato que el daemon: 8 hex agrupados AB12-CD34
  return pubkeyId(sub).then((id) => id.slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2'))
}

function cmdStatus () {
  const s = readState()
  const up = alive(s.pid)
  console.log('dotrino-vault · %s', up ? 'corriendo' : 'DETENIDO (state.json viejo)')
  console.log('  versión     : %s', VERSION)
  // El .deb instala el binario pero NO reinicia el servicio: si el daemon
  // corriendo es más viejo que el CLI, avisar (nos mordió 3 veces).
  if (s.version && s.version !== VERSION) {
    console.log('  ⚠ el servicio corre la versión %s (binario instalado: %s).', s.version, VERSION)
    console.log('    Reinicia para actualizarlo:  %s', RESTART_HINT)
  }
  console.log('  fingerprint : %s', s.fingerprint)
  console.log('  proxy       : %s', s.proxy)
  console.log('  pid         : %s%s', s.pid, up ? '' : ' (no responde)')
  console.log('  datos       : %s', dir)
  const profiles = s.profiles || []
  if (profiles.length) {
    console.log('  perfiles    : %d', profiles.length)
    for (const p of profiles) console.log('    %s %s', p.current ? '*' : ' ', describeProfile(p))
    if (profiles.length > 1) console.log('    (el * es el perfil activo; los demás siguen atendiendo a sus dispositivos)')
  }
  if (!up) process.exitCode = 1
}

/** Una línea por perfil: nombre, id, huella y estado del candado. */
function describeProfile (p) {
  const lock = !p.protected ? 'sin contraseña' : (p.locked ? `${B}🔒 bloqueado${Z}` : '🔓 desbloqueado')
  return `${B}${p.name || '(sin nombre)'}${Z}  ${p.id}  ${p.fingerprint || '—'}  ${lock}`
}

function showChallenge (pe) {
  console.log('\n%sUn dispositivo quiere conectarse a tu bóveda:%s', B, Z)
  console.log('  dispositivo : %s%s%s', B, pe.deviceId, Z)
  console.log('\n  Ingresa el código que MUESTRA el dispositivo (el vault no lo conoce):')
  console.log('    %sdotrino-vault approve <código>%s', B, Z)
  console.log('  Si no reconoces este dispositivo:  dotrino-vault reject %s\n', pe.deviceId)
}

/**
 * EL CANDADO. Un perfil con contraseña y bloqueado no se ve ni se toca desde esta consola:
 * el daemon contesta `locked` y sin contenido, y aquí se corta con un mensaje que dice qué
 * hacer. Los aparatos ya emparejados siguen atendidos — lo que está cerrado es esta
 * pantalla, no la bóveda.
 */
function assertOpen (d) {
  if (d?.locked) {
    console.error('Perfil bloqueado. Ábrelo con:  dotrino-vault unlock')
    process.exit(1)
  }
  return d
}

async function cmdPair (args = []) {
  const s = requireDaemon()
  try { fs.rmSync(pairFile, { force: true }) } catch (_) {}
  try { fs.rmSync(pendingFile, { force: true }) } catch (_) {}
  // --service <ns>: emparejar un SERVICIO (proxy, geo…) con cert limitado a
  // vault:secrets:<ns> (no puede firmar como tú ni leer tus datos).
  const svcIdx = args.indexOf('--service')
  let service = null
  if (svcIdx >= 0) {
    service = args[svcIdx + 1]
    if (!service || service.startsWith('-') || !/^[a-z0-9-]{1,32}$/.test(service)) {
      console.error('uso: dotrino-vault pair --service <ns>   (ns en minúsculas, p.ej. proxy)'); process.exit(2)
    }
  }
  // --scope <lista>: los PERMISOS del cert, y nada más. No hay tipos de aparato
  // (2026-08-22, dueño): un aparato es un aparato y lo que puede hacer. Sin --scope,
  // el juego de siempre (sign,read,store); `--service <ns>` es el atajo de
  // `secrets:<ns>`, y los dos se combinan (`--service eco --scope sign` = un bot que
  // firma como aparato del acta y lee solo su cajón). `admin` no se empareja: se
  // concede desde el PC (`caps <ID> +administra`).
  const scIdx = args.indexOf('--scope')
  let scope = null
  if (scIdx >= 0) {
    const raw = args[scIdx + 1]
    if (!raw || raw.startsWith('-')) { console.error('uso: dotrino-vault pair --scope sign,read,store,secrets:<ns>'); process.exit(2) }
    const ALIAS = { firma: 'sign', lee: 'read', guarda: 'store' }
    scope = []
    for (const tok of raw.split(',').map((t) => t.trim()).filter(Boolean)) {
      const t = ALIAS[tok] || tok
      if (t === 'admin' || t === 'administra') { console.error('`admin` no se empareja: concédelo desde el PC con  dotrino-vault caps <ID> +administra'); process.exit(2) }
      if (t === 'approve' || t === 'aprueba') { console.error('`approve` no se empareja: concédelo desde el PC con  dotrino-vault caps <ID> +aprueba'); process.exit(2) }
      if (t === 'sign' || t === 'read' || t === 'store') { scope.push('vault:' + t); continue }
      const m = /^secrets:([a-z0-9-]{1,32})$/.exec(t)
      if (m) { scope.push('vault:secrets:' + m[1]); continue }
      console.error('permiso desconocido: %s  (sign | read | store | secrets:<ns>)', tok); process.exit(2)
    }
    if (service) scope.push('vault:secrets:' + service)
    scope = [...new Set(scope)]
  }
  // `--new-account [nombre]`: la otra respuesta a «¿a qué cuenta entra?». En vez de
  // meter el dispositivo en una cuenta que ya vive aquí, se ESTRENA una (vacía) y
  // entra a ella; las demás no se tocan. En la TUI esto es una pregunta con sus
  // opciones; en la CLI es una bandera, para que siga sirviendo en un script.
  const naIdx = args.findIndex((a) => a === '--new-account')
  if (naIdx >= 0) {
    const next = args[naIdx + 1]
    const name = (next && !next.startsWith('-')) ? next : `cuenta ${new Date().toISOString().slice(0, 10)}`
    const d = await profileRequest('add', { name })
    if (d.error) { console.error('%s', d.error); process.exit(1) }
    if (!d.id) { console.error('El daemon no dijo qué cuenta creó.'); process.exit(1) }
    PROFILE = d.id // el emparejamiento y los comandos siguientes apuntan a ELLA
    console.log('Cuenta nueva: %s  (%s)', name, d.id)
  }
  // `--adopt [nombre]`: la TERCERA respuesta a «¿de qué cuenta hablamos?» — el camino A.
  // Aquí la cuenta NO sale de esta bóveda: la trae el aparato y esta bóveda pasa a
  // guardarla y a mandarla. Por eso se crea un perfil VACÍO, que nace a la espera de
  // adoptarla; sin ese sitio no habría dónde meterla.
  const adIdx = args.findIndex((a) => a === '--adopt')
  const adopt = adIdx >= 0
  if (adopt) {
    const next = args[adIdx + 1]
    const name = (next && !next.startsWith('-')) ? next : `cuenta del dispositivo`
    const d = await profileRequest('add', { name, adopt: true })
    if (d.error) { console.error('%s', d.error); process.exit(1) }
    if (!d.id) { console.error('El daemon no dijo qué cuenta creó.'); process.exit(1) }
    PROFILE = d.id
    console.log('Cuenta a la espera de adoptar la del dispositivo: %s  (%s)', name, d.id)
  }
  // La petición se escribe SIEMPRE (aunque no haya --service): lleva a qué perfil
  // se empareja el dispositivo.
  writeReq('pair-request.json', { ...(service ? { service } : {}), ...(scope ? { scope } : {}), ...(adopt ? { mode: 'adopt' } : {}) })
  sendSignal(s.pid, 'SIGUSR1')

  let pair = null
  for (let i = 0; i < 50; i++) {
    await sleep(100)
    const p = readJson(pairFile, null)
    assertOpen(p) // el candado se contesta por el mismo archivo, para no dejar esperando
    if (p?.expiresAt > Date.now()) { pair = p; break }
  }
  if (!pair) { console.error('No se recibió respuesta del daemon para el emparejamiento.'); process.exit(1) }

  // Una sola forma para las dos cosas: la invitación compacta (base64url de ~100
  // caracteres) va igual de bien dentro del QR que pegada a mano. Ver `lib/src/invite.js`.
  const b64 = encodeInvite(pair.qr)
  const url = inviteUrl(pair.qr)
  const mins = Math.round((pair.expiresAt - Date.now()) / 60000)
  // QUÉ CUENTA se comparte: el vault puede tener varias bóvedas y este QR sale de
  // UNA (la activa, o la de --profile). Decirlo evita enrolar el dispositivo en la
  // equivocada; es la misma línea que muestra la TUI.
  const acct = pair.profileName || pair.profile
  if (acct) console.log('\nCuenta que se comparte: %s%s', acct, pair.profileName && pair.profile ? `  (${pair.profile})` : '')
  console.log('\nEscanea este QR con el dispositivo que quieres conectar (válido %d min):\n', mins)
  console.log(qrToString(url)) // el QR abre la consola de dispositivos y empareja solo
  console.log(`${R}${B}⚠ Este código deja LEER tus datos y FIRMAR con tu identidad.${Z}`)
  console.log(`${R}  NO lo compartas con nadie, ni con "soporte". Solo escanéalo en TU dispositivo.${Z}`)
  console.log('\nO abre esta dirección en el dispositivo:\n  ' + url)
  console.log('\nO pega este código en vault.dotrino.com/dispositivos :\n  ' + b64)

  // --save [archivo]: escribe la invitación (.dpair) para transferirla y abrirla en profile.
  const saveIdx = args.indexOf('--save')
  if (saveIdx >= 0) {
    const next = args[saveIdx + 1]
    const file = (next && !next.startsWith('-')) ? next : 'dotrino-invite.dpair'
    try { fs.writeFileSync(file, url + '\n', { mode: 0o600 }); console.log('\nInvitación guardada en: %s\n  (ábrela en vault.dotrino.com/dispositivos → «Abrir imagen o archivo». Es efímera y de un solo uso; no la compartas.)', file) }
    catch (e) { console.error('No se pudo guardar la invitación:', e.message) }
  }

  // Esperar a que el dispositivo se conecte y mostrar su código para comparar.
  console.log('\nEsperando a que el dispositivo se conecte…  (Ctrl+C para salir)')
  for (let i = 0; i < 1500; i++) { // ~2.5 min
    await sleep(100)
    const pe = readJson(pendingFile, null)
    if (pe?.deviceId) { showChallenge(pe); return }
  }
  console.log('\nNingún dispositivo se conectó aún. Cuando lo haga:  dotrino-vault pending')
}

function cmdPending () {
  requireDaemon()
  const pe = readJson(pendingFile, null)
  if (!pe?.deviceId) { console.log('No hay ningún dispositivo pendiente de aprobar.'); return }
  showChallenge(pe)
}

function cmdApprove (code) {
  if (!code) { console.error('uso: dotrino-vault approve <código>   (los dígitos que muestra el dispositivo)'); process.exit(2) }
  const s = requireDaemon()
  writeReq('approve-request.json', { code: String(code) })
  sendSignal(s.pid, 'SIGUSR2')
  console.log('Aprobando con el código %s… verifica con: dotrino-vault devices', code)
}

function cmdReject (deviceId) {
  if (!deviceId) { console.error('uso: dotrino-vault reject <deviceId>'); process.exit(2) }
  const s = requireDaemon()
  writeReq('reject-request.json', { deviceId })
  sendSignal(s.pid, 'SIGUSR2')
  console.log('Rechazado %s.', deviceId)
}

/**
 * `dotrino-vault me` — el PERFIL del usuario tal como lo tiene la bóveda: apodo, foto y
 * datos. Es lo que editas en cualquier dispositivo emparejado y se sincroniza aquí, así
 * que sirve para comprobar que lo que cambiaste en el aparato llegó de verdad.
 *
 * Distinto de `members` (quién es del perfil) y de `profile` (los perfiles del PC): esto
 * es el CONTENIDO, no la identidad.
 *
 * De la foto solo se dice que la hay, de qué tipo y cuánto pesa: es un data-URI de hasta
 * ~90 KB y una terminal no es sitio para volcarlo.
 */
async function cmdMe () {
  const s = requireDaemon()
  const meFile = path.join(dir, 'me.json')
  try { fs.rmSync(meFile, { force: true }) } catch (_) {}
  writeReq('me-request.json', {})
  sendSignal(s.pid, 'SIGUSR2')
  let dump = null
  for (let n = 0; n < 50; n++) { await sleep(100); const d = readJson(meFile, null); if (d?.at) { dump = d; break } }
  // El volcado es contenido del usuario: se lee y se BORRA, no se queda ahí suelto.
  try { fs.rmSync(meFile, { force: true }) } catch (_) {}
  if (!dump) { console.error('La bóveda no respondió. ¿Está corriendo?  dotrino-vault status'); process.exit(1) }
  assertOpen(dump)

  const me = dump.me
  if (!me) {
    console.log('\nTodavía no hay perfil en esta bóveda.')
    console.log('Edita tu nombre o tu foto en un dispositivo emparejado y vuelve a mirar.\n')
    return
  }

  const when = me.updatedAt ? new Date(me.updatedAt).toLocaleString() : '—'
  console.log('\n%sPerfil%s · actualizado %s\n', B, Z, when)
  console.log('  nombre      : %s', me.nickname || '(sin nombre)')
  console.log('  foto        : %s', me.avatar
    ? `sí · ${me.avatar.type || 'desconocido'} · ${(me.avatar.bytes / 1024).toFixed(1)} KB`
    : 'no')

  // Los campos estándar. `visible` es del usuario: teléfono y dirección nacen ocultos.
  const STD = [['nombres', 'nombres'], ['apellidos', 'apellidos'], ['email', 'correo'],
    ['telefono', 'teléfono'], ['direccion', 'dirección']]
  const filled = STD.filter(([k]) => me[k])
  if (filled.length) {
    console.log('')
    for (const [k, label] of filled) {
      console.log('  %s: %s%s', label.padEnd(12), me[k], me[k + 'Visible'] === false ? '   (oculto)' : '')
    }
  }
  for (const [title, list] of [['Enlaces', me.links], ['Otros datos', me.fields]]) {
    if (!Array.isArray(list) || !list.length) continue
    console.log('\n  %s:', title)
    for (const x of list) console.log('    %s %s%s', (x.type || x.label || '').padEnd(12), x.value, x.visible === false ? '   (oculto)' : '')
  }

  console.log('')
}

/**
 * `dotrino-vault members` — el ACTA del perfil: qué llaves son tuyas y qué puede hacer cada
 * una. Es la misma información que muestra la consola de vault.dotrino.com.
 */
async function cmdMembers () {
  const s = requireDaemon()
  const recordFile = path.join(dataDir(), 'acta.json')
  try { fs.rmSync(recordFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {})
  sendSignal(s.pid, 'SIGUSR2')
  let record = null
  for (let i = 0; i < 50; i++) { await sleep(100); const a = readJson(recordFile, null); if (a?.at) { record = a; break } }
  if (!record) { console.error('El daemon no respondió.'); process.exit(1) }
  assertOpen(record)
  if (!record.members?.length) { console.log('Este perfil todavía no tiene acta.'); return }

  const CAP = { sign: 'firma', store: 'guarda', read: 'lee', secrets: 'lee sus claves', admin: `${B}administra el perfil${Z}`, approve: `${B}aprueba pedidos${Z}` }
  // El nombre del perfil es una pubkey JWK. Recortarla no la hace legible: la deja
  // pareciendo un error (`{"key_ops":["verify"],"e…`). Se muestra su huella corta, la
  // misma que se enseña al emparejar y en la lista de miembros.
  const profileId = await deviceIdOf(record.profileId).catch(() => '????-????')
  console.log('\n%sPerfil%s %s · acta #%d\n', B, Z, profileId, record.seq)
  for (const m of record.members) {
    const who = m.label || m.id
    const marks = [
      m.isMaster ? `${B}Master${Z}` : null,
      m.isMe ? 'este dispositivo' : null,
      m.cn ? `servicio «${m.cn}»` : null
    ].filter(Boolean)
    const caps = m.caps.length ? m.caps.map((c) => CAP[c] || c).join(', ') : '(sin permisos)'
    console.log('  %s  %s%s\n      %s', m.id, who, marks.length ? '  [' + marks.join(' · ') + ']' : '', caps)
    // Un servicio SIN llave de cifrado no puede leer ninguna variable privada: van
    // selladas a esa llave. Se dice aquí, junto a él, porque es el único sitio donde
    // se mira quién es quién — y en la lista de variables ya seria tarde.
    if (m.cn && !m.canSeal) console.log('      %ssin llave de cifrado: NO puede leer sus variables%s', R, Z)
  }
  console.log('\n  Cambiar permisos:  dotrino-vault caps <ID> +firma | -firma | +guarda | -guarda | +lee | -lee | +administra | +aprueba')
  console.log('  «Administra» deja conectar y quitar dispositivos desde ese aparato, sin venir aquí.')
  console.log('  No deja cambiar permisos ni traspasar el mando: eso solo se hace en esta máquina.')
  console.log('  Los servicios solo pueden abrir las claves de su propio nombre; eso no se cambia aquí.\n')
}

/**
 * `dotrino-vault label <ID> <nombre>` — renombra un dispositivo.
 *
 * El nombre lo pone el aparato al emparejarse (y si no le diste uno, entra con TU apodo de
 * ese momento), así que se queda desfasado en cuanto te renombras. Esto lo arregla sin
 * tener que revocar y volver a emparejar.
 */
async function cmdLabel (args = []) {
  const [id, ...rest] = args
  const name = rest.join(' ').trim()
  if (!id || !name) {
    console.error('uso: dotrino-vault label <ID> <nombre>   (p.ej. label AB12-CD34 "Teléfono de casa")')
    process.exit(2)
  }
  const m = await findMember(id)
  writeReq('label-request.json', { pub: m.pub, label: name })
  sendSignal(requireDaemon().pid, 'SIGUSR2')
  console.log('Listo: %s ahora se llama «%s». Compruébalo con: dotrino-vault members', m.id, name.slice(0, 60))
}

/** Busca un miembro del acta por su identificador (AB12-CD34) o se rinde con un mensaje claro. */
async function findMember (id) {
  const s = requireDaemon()
  const recordFile = path.join(dataDir(), 'acta.json')
  try { fs.rmSync(recordFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {})
  sendSignal(s.pid, 'SIGUSR2')
  let record = null
  for (let i = 0; i < 50; i++) { await sleep(100); const a = readJson(recordFile, null); if (a?.at) { record = a; break } }
  assertOpen(record)
  const m = record?.members?.find((x) => x.id === String(id).toUpperCase())
  if (!m) { console.error('No hay ningún dispositivo con ese identificador. Míralos con: dotrino-vault members'); process.exit(1) }
  return m
}

/** `dotrino-vault caps <ID> ±permiso` — cambia lo que puede hacer un dispositivo. */
async function cmdCaps (args = []) {
  const [id, ...changes] = args
  if (!id || !changes.length) {
    console.error('uso: dotrino-vault caps <ID> +firma|-firma|+guarda|-guarda|+lee|-lee|+administra|-administra|+aprueba|-aprueba')
    process.exit(2)
  }
  const CAP_BY_WORD = {
    firma: 'sign', guarda: 'store', lee: 'read', administra: 'admin', aprueba: 'approve',
    sign: 'sign', store: 'store', read: 'read', admin: 'admin', approve: 'approve'
  }
  const s = requireDaemon()
  const m = await findMember(id)

  const caps = new Set(m.caps)
  for (const c of changes) {
    const sign = c[0]
    const cap = CAP_BY_WORD[c.slice(1).toLowerCase()]
    if (!cap || (sign !== '+' && sign !== '-')) { console.error('permiso no reconocido: %s', c); process.exit(2) }
    if (sign === '+') caps.add(cap); else caps.delete(cap)
  }
  writeReq('caps-request.json', { pub: m.pub, caps: [...caps] })
  sendSignal(s.pid, 'SIGUSR2')
  console.log('Listo. Compruébalo con: dotrino-vault members')
}

async function cmdDevices () {
  const s = requireDaemon()
  try { fs.rmSync(devFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {}) // de qué perfil queremos los dispositivos
  sendSignal(s.pid, 'SIGUSR2')
  let snap = null
  for (let i = 0; i < 50; i++) { await sleep(100); const d = readJson(devFile, null); if (d?.at) { snap = d; break } }
  if (!snap) { console.error('El daemon no respondió.'); process.exit(1) }
  assertOpen(snap)
  const revoked = snap.revoked || []
  const revokedSet = new Set(revoked.map((r) => r?.nonce || r))
  // UN APARATO, UNA LÍNEA. El daemon lleva la cuenta por CERTIFICADO —correcto para él,
  // porque revocar es revocar un papel—, pero renovar emite uno nuevo cada 30 días: un
  // aparato de un año salía doce veces, y los ya retirados seguían contando como
  // enrolados. Se agrupa por llave y se dice cuántos certificados tiene.
  const byKey = new Map()
  for (const d of (snap.issued || snap.active || snap.delegations || [])) {
    if (d.revokedAt || revokedSet.has(d.nonce)) continue
    const key = d.sub || d.nonce
    const y = byKey.get(key)
    if (!y) byKey.set(key, { ...d, certs: 1 })
    else { y.certs++; if ((d.exp || 0) > (y.exp || 0)) Object.assign(y, { ...d, certs: y.certs }) }
  }
  const active = [...byKey.values()]
  console.log('Dispositivos enrolados: %d', active.length)
  for (const d of active) {
    const did = d.sub ? await deviceIdOf(d.sub) : '????-????'
    console.log('  · %s  %s%s%s%s', did, d.label || '(sin etiqueta)',
      d.exp ? '  vence=' + new Date(d.exp).toISOString().slice(0, 10) : '',
      d.certs > 1 ? '  (' + d.certs + ' certificados)' : '',
      d.nonce ? '  nonce=' + d.nonce : '')
  }
  if (revoked.length) {
    console.log('Revocados: %d', revoked.length)
    for (const r of revoked) console.log('  · nonce=%s', r.nonce)
  }
  console.log('\nPara revocar uno (y ordenarle autoborrarse):  dotrino-vault revoke <nonce>')
}

/**
 * `dotrino-vault revoke <ID|nonce>` — quita un dispositivo.
 *
 * Con el IDENTIFICADOR del aparato (`AB12-CD34`) se le retiran TODOS sus certificados,
 * que es lo que la gente quiere decir con «quitar este dispositivo»: renovar emite uno
 * nuevo cada 30 días, así que quitar solo el último dejaba vivos los anteriores hasta que
 * caducaran — quitarlo sin quitarlo. Con un `nonce` suelto se retira ese y solo ese, que
 * sigue siendo útil para casos finos.
 */
async function cmdRevoke (arg) {
  if (!arg) { console.error('uso: dotrino-vault revoke <ID|nonce>   (el ID quita el aparato entero)'); process.exit(2) }
  const esId = /^[0-9a-f]{4}-?[0-9a-f]{4}$/i.test(arg)
  const s = requireDaemon()
  if (esId) {
    const m = await findMember(arg.toUpperCase().includes('-') ? arg.toUpperCase() : arg.toUpperCase().replace(/(.{4})(.{4})/, '$1-$2'))
    writeReq('revoke-request.json', { sub: m.pub })
    sendSignal(s.pid, 'SIGUSR2')
    console.log('Quitado %s (todos sus certificados). Se autoborrará al reconectar. Verifica: dotrino-vault devices', m.id)
    return
  }
  writeReq('revoke-request.json', { nonce: arg })
  sendSignal(s.pid, 'SIGUSR2')
  console.log('Revocación enviada para nonce=%s. El dispositivo se autoborrará al reconectar. Verifica: dotrino-vault devices', arg)
}

/**
 * Dir de datos de un perfil (o del activo). Cada perfil tiene el suyo, así que su
 * bitácora también es propia. Cae al dir raíz si el daemon aún es mono-perfil.
 */
function profileDir () {
  const s = readState()
  const list = s.profiles || []
  if (!list.length) return dir // vault anterior al multi-perfil
  const ref = PROFILE ? String(PROFILE).toLowerCase() : null
  const p = ref
    ? list.find((x) => x.id === PROFILE || (x.name || '').toLowerCase() === ref)
    : (list.find((x) => x.current) || list[0])
  if (!p) { console.error('el perfil no existe: %s', PROFILE); process.exit(1) }
  // El candado también aquí: esto es la única puerta que lee el directorio del perfil sin
  // pasar por el daemon (la bitácora), y sin esta línea `activity` seguía contando quién
  // firmó y cuándo con la bóveda cerrada.
  assertOpen(p)
  return path.join(dir, 'p', p.id)
}

// Bitácora de actividad de seguridad (quién firmó/renovó/enroló y qué se rechazó).
function cmdActivity (n = 30) {
  const f = path.join(profileDir(), 'activity.log')
  let lines = []
  try { lines = fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean) } catch {
    console.log('Sin actividad registrada todavía (o el servicio es anterior a 0.1.10).'); return
  }
  const ICON = { sign: '🖊 firma', renew: '♻ renovación', enroll: '➕ enrolado', revoke: '⛔ revocado', rejected: '🚫 RECHAZADO', secrets: '🔑 secretos leídos', 'secret.set': '🔑 secreto guardado', 'secret.rm': '🔑 secreto borrado' }
  for (const line of lines.slice(-n)) {
    try {
      const e = JSON.parse(line)
      const when = new Date(e.ts).toLocaleString()
      const what = ICON[e.op] || e.op
      const extra = [e.device, e.label, e.what, e.ns, e.key, e.reason, e.nonce].filter(Boolean).join(' · ')
      console.log(`${when}  ${what}${extra ? '  ' + extra : ''}`)
    } catch {}
  }
}

// Variables de entorno de los servicios: se cargan aquí (el dueño, en el PC del vault) y
// las leen los SERVICIOS enrolados con `pair --service <ns>`. Nunca se listan valores.
//
// DOS CAJONES: las del SCOPE (`secret set <ns> …`) las comparten todos los aparatos que
// sirven ese namespace; las del APARATO (`secret device set <ID> …`) las lee solo ese
// aparato y PISAN a las del scope con el mismo nombre. Ahí va lo que cambia de máquina a
// máquina (el puerto, la URL pública) sin tener que partir el ns en uno por servidor.
/**
 * `KEY=valor KEY2=valor2` — la forma de CARGAR VARIAS de una vez. Devuelve `null` si no
 * son todos pares, para que la forma clásica de tres argumentos (`set ns CLAVE valor`,
 * donde el valor puede llevar espacios y hasta un `=`) siga funcionando igual.
 */
function asPairs (args) {
  if (!args.length) return null
  const out = []
  for (const a of args) {
    const m = PAIR_RE.exec(a)
    if (!m) return null
    out.push({ op: 'set', key: m[1], value: m[2] })
  }
  return out
}

/** Un `.env` con un problema no se carga A MEDIAS: se dice qué línea y no se escribe nada. */
function abortEnv (errors) {
  console.error('%sNo se cargó nada%s:', R, Z)
  for (const e of errors) console.error('  · %s', envErrorText(e))
  process.exit(2)
}

/** Los códigos del lector de `.env`, en la lengua del CLI. */
function envErrorText (e) {
  if (e.code === 'shape') return `línea ${e.line}: no tiene la forma CLAVE=valor`
  if (e.code === 'key') return `línea ${e.line}: «${e.key}» va en MAYÚSCULAS_CON_GUION_BAJO`
  if (e.code === 'novalue') return `línea ${e.line}: ${e.key} no tiene valor (para quitarla: secret rm)`
  if (e.code === 'dup') return `línea ${e.line}: ${e.key} ya venía en la línea ${e.first}`
  return 'no hay ninguna variable que cargar'
}

/** El problema de una variable, en español, o `null`. Las reglas son las del cajón. */
function problemWith (key, value) {
  try { assertVar(key, value); return null } catch (e) {
    if (/invalid key/.test(e.message)) return 'el nombre va en MAYÚSCULAS_CON_GUION_BAJO (p. ej. TURN_KEY_ID)'
    if (/non-empty/.test(e.message)) return 'no tiene valor (para quitarla: secret rm)'
    if (/too long/.test(e.message)) return 'el valor es demasiado largo'
    return e.message
  }
}

async function cmdSecret (rest) {
  // --public / --private: si el VALOR puede salir de esta máquina hacia la consola remota.
  // Se sacan de la línea antes de partirla, para que puedan ir en cualquier posición y no
  // se cuelen dentro del valor (que es lo último y puede llevar espacios).
  let isPublic
  const rest2 = rest.filter((a) => {
    if (a === '--public') { isPublic = true; return false }
    if (a === '--private') { isPublic = false; return false }
    return true
  })
  const [sub, ...args] = rest2
  const s = requireDaemon()

  /**
   * La contraseña del perfil, y SOLO si el perfil la tiene.
   *
   * Desde v5 la piden únicamente las operaciones que **LEEN** un valor: verlo, cambiarle
   * la visibilidad (para enseñarlo hay que sacarlo), convertir el archivo y saldar lo que
   * quedó a deber. **Guardar no la pide**: sellar solo necesita las públicas de quien va
   * a leer (`docs/secretos-sellados.md` §8.1). Borrar tampoco, porque tirar un sobre no
   * obliga a abrirlo.
   */
  let cachedPwd
  const adminPassword = async () => {
    if (cachedPwd !== undefined) return cachedPwd
    const d = await profileRequest('list')
    const list = Array.isArray(d.profiles) ? d.profiles : []
    const p = PROFILE
      ? list.find((x) => x.id === PROFILE || x.name === PROFILE)
      : (list.find((x) => x.current) || list[0])
    if (!p?.protected) { cachedPwd = null; return null }
    // Nunca por argumento: quedaría en `ps` y en el historial de la shell. Si no hay
    // terminal se dice qué falta, en vez de fallar con «el daemon no aplicó el cambio».
    let pwd
    try { pwd = await askPassword('Contraseña del perfil: ') } catch (_) {
      console.error('Este perfil tiene contraseña y hace falta para guardar una variable.')
      console.error('Ejecútalo desde un terminal (por ssh, con -t).')
      process.exit(1)
    }
    if (!pwd) { console.error('Cancelado.'); process.exit(1) }
    cachedPwd = pwd
    return pwd
  }
  const secretsListFile = path.join(dir, 'secrets-list.json')
  const signalAndWaitList = async () => {
    try { fs.rmSync(secretsListFile, { force: true }) } catch (_) {}
    writeReq('dump-request.json', {}) // de qué perfil son los secretos
    sendSignal(s.pid, 'SIGUSR2')
    for (let i = 0; i < 50; i++) {
      await sleep(100)
      const d = readJson(secretsListFile, null)
      // El volcado lleva el valor de las públicas: se borra en cuanto se tiene, para que no
      // se quede esperando en el disco a que copien la carpeta (ver `daemon.js`).
      if (d?.at) { try { fs.rmSync(secretsListFile, { force: true }) } catch (_) {} ; return assertOpen(d) }
    }
    console.error('El daemon no respondió.'); process.exit(1)
  }
  /**
   * SELLA el almacén: pasa un `secrets.json` v3 (valores que esta bóveda puede leer) a
   * v4 (cada privada cifrada a la llave de su destinatario). Corre UNA vez.
   *
   * Es una operación con nombre propio y no un efecto de desbloquear, porque es el
   * punto de no retorno: a partir de aquí la contraseña es lo ÚNICO que puede
   * re-sellar, y perderla impide rotar una variable o sumar un aparato al namespace.
   * Deja `secrets.json.v3.bak` al lado para poder volver.
   */
  async function secretMigrate () {
    console.log('Esto SELLA las variables privadas a la llave de cada aparato.')
    console.log('A partir de aquí, esta contraseña es lo único que puede volver a sellarlas:')
    console.log('si la pierdes no podrás rotar una variable ni sumar un aparato al namespace.')
    console.log('Se deja una copia en secrets.json.v3.bak por si hay que volver.\n')
    const pwd = await askPassword('Contraseña del perfil: ')
    if (!pwd) { console.error('Cancelado.'); process.exit(1) }
    writeReq('secret-request.json', { op: 'migrate', password: pwd })
    console.log('\nPedido enviado. Mira el resultado con:  journalctl --user -u dotrino-vault -n 20')
  }

  const USAGE = [
    'uso: dotrino-vault secret set <ns> <CLAVE> <valor> [--public|--private]',
    '                                                  (la comparten todos los aparatos del ns)',
    '     dotrino-vault secret set <ns> CLAVE=valor [CLAVE2=valor2 …]   varias DE UNA VEZ',
    '     dotrino-vault secret import <ns> [archivo.env]               desde un .env (o stdin)',
    '     dotrino-vault secret rm  <ns> <CLAVE>',
    '     dotrino-vault secret device set <ID> <CLAVE> <valor> [--public|--private]',
    '                                                  (solo la lee ese aparato, y pisa a la del ns)',
    '     dotrino-vault secret device set <ID> CLAVE=valor [CLAVE2=valor2 …]',
    '     dotrino-vault secret device import <ID> [archivo.env]',
    '     dotrino-vault secret device rm  <ID> <CLAVE>',
    '     dotrino-vault secret list',
    '     dotrino-vault secret migrate                                 SELLA los secretos (una vez)',
    '     dotrino-vault secret policy <ns> approval on|off              cada lectura espera tu aprobación (teléfono)',
    '',
    'CARGA LA CONFIGURACIÓN DE UN SERVICIO DE UNA VEZ (`set` con varios pares, o `import`):',
    'la bóveda la aplica entera y avisa UNA sola vez. De una en una, cada variable es un',
    'cambio de configuración y el servicio se reinicia a media carga.',
    '',
    'Pública o privada dice UNA cosa: si el VALOR puede salir de esta máquina hacia la',
    'consola remota (vault.dotrino.com). Se nace privada. El servicio recibe las dos igual.'
  ].join('\n')

  /**
   * Manda un grupo entero al daemon y comprueba que llegó completo.
   *
   * Se valida TODO aquí antes de escribir nada: si una variable del archivo está mal, no
   * se carga ninguna. Media configuración aplicada es peor que ninguna, porque el
   * servicio arranca con ella y parece que funcionó.
   */
  const sendBatch = async ({ ns = null, pub = null, items, where }) => {
    const bad = items.map((it) => [it.key, problemWith(it.key, it.value)]).filter(([, p]) => p)
    if (bad.length) {
      console.error('%sNo se cargó nada%s. Revisa:', R, Z)
      for (const [key, p] of bad) console.error('  · %s: %s', key, p)
      process.exit(2)
    }
    const withVisibility = items.map((it) => (isPublic === undefined ? it : { ...it, public: isPublic }))
    // Guardar NO pide la contraseña (§8.1).
    const base = pub ? { op: 'batch', pub, items: withVisibility } : { op: 'batch', ns, items: withVisibility }
    writeReq('secret-request.json', base)
    const d = await signalAndWaitList()
    const list = pub
      ? ((Array.isArray(d.dev) ? d.dev : []).find((x) => x.pub === pub)?.keys || [])
      : (d.ns?.[ns] || [])
    const missing = items.filter((it) => !has(list, it.key)).map((it) => it.key)
    if (missing.length) {
      if (d?.secretError) return noSeAplico(d)
      console.error('El daemon no guardó: %s (revisa: dotrino-vault logs)', missing.join(', '))
      process.exit(1)
    }
    console.log('%d variables guardadas en %s%s%s%s', items.length, B, where, Z,
      isPublic === undefined ? '' : isPublic ? '   (públicas)' : '   (privadas)')
    console.log('Un solo aviso de cambio: el servicio se reinicia una vez, con todo puesto.')
  }

  /** El texto del `.env`: de un archivo, o de la entrada estándar si no se da ninguno. */
  const readEnvText = (file) => {
    if (file) {
      try { return fs.readFileSync(file, 'utf8') } catch (e) {
        console.error('No se pudo leer %s: %s', file, e.message); process.exit(1)
      }
    }
    if (process.stdin.isTTY) {
      console.error('%s\n\nimport necesita un archivo, o el .env por la entrada estándar:', USAGE)
      console.error('  dotrino-vault secret import proxy .env')
      console.error('  cat .env | dotrino-vault secret import proxy')
      process.exit(2)
    }
    return fs.readFileSync(0, 'utf8')
  }

  /**
   * Una variable en la lista: su nombre y su valor. La PÚBLICA enseña el suyo (pública
   * quiere decir que ese valor puede salir de esta máquina: taparlo aquí, delante de su
   * dueño, era lo único que la marca no significaba). La privada no se muestra.
   */
  const printVar = (k) => console.log('  · %s   %s', k.key, k.public ? `${k.value ?? ''}   (pública)` : '••••••')
  /**
   * Por qué no se aplicó. El daemon deja el motivo en el volcado siguiente; sin él lo
   * único que se podía decir era «revisa los logs», que no ayuda a quien acaba de
   * escribir mal la contraseña.
   */
  const noSeAplico = (d) => {
    if (d?.secretError?.code === 'WRONG_PASSWORD') console.error('Contraseña incorrecta.')
    else if (d?.secretError?.error) console.error('No se aplicó: %s', d.secretError.error)
    else console.error('El daemon no aplicó el cambio (revisa: dotrino-vault logs)')
    process.exit(1)
  }
  const has = (list, key) => (list || []).some((x) => x.key === key)
  /**
   * Los cajones que quedaron a deber un sellado. Sale ARRIBA del todo en rojo porque no
   * es un detalle: mientras esté ahí, los aparatos de ese cajón NO están leyendo sus
   * variables, y la bóveda no puede arreglarlo sola — necesita la contraseña.
   */
  /**
   * Un perfil SIN contraseña abre sus variables privadas con la llave de esta máquina,
   * cuyo material vive en este mismo disco: una copia del disco las abre. Es un default
   * deliberado —tiene que seguir funcionando— pero NO es lo mismo, y callarlo es
   * exactamente el error del comentario mentiroso de `atrest.js`.
   */
  const printNoPassword = async () => {
    const d = await profileRequest('list')
    const list = Array.isArray(d.profiles) ? d.profiles : []
    const p = PROFILE ? list.find((x) => x.id === PROFILE || x.name === PROFILE) : (list.find((x) => x.current) || list[0])
    if (!p || p.protected) return
    console.log('%sEste perfil no tiene contraseña%s: las privadas se abren con la llave de ESTA', B, Z)
    console.log('máquina, cuyo material vive en este mismo disco — o sea que una copia del disco')
    console.log('las abre. Ponle una con:  dotrino-vault profile password\n')
  }
  const printPending = (d) => {
    const pend = Object.entries(d?.pending || {})
    if (!pend.length) return
    console.error('%sHay %d cajón(es) sin sellar%s:', R, pend.length, Z)
    for (const [owner, info] of pend) {
      console.error('  · %s — %s', owner, info?.kind === 'rotate'
        ? 'se fue un miembro y no se pudo rotar su llave'
        : 'entró un aparato y no se le pudo entregar la llave')
    }
    console.error('Sus aparatos NO leen sus variables. Se arregla guardando una variable')
    console.error('de ese cajón con la contraseña:  dotrino-vault secret set <ns> <CLAVE> <valor>\n')
  }

  if (sub === 'migrate') return secretMigrate()
  // `secret policy <ns> approval on|off`: el cajón pasa a pedir el visto bueno de un
  // aparato con `aprueba` (el teléfono) en cada lectura, con ventana de 15 min.
  if (sub === 'policy') {
    const [ns, what, val] = args
    if (!isValidSecretsNs(ns || '') || what !== 'approval' || !['on', 'off'].includes(val)) {
      console.error('uso: dotrino-vault secret policy <ns> approval on|off'); process.exit(2)
    }
    writeReq('secret-request.json', { op: 'policy', ns, approval: val === 'on' })
    sendSignal(s.pid, 'SIGUSR2')
    console.log(val === 'on'
      ? `Listo: cada lectura de «${ns}» esperará la aprobación de un aparato con  caps <ID> +aprueba  (ventana de 15 min).`
      : `Listo: «${ns}» vuelve a entregarse sin aprobación.`)
    return
  }

  // --- VER un valor, su histórico y volver atrás ---------------------------------
  // Las tres van juntas porque son la misma idea: ver es lo único que la contraseña
  // guarda, y revertir es ver + volver a guardar (§8.3/§8.4).
  const ownerDe = async (kind, ref) => {
    if (kind === 'ns') return `ns:${ref}`
    const m = await findMember(ref)
    return `dev:${m.pub}`
  }

  if (sub === 'show' || sub === 'history' || sub === 'revert') {
    // `secret show device <ID> <CLAVE>` mira el cajón de un aparato.
    const esDev = args[0] === 'device'
    const [ref, key, extra] = esDev ? args.slice(1) : args
    if (!ref || (sub !== 'history' && !key)) {
      console.error('uso: dotrino-vault secret %s [device] <ns|ID> <CLAVE>%s', sub, sub === 'revert' ? ' <marca>' : '')
      process.exit(2)
    }
    const owner = await ownerDe(esDev ? 'dev' : 'ns', ref)

    if (sub === 'history') {
      writeReq('secret-request.json', { op: 'history', owner, key: key || null })
      const d = await signalAndWaitList()
      const items = d.history?.items || []
      if (!items.length) { console.log('No hay versiones anteriores de %s%s.', owner, key ? `/${key}` : ''); return }
      console.log('\n%sVersiones anteriores%s  (la de arriba es la más reciente)\n', B, Z)
      for (const h of items) {
        // Sin `by` no es que falte un dato: es que se escribió AQUÍ, desde esta máquina.
        // Lo que llega por la consola remota sí trae de qué aparato vino.
        console.log('  %s  %s%s%s  %s%s', new Date(h.ts).toISOString(), B, h.key, Z,
          h.by ? `desde ${h.by.slice(0, 12)}…` : 'desde esta máquina', h.signed ? '' : '   (sobre sin firma)')
      }
      console.log('\nPara volver a una:  dotrino-vault secret revert %s%s <CLAVE> <marca>\n',
        esDev ? 'device ' : '', ref)
      return
    }

    if (sub === 'revert') {
      if (!extra) { console.error('uso: dotrino-vault secret revert [device] <ns|ID> <CLAVE> <marca>'); process.exit(2) }
      const ts = Number.isFinite(Number(extra)) ? Number(extra) : Date.parse(extra)
      if (!Number.isFinite(ts)) { console.error('La marca es la que enseña `secret history` (fecha ISO).'); process.exit(2) }
      const password = await adminPassword()
      writeReq('secret-request.json', { op: 'revert', owner, key, ts, ...(password ? { password } : {}) })
      const d = await signalAndWaitList()
      if (d?.secretError) return noSeAplico(d)
      console.log('Restaurada: %s/%s', owner, key)
      return
    }

    // `show`: el valor. Es lo único que la contraseña guarda en esta máquina.
    const password = await adminPassword()
    writeReq('secret-request.json', { op: 'reveal', owner, key, ...(password ? { password } : {}) })
    const d = await signalAndWaitList()
    if (d?.secretError) return noSeAplico(d)
    if (d.revealed?.owner !== owner || d.revealed?.key !== key) {
      console.error('El daemon no devolvió el valor (revisa: dotrino-vault logs)')
      process.exit(1)
    }
    if (d.revealed.value == null) { console.error('No existe esa variable.'); process.exit(1) }
    console.log(d.revealed.value)
    return
  }

  // Saldar lo que quedó a deber: heredarle a un aparato lo ya guardado, rotar de verdad.
  if (sub === 'settle') {
    const password = await adminPassword()
    writeReq('secret-request.json', { op: 'settle', ...(password ? { password } : {}) })
    const d = await signalAndWaitList()
    if (d?.secretError) return noSeAplico(d)
    const pend = Object.keys(d.pending || {})
    if (!pend.length) console.log('Nada pendiente.')
    else console.log('Siguen pendientes: %s', pend.join(', '))
    return
  }

  if (sub === 'list') {
    const d = await signalAndWaitList()
    const names = d.ns || {}
    const nss = Object.keys(names)
    const dev = Array.isArray(d.dev) ? d.dev : []
    if (!nss.length && !dev.length) {
      console.log('No hay variables guardadas. Agrega una:  dotrino-vault secret set <ns> <CLAVE> <valor>')
      return
    }
    if (nss.length) console.log('\n%sPor scope%s (las comparten todos los aparatos del perfil)\n', B, Z)
    for (const n of nss) {
      console.log('%s%s%s  (scope vault:secrets:%s)', B, n, Z, n)
      for (const k of names[n]) printVar(k)
    }
    if (dev.length) console.log('\n%sPor aparato%s (solo las lee ese aparato; pisan a las del scope)\n', B, Z)
    for (const x of dev) {
      const who = [x.label, x.cn ? `servicio «${x.cn}»` : null, x.orphan ? 'YA NO ESTÁ EN EL ACTA' : null].filter(Boolean).join(' · ')
      console.log('%s%s%s%s', B, x.id, Z, who ? '  ' + who : '')
      for (const k of x.keys) printVar(k)
    }
    console.log('\n(pública) = su valor se puede ver desde la consola remota. Las demás no salen de aquí.\n')
    printPending(d)
    await printNoPassword()
    return
  }

  // Por APARATO: `secret device set|rm|visibility <ID> <CLAVE> [valor|public|private]`.
  if (sub === 'device') {
    const [op, id, key, ...valueParts] = args
    const value = valueParts.join(' ')
    const ops = ['set', 'rm', 'visibility', 'import']
    const asGroup = op === 'import' || (op === 'set' && !!asPairs(args.slice(2)))
    if (!ops.includes(op) || !id || (!asGroup && (!key || (op === 'set' && !value)))) { console.error(USAGE); process.exit(2) }
    const m = await findMember(id)
    // Se avisa aquí, con nombre y apellido, en vez de dejar que el daemon lo rechace y la
    // CLI diga «no aplicó el cambio»: quien escribe esto quiere saber POR QUÉ no vale.
    if (!m.cn) {
      console.error('%s no es un servicio, y solo los servicios leen variables.', m.id)
      console.error('Empareja el servicio con:  dotrino-vault pair --service <ns>')
      process.exit(1)
    }
    if (op === 'import') {
      const { items, errors } = parseEnvText(readEnvText(args[2]))
      if (errors.length) return abortEnv(errors)
      return sendBatch({ pub: m.pub, items, where: m.id })
    }
    if (asGroup) return sendBatch({ pub: m.pub, items: asPairs(args.slice(2)), where: m.id })
    if (key && PAIR_RE.test(key) && args.length > 3) {
      console.error('%s\n\nO todos los argumentos son CLAVE=valor, o es una sola variable.', USAGE)
      process.exit(2)
    }
    const req = op === 'set'
      ? { op: 'dev-set', pub: m.pub, key, value, ...(isPublic === undefined ? {} : { public: isPublic }) }
      : op === 'rm'
        ? { op: 'dev-rm', pub: m.pub, key }
        : { op: 'dev-vis', pub: m.pub, key, public: wantsPublic(value, USAGE) }
    // Solo la visibilidad pide la frase: enseñar un valor obliga a sacarlo.
    const password = op === 'vis' ? await adminPassword() : null
    writeReq('secret-request.json', password ? { ...req, password } : req)
    const d = await signalAndWaitList()
    const keys = (Array.isArray(d.dev) ? d.dev : []).find((x) => x.pub === m.pub)?.keys || []
    const ok = op === 'rm' ? !has(keys, key) : has(keys, key)
    if (!ok) return noSeAplico(d)
    if (op === 'rm') console.log('Variable borrada: %s/%s', m.id, key)
    else console.log('Variable guardada: %s/%s%s', m.id, key, (keys.find((x) => x.key === key)?.public) ? '   (pública)' : '')
    return
  }

  // Desde un `.env`: el caso real de estrenar un servicio, y el que de una en una
  // reiniciaba al agente una vez por variable.
  if (sub === 'import') {
    const [ns, file] = args
    if (!ns) { console.error(USAGE); process.exit(2) }
    const { items, errors } = parseEnvText(readEnvText(file))
    if (errors.length) return abortEnv(errors)
    return sendBatch({ ns, items, where: ns })
  }

  if (sub === 'set' || sub === 'rm' || sub === 'visibility') {
    const [ns, key, ...valueParts] = args
    const value = valueParts.join(' ')
    // `set <ns> CLAVE=valor CLAVE2=valor2` — varias de una vez, un solo aviso.
    const pairs = sub === 'set' ? asPairs(args.slice(1)) : null
    if (ns && pairs) return sendBatch({ ns, items: pairs, where: ns })
    // Mezclar las dos formas (`K1=v1 CLAVE valor`) no es ninguna de las dos: mejor
    // decirlo que guardar una variable llamada «K1=v1».
    if (sub === 'set' && key && PAIR_RE.test(key) && args.length > 2) {
      console.error('%s\n\nO todos los argumentos son CLAVE=valor, o es una sola variable: set <ns> <CLAVE> <valor>.', USAGE)
      process.exit(2)
    }
    if (!ns || !key || (sub === 'set' && !value)) { console.error(USAGE); process.exit(2) }
    const req = sub === 'set'
      ? { op: 'set', ns, key, value, ...(isPublic === undefined ? {} : { public: isPublic }) }
      : sub === 'rm'
        ? { op: 'rm', ns, key }
        : { op: 'vis', ns, key, public: wantsPublic(value, USAGE) }
    // Solo la visibilidad pide la frase: enseñar un valor obliga a sacarlo.
    const password = sub === 'visibility' ? await adminPassword() : null
    writeReq('secret-request.json', password ? { ...req, password } : req)
    const d = await signalAndWaitList()
    const list = d.ns?.[ns] || []
    const ok = sub === 'rm' ? !has(list, key) : has(list, key)
    if (!ok) return noSeAplico(d)
    if (sub === 'rm') console.log('Secreto borrado: %s/%s', ns, key)
    else console.log('Secreto guardado: %s/%s%s', ns, key, (list.find((x) => x.key === key)?.public) ? '   (pública)' : '')
    return
  }
  console.error(USAGE); process.exit(2)
}

/** `visibility … public|private` — el único argumento que acepta, y sin adivinar. */
function wantsPublic (word, usage) {
  if (word === 'public') return true
  if (word === 'private') return false
  console.error('%s\n\nvisibility acepta «public» o «private».', usage); process.exit(2)
}

/**
 * Lee una contraseña del terminal SIN eco. Nunca se pasa como argumento: quedaría
 * en `ps` y en el historial de la shell.
 */
function askPassword (prompt) {
  return new Promise((resolve, reject) => {
    // Se lee del TERMINAL, no de la entrada estándar. `secret import` ya usa stdin para
    // el `.env` (`cat .env | dotrino-vault secret import proxy`) y aun así hay que poder
    // escribir la contraseña; lo mismo vale para cualquier tubería.
    let stdin = process.stdin
    let own = null
    if (!stdin.isTTY) {
      try {
        own = fs.openSync('/dev/tty', 'r')
        stdin = new tty.ReadStream(own)
      } catch (_) { return reject(new Error('a terminal is required to type the password')) }
    }
    process.stdout.write(prompt)
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8')
    let buf = ''
    const done = (err, val) => {
      try { stdin.setRawMode(false) } catch (_) {}
      stdin.removeListener('data', onData)
      if (own !== null) { try { stdin.destroy() } catch (_) {} } else stdin.pause()
      process.stdout.write('\n')
      err ? reject(err) : resolve(val)
    }
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\n' || c === '\r' || c === '\u0004') return done(null, buf) // Enter / Ctrl-D
        if (c === '\u0003') return done(new Error('cancelled')) // Ctrl-C
        if (c === '\u007f' || c === '\b') { buf = buf.slice(0, -1); continue } // borrar
        buf += c
      }
    }
    stdin.on('data', onData)
  })
}

/**
 * Manda una orden de perfil/candado al daemon y espera su volcado. La contraseña
 * (si la hay) viaja por un archivo 0600 dentro del dir 0700 del vault, que el
 * daemon borra al leerlo — mismo camino que ya usan los secretos.
 */
async function profileRequest (op, extra = {}) {
  const s = requireDaemon()
  try { fs.rmSync(profilesFile, { force: true }) } catch (_) {}
  writeReq('profile-request.json', { op, ...extra })
  sendSignal(s.pid, 'SIGUSR2')
  for (let i = 0; i < 100; i++) {
    await sleep(100)
    const d = readJson(profilesFile, null)
    if (d?.at) return d
  }
  console.error('El daemon no respondió.'); process.exit(1)
}

function reportProfiles (d) {
  if (d.error) {
    // Los dos rechazos del candado se dicen con palabras y con el dato que hace falta; el
    // resto se reenvía tal cual (son diagnósticos del servicio).
    if (d.code === 'WRONG_PASSWORD') console.error('Contraseña incorrecta%s.', d.tries ? ` — van ${d.tries} intentos fallidos` : '')
    else if (d.code === 'TOO_MANY_TRIES') console.error('Demasiados intentos: espera %s s antes de volver a probar.', d.waitSec || '?')
    else console.error('%s', d.error)
    process.exit(1)
  }
  if (d.done) console.log('%s', d.done)
  return d
}

async function cmdProfile (rest) {
  const [sub, ...args] = rest
  const name = args.join(' ').trim()
  switch (sub || 'ls') {
    case 'ls': {
      const d = await profileRequest('list')
      console.log('Perfiles del vault: %d', d.profiles.length)
      for (const p of d.profiles) console.log('  %s %s', p.current ? '*' : ' ', describeProfile(p))
      console.log('\nEl * es el perfil activo (el destino por defecto). Todos atienden a sus dispositivos a la vez.')
      console.log('Apunta un comando a otro:  dotrino-vault <comando> --profile <id|nombre>')
      return
    }
    case 'add': {
      if (!name) { console.error('uso: dotrino-vault profile add <nombre>'); process.exit(2) }
      reportProfiles(await profileRequest('add', { name }))
      console.log('Conecta un dispositivo a este perfil:  dotrino-vault pair --profile "%s"', name)
      return
    }
    case 'rename': {
      if (!name) { console.error('uso: dotrino-vault profile rename <nombre nuevo>   (usa --profile para elegir cuál)'); process.exit(2) }
      reportProfiles(await profileRequest('rename', { name }))
      return
    }
    case 'use': {
      const ref = name || PROFILE
      if (!ref) { console.error('uso: dotrino-vault profile use <id|nombre>'); process.exit(2) }
      reportProfiles(await profileRequest('use', { profile: ref }))
      return
    }
    case 'rm': {
      const ref = name || PROFILE
      if (!ref) { console.error('uso: dotrino-vault profile rm <id|nombre>'); process.exit(2) }
      const d = await profileRequest('list')
      const p = d.profiles.find((x) => x.id === ref || (x.name || '').toLowerCase() === ref.toLowerCase())
      if (!p) { console.error('el perfil no existe: %s', ref); process.exit(1) }
      console.log('\n%s%sEsto BORRA la identidad del perfil "%s" y todos sus datos.%s', R, B, p.name || p.id, Z)
      console.log('%s  Es irreversible: se pierde su clave, y sus dispositivos dejan de funcionar.%s', R, Z)
      const typed = await askText(`\nEscribe el nombre del perfil para confirmar (${p.name || p.id}): `)
      if (typed.trim() !== (p.name || p.id)) { console.log('Cancelado (no coincide).'); return }
      reportProfiles(await profileRequest('rm', { profile: p.id }))
      return
    }
    case 'password': {
      const action = args[0]
      // QUITARLA pide la actual, y no por trámite: con ella se abre la copia maestra de
      // los secretos para volver a cerrarla con la llave de esta máquina. Sin ese paso,
      // quitar la contraseña dejaría las variables privadas ilegibles para siempre.
      if (action === 'rm') {
        console.log('Al quitarla, las variables privadas pasan a abrirse con la llave de ESTA')
        console.log('máquina: siguen cifradas en el disco, pero su material vive en ese mismo')
        console.log('disco, así que una copia del disco las abre. Los aparatos no se enteran.')
        const cur = await askPassword('\nContraseña actual: ')
        if (!cur) { console.error('Cancelado.'); process.exit(1) }
        reportProfiles(await profileRequest('password-rm', { password: cur }))
        return
      }
      if (action && action !== 'set') { console.error('uso: dotrino-vault profile password [set|rm]'); process.exit(2) }
      console.log('La contraseña se pide para EDITAR el perfil y para escribir variables')
      console.log('privadas. Tus dispositivos siguen funcionando (firmando, leyendo y')
      console.log('recibiendo su configuración) aunque el perfil esté bloqueado.')
      // Si ya hay una, hace falta para poder abrir la copia maestra y re-sellarla. El
      // camino recomendado para CAMBIARLA es quitarla y ponerla: así cada paso pide
      // solo lo que necesita.
      const actual = await askPassword('\nContraseña actual (vacío si no tiene): ')
      // Se pide una FRASE, y se dice cómo sacarla, porque lo que da fuerza es la
      // longitud y que no la elija un humano: un modismo tiene la entropía de un
      // modismo, no la de su longitud. Desde el sellado, esta frase es lo único que
      // separa una copia del disco de las variables privadas.
      console.log('\nUsa VARIAS PALABRAS AL AZAR (mínimo 12 caracteres). Para que las elija')
      console.log('la máquina y no tú:')
      console.log("  grep -x '[a-z]\\{4,8\\}' /usr/share/dict/words | shuf -n5 | paste -sd-")
      const pwd = await askPassword('\nContraseña nueva: ')
      const again = await askPassword('Repítela: ')
      if (pwd !== again) { console.error('Las contraseñas no coinciden.'); process.exit(1) }
      reportProfiles(await profileRequest('password-set', { password: pwd, current: actual || undefined }))
      return
    }
    default:
      console.error('uso: dotrino-vault profile {ls|add|rename|use|rm|password}'); process.exit(2)
  }
}

/** Lee una línea del terminal (con eco): confirmaciones. */
function askText (prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt)
    process.stdin.resume(); process.stdin.setEncoding('utf8')
    process.stdin.once('data', (d) => { process.stdin.pause(); resolve(String(d).replace(/\n$/, '')) })
  })
}

async function cmdUnlock () {
  const pwd = await askPassword('Contraseña del perfil: ')
  reportProfiles(await profileRequest('unlock', { password: pwd }))
  console.log('Ya puedes editar el perfil. Se vuelve a bloquear al reiniciar el servicio (o con: dotrino-vault lock).')
}

async function cmdLock () {
  reportProfiles(await profileRequest('lock'))
}

function cmdLogs () {
  try { process.stdout.write(execFileSync('journalctl', ['--user', '-u', 'dotrino-vault', '-n', '40', '--no-pager'], { encoding: 'utf8' })) }
  catch { console.error('No se pudieron leer los logs. Prueba:  journalctl --user -u dotrino-vault -f') }
}

// Import dinámico: así `dotrino-vault status` (el caso común) no carga la TUI.
async function cmdTui () {
  if (!process.stdout.isTTY) { console.error('la TUI necesita un terminal interactivo (TTY).'); process.exit(2) }
  const { runTui } = await import('./tui/app.js')
  await runTui()
}

function help () {
  console.log(`dotrino-vault — control del certificador personal

  tui                 interfaz de terminal a pantalla completa (bóvedas, pares, secretos)
  status              estado del servicio + fingerprint
  pair [--save <f>]   inicia un emparejamiento (QR + espera); --save escribe la invitación (.dpair)
  pair --new-account [nombre]
                      estrena una cuenta VACÍA en este vault y mete ahí al dispositivo
                      (sin la bandera entra a la cuenta activa, o a la de --profile)
  pair --service <ns> empareja un SERVICIO (proxy, geo…) con acceso SOLO a sus secretos
  pair --scope <lista>  los PERMISOS del cert: sign,read,store,secrets:<ns> (sin esto: sign,read,store;
                      se combina con --service: --service eco --scope sign = bot que firma y lee su cajón)
  secret set <ns> <CLAVE> <valor>   variable del scope <ns>: la comparten TODOS los
                                    aparatos del perfil que sirven ese namespace
  secret set <ns> CLAVE=valor CLAVE2=valor2 …
                                    carga VARIAS de una vez: se aplican juntas y el
                                    servicio recibe UN solo aviso (se reinicia una vez)
  secret import <ns> [archivo.env]  lo mismo desde un .env (o por la entrada estándar)
  secret rm <ns> <CLAVE>            borra una variable del scope
  secret device set <ID> <CLAVE> <valor>
                                    variable de UN aparato: solo la lee él, y pisa a la
                                    del scope que se llame igual (puerto, URL pública…)
  secret device set <ID> CLAVE=valor …
  secret device import <ID> [archivo.env]
  secret device rm <ID> <CLAVE>     borra una variable de ese aparato
  secret list                       lista los dos cajones: el valor de las públicas,
                                    tapadas las privadas
  secret show [device] <ns|ID> <CLAVE>
                                    VE el valor de una privada. Es lo único que pide la
                                    contraseña del perfil: en esta máquina es lo único
                                    que la separa de una copia del disco
  secret history [device] <ns|ID> [CLAVE]
                                    las versiones anteriores (quién y cuándo)
  secret revert [device] <ns|ID> <CLAVE> <marca>
                                    vuelve a una versión anterior
  secret settle                     salda lo pendiente: hereda lo ya guardado a un
                                    aparato nuevo y rota de verdad el cajón del que se fue
  --public | --private              (al hacer un set) si el VALOR puede salir de esta
                                    máquina hacia la consola remota. Se nace privada,
                                    y una privada NO se vuelve pública (bórrala y créala).
  secret visibility <ns> <CLAVE> private               tapa una pública sin tocar el valor
  secret device visibility <ID> <CLAVE> private
  pending             muestra el dispositivo pendiente + su código a comparar
  approve <código>    aprueba el dispositivo tipeando el código que MUESTRA (el vault no lo sabe)
  reject <deviceId>   rechaza un dispositivo pendiente
  devices             lista dispositivos enrolados / revocados
  me                  tu perfil (nombre, foto, datos) tal como lo tiene la bóveda
  members             el acta del perfil: quién es tuyo y qué puede hacer
  label <ID> <nombre> renombra un dispositivo (el nombre con el que lo reconoces)
  caps <ID> ±permiso  cambia permisos (+firma -guarda +administra …)
  revoke <ID|nonce>   quita un dispositivo (con el ID, todos sus certificados)
  activity [n]        bitácora de seguridad: firmas, renovaciones, enrolados, rechazos
  logs                últimos logs del servicio
  version             muestra la versión instalada

Perfiles (varias identidades tuyas en el mismo PC; todas atienden a la vez):
  profile ls                        lista los perfiles (* = el activo, el destino por defecto)
  profile add <nombre>              crea un perfil (identidad nueva, vacía)
  profile use <id|nombre>           elige el perfil activo
  profile rename <nombre>           renombra un perfil
  profile rm <id|nombre>            BORRA un perfil y su identidad (irreversible)
  --profile <id|nombre>             apunta CUALQUIER comando a otro perfil
                                    (p.ej. dotrino-vault pair --profile trabajo)

Contraseña del perfil (opcional; solo se pide para EDITAR el perfil — tus
dispositivos siguen firmando y leyendo aunque esté bloqueado):
  profile password [set]            pone o cambia la contraseña
  profile password rm               la quita
  unlock                            desbloquea para poder editar
  lock                              vuelve a bloquear (también al reiniciar el servicio)

Arrancar y parar, según dónde corra:
  Linux (servicio)  systemctl --user {start,stop,restart} dotrino-vault
                    journalctl --user -u dotrino-vault -f
  Windows / macOS   dotrino-vaultd     (o sin instalar nada: npx -y @dotrino/vaultd)
  Docker            docker {start,stop,restart} dotrino-vault · docker logs -f dotrino-vault
                    (el CLI, dentro:  docker exec -it dotrino-vault dotrino-vault status)`)
}

export async function runCtl (argv) {
  const [cmd, ...rest] = takeProfileFlag(argv)
  switch (cmd) {
    case 'tui': return cmdTui()
    case 'profile': return cmdProfile(rest)
    case 'unlock': return cmdUnlock()
    case 'lock': return cmdLock()
    case 'status': return cmdStatus()
    case 'pair': return cmdPair(rest)
    case 'pending': return cmdPending()
    case 'approve': return cmdApprove(rest[0])
    case 'reject': return cmdReject(rest[0])
    case 'devices': return cmdDevices()
    case 'me': return cmdMe()
    case 'members': return cmdMembers()
    case 'label': return cmdLabel(rest)
    case 'caps': return cmdCaps(rest)
    case 'revoke': return cmdRevoke(rest[0])
    case 'secret': return cmdSecret(rest)
    case 'activity': return cmdActivity(Number(rest[0]) || 30)
    case 'logs': return cmdLogs()
    case 'version':
    case '--version':
    case '-v': console.log('dotrino-vault ' + VERSION); return
    case undefined:
    case 'help':
    case '--help':
    case '-h': return help()
    default:
      console.error('comando desconocido: %s', cmd); help(); process.exit(2)
  }
}
