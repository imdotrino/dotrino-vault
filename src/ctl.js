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
import { pubkeyId } from '@dotrino/identity/capabilities'
import { dataDir, readJson } from './paths.js'
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
const writeReq = (name, obj) => fs.writeFileSync(path.join(dir, name), JSON.stringify(withProfile({ ...obj, at: Date.now() })), { mode: 0o600 })

const R = '\x1b[31m', B = '\x1b[1m', Z = '\x1b[0m' // rojo / negrita / reset
// La versión se inyecta en build (esbuild --define); en dev cae a 'dev'.

/**
 * Cómo se arranca el vault EN ESTA MÁQUINA. El CLI corre en Linux (servicio systemd),
 * en Windows/macOS (por npm, en primer plano o al inicio de sesión) y dentro de un
 * contenedor, así que decir siempre «systemctl» manda a la mitad de la gente a un
 * comando que no existe.
 */
const EN_DOCKER = !!process.env.DOTRINO_IN_DOCKER
const START_HINT = EN_DOCKER
  ? 'docker start dotrino-vault'
  : process.platform === 'linux'
    ? 'systemctl --user start dotrino-vault'
    : 'dotrino-vaultd   (o: npx -y @dotrino/vaultd)'
const RESTART_HINT = EN_DOCKER
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
function avisar (pid, sig) { try { process.kill(pid, sig) } catch (_) { /* Windows, o el daemon ya se enteró */ } }
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
  writeReq('pair-request.json', { ...(service ? { service } : {}), ...(adopt ? { mode: 'adopt' } : {}) })
  avisar(s.pid, 'SIGUSR1')

  let pair = null
  for (let i = 0; i < 50; i++) { await sleep(100); const p = readJson(pairFile, null); if (p?.expiresAt > Date.now()) { pair = p; break } }
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
  avisar(s.pid, 'SIGUSR2')
  console.log('Aprobando con el código %s… verifica con: dotrino-vault devices', code)
}

function cmdReject (deviceId) {
  if (!deviceId) { console.error('uso: dotrino-vault reject <deviceId>'); process.exit(2) }
  const s = requireDaemon()
  writeReq('reject-request.json', { deviceId })
  avisar(s.pid, 'SIGUSR2')
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
  avisar(s.pid, 'SIGUSR2')
  let dump = null
  for (let n = 0; n < 50; n++) { await sleep(100); const d = readJson(meFile, null); if (d?.at) { dump = d; break } }
  // El volcado es contenido del usuario: se lee y se BORRA, no se queda ahí suelto.
  try { fs.rmSync(meFile, { force: true }) } catch (_) {}
  if (!dump) { console.error('La bóveda no respondió. ¿Está corriendo?  dotrino-vault status'); process.exit(1) }

  const me = dump.me
  if (!me) {
    console.log('\nTodavía no hay perfil en esta bóveda.')
    console.log('Edita tu nombre o tu foto en un dispositivo emparejado y vuelve a mirar.\n')
    return
  }

  const cuando = me.updatedAt ? new Date(me.updatedAt).toLocaleString() : '—'
  console.log('\n%sPerfil%s · actualizado %s\n', B, Z, cuando)
  console.log('  nombre      : %s', me.nickname || '(sin nombre)')
  console.log('  foto        : %s', me.avatar
    ? `sí · ${me.avatar.type || 'desconocido'} · ${(me.avatar.bytes / 1024).toFixed(1)} KB`
    : 'no')

  // Los campos estándar. `visible` es del usuario: teléfono y dirección nacen ocultos.
  const STD = [['nombres', 'nombres'], ['apellidos', 'apellidos'], ['email', 'correo'],
    ['telefono', 'teléfono'], ['direccion', 'dirección']]
  const puestos = STD.filter(([k]) => me[k])
  if (puestos.length) {
    console.log('')
    for (const [k, etiqueta] of puestos) {
      console.log('  %s: %s%s', etiqueta.padEnd(12), me[k], me[k + 'Visible'] === false ? '   (oculto)' : '')
    }
  }
  for (const [titulo, lista] of [['Enlaces', me.links], ['Otros datos', me.fields]]) {
    if (!Array.isArray(lista) || !lista.length) continue
    console.log('\n  %s:', titulo)
    for (const x of lista) console.log('    %s %s%s', (x.type || x.label || '').padEnd(12), x.value, x.visible === false ? '   (oculto)' : '')
  }

  console.log('')
}

/**
 * `dotrino-vault members` — el ACTA del perfil: qué llaves son tuyas y qué puede hacer cada
 * una. Es la misma información que muestra la consola de vault.dotrino.com.
 */
async function cmdMembers () {
  const s = requireDaemon()
  const actaFile = path.join(dataDir(), 'acta.json')
  try { fs.rmSync(actaFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {})
  avisar(s.pid, 'SIGUSR2')
  let acta = null
  for (let i = 0; i < 50; i++) { await sleep(100); const a = readJson(actaFile, null); if (a?.at) { acta = a; break } }
  if (!acta) { console.error('El daemon no respondió.'); process.exit(1) }
  if (!acta.members?.length) { console.log('Este perfil todavía no tiene acta.'); return }

  const CAP = { sign: 'firma', store: 'guarda', read: 'lee', secrets: 'lee sus claves', admin: `${B}administra el perfil${Z}` }
  // El nombre del perfil es una pubkey JWK. Recortarla no la hace legible: la deja
  // pareciendo un error (`{"key_ops":["verify"],"e…`). Se muestra su huella corta, la
  // misma que se enseña al emparejar y en la lista de miembros.
  const perfilId = await deviceIdOf(acta.profileId).catch(() => '????-????')
  console.log('\n%sPerfil%s %s · acta #%d\n', B, Z, perfilId, acta.seq)
  for (const m of acta.members) {
    const quien = m.label || m.id
    const marcas = [
      m.isMaster ? `${B}Master${Z}` : null,
      m.isMe ? 'este dispositivo' : null,
      m.cn ? `servicio «${m.cn}»` : null
    ].filter(Boolean)
    const caps = m.caps.length ? m.caps.map((c) => CAP[c] || c).join(', ') : '(sin permisos)'
    console.log('  %s  %s%s\n      %s', m.id, quien, marcas.length ? '  [' + marcas.join(' · ') + ']' : '', caps)
  }
  console.log('\n  Cambiar permisos:  dotrino-vault caps <ID> +firma | -firma | +guarda | -guarda | +lee | -lee | +administra')
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
  const [id, ...resto] = args
  const nombre = resto.join(' ').trim()
  if (!id || !nombre) {
    console.error('uso: dotrino-vault label <ID> <nombre>   (p.ej. label AB12-CD34 "Teléfono de casa")')
    process.exit(2)
  }
  const m = await buscarMiembro(id)
  writeReq('label-request.json', { pub: m.pub, label: nombre })
  avisar(requireDaemon().pid, 'SIGUSR2')
  console.log('Listo: %s ahora se llama «%s». Compruébalo con: dotrino-vault members', m.id, nombre.slice(0, 60))
}

/** Busca un miembro del acta por su identificador (AB12-CD34) o se rinde con un mensaje claro. */
async function buscarMiembro (id) {
  const s = requireDaemon()
  const actaFile = path.join(dataDir(), 'acta.json')
  try { fs.rmSync(actaFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {})
  avisar(s.pid, 'SIGUSR2')
  let acta = null
  for (let i = 0; i < 50; i++) { await sleep(100); const a = readJson(actaFile, null); if (a?.at) { acta = a; break } }
  const m = acta?.members?.find((x) => x.id === String(id).toUpperCase())
  if (!m) { console.error('No hay ningún dispositivo con ese identificador. Míralos con: dotrino-vault members'); process.exit(1) }
  return m
}

/** `dotrino-vault caps <ID> ±permiso` — cambia lo que puede hacer un dispositivo. */
async function cmdCaps (args = []) {
  const [id, ...cambios] = args
  if (!id || !cambios.length) {
    console.error('uso: dotrino-vault caps <ID> +firma|-firma|+guarda|-guarda|+lee|-lee|+administra|-administra')
    process.exit(2)
  }
  const NOMBRE = {
    firma: 'sign', guarda: 'store', lee: 'read', administra: 'admin',
    sign: 'sign', store: 'store', read: 'read', admin: 'admin'
  }
  const s = requireDaemon()
  const m = await buscarMiembro(id)

  const caps = new Set(m.caps)
  for (const c of cambios) {
    const signo = c[0]
    const cap = NOMBRE[c.slice(1).toLowerCase()]
    if (!cap || (signo !== '+' && signo !== '-')) { console.error('permiso no reconocido: %s', c); process.exit(2) }
    if (signo === '+') caps.add(cap); else caps.delete(cap)
  }
  writeReq('caps-request.json', { pub: m.pub, caps: [...caps] })
  avisar(s.pid, 'SIGUSR2')
  console.log('Listo. Compruébalo con: dotrino-vault members')
}

async function cmdDevices () {
  const s = requireDaemon()
  try { fs.rmSync(devFile, { force: true }) } catch (_) {}
  writeReq('dump-request.json', {}) // de qué perfil queremos los dispositivos
  avisar(s.pid, 'SIGUSR2')
  let snap = null
  for (let i = 0; i < 50; i++) { await sleep(100); const d = readJson(devFile, null); if (d?.at) { snap = d; break } }
  if (!snap) { console.error('El daemon no respondió.'); process.exit(1) }
  const revoked = snap.revoked || []
  const fuera = new Set(revoked.map((r) => r?.nonce || r))
  // UN APARATO, UNA LÍNEA. El daemon lleva la cuenta por CERTIFICADO —correcto para él,
  // porque revocar es revocar un papel—, pero renovar emite uno nuevo cada 30 días: un
  // aparato de un año salía doce veces, y los ya retirados seguían contando como
  // enrolados. Se agrupa por llave y se dice cuántos certificados tiene.
  const porLlave = new Map()
  for (const d of (snap.issued || snap.active || snap.delegations || [])) {
    if (d.revokedAt || fuera.has(d.nonce)) continue
    const clave = d.sub || d.nonce
    const y = porLlave.get(clave)
    if (!y) porLlave.set(clave, { ...d, certs: 1 })
    else { y.certs++; if ((d.exp || 0) > (y.exp || 0)) Object.assign(y, { ...d, certs: y.certs }) }
  }
  const active = [...porLlave.values()]
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
    const m = await buscarMiembro(arg.toUpperCase().includes('-') ? arg.toUpperCase() : arg.toUpperCase().replace(/(.{4})(.{4})/, '$1-$2'))
    writeReq('revoke-request.json', { sub: m.pub })
    avisar(s.pid, 'SIGUSR2')
    console.log('Quitado %s (todos sus certificados). Se autoborrará al reconectar. Verifica: dotrino-vault devices', m.id)
    return
  }
  writeReq('revoke-request.json', { nonce: arg })
  avisar(s.pid, 'SIGUSR2')
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

// Secretos de servicios: se cargan aquí (el dueño, en el PC del vault) y los
// leen los SERVICIOS enrolados con `pair --service <ns>`. Nunca se listan valores.
async function cmdSecret (rest) {
  const [sub, ns, key, ...valueParts] = rest
  const s = requireDaemon()
  const secretsListFile = path.join(dir, 'secrets-list.json')
  const signalAndWaitList = async () => {
    try { fs.rmSync(secretsListFile, { force: true }) } catch (_) {}
    writeReq('dump-request.json', {}) // de qué perfil son los secretos
    avisar(s.pid, 'SIGUSR2')
    for (let i = 0; i < 50; i++) { await sleep(100); const d = readJson(secretsListFile, null); if (d?.at) return d }
    console.error('El daemon no respondió.'); process.exit(1)
  }
  if (sub === 'list') {
    const d = await signalAndWaitList()
    const names = d.ns || {}
    const nss = Object.keys(names)
    if (!nss.length) { console.log('No hay secretos guardados. Agrega uno:  dotrino-vault secret set <ns> <CLAVE> <valor>'); return }
    for (const n of nss) {
      console.log('%s%s%s  (scope vault:secrets:%s)', B, n, Z, n)
      for (const k of names[n]) console.log('  · %s', k)
    }
    return
  }
  if (sub === 'set' || sub === 'rm') {
    const value = valueParts.join(' ')
    if (!ns || !key || (sub === 'set' && !value)) {
      console.error('uso: dotrino-vault secret set <ns> <CLAVE> <valor>\n     dotrino-vault secret rm <ns> <CLAVE>'); process.exit(2)
    }
    writeReq('secret-request.json', sub === 'set' ? { op: 'set', ns, key, value } : { op: 'rm', ns, key })
    const d = await signalAndWaitList()
    const ok = sub === 'set' ? (d.ns?.[ns] || []).includes(key) : !(d.ns?.[ns] || []).includes(key)
    if (ok) console.log(sub === 'set' ? 'Secreto guardado: %s/%s' : 'Secreto borrado: %s/%s', ns, key)
    else { console.error('El daemon no aplicó el cambio (revisa: dotrino-vault logs)'); process.exit(1) }
    return
  }
  console.error('uso: dotrino-vault secret {set|rm|list}'); process.exit(2)
}

/**
 * Lee una contraseña del terminal SIN eco. Nunca se pasa como argumento: quedaría
 * en `ps` y en el historial de la shell.
 */
function askPassword (prompt) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin
    if (!stdin.isTTY) return reject(new Error('hace falta un terminal para escribir la contraseña'))
    process.stdout.write(prompt)
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8')
    let buf = ''
    const done = (err, val) => {
      stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData)
      process.stdout.write('\n')
      err ? reject(err) : resolve(val)
    }
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\n' || c === '\r' || c === '\u0004') return done(null, buf) // Enter / Ctrl-D
        if (c === '\u0003') return done(new Error('cancelado')) // Ctrl-C
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
  avisar(s.pid, 'SIGUSR2')
  for (let i = 0; i < 100; i++) {
    await sleep(100)
    const d = readJson(profilesFile, null)
    if (d?.at) return d
  }
  console.error('El daemon no respondió.'); process.exit(1)
}

function reportProfiles (d) {
  if (d.error) { console.error('%s', d.error); process.exit(1) }
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
      if (action === 'rm') { reportProfiles(await profileRequest('password-rm')); return }
      if (action && action !== 'set') { console.error('uso: dotrino-vault profile password [set|rm]'); process.exit(2) }
      console.log('La contraseña solo se pide para EDITAR el perfil. Tus dispositivos siguen')
      console.log('funcionando (firmando y leyendo) aunque el perfil esté bloqueado.')
      const pwd = await askPassword('\nContraseña nueva (mínimo 4): ')
      const again = await askPassword('Repítela: ')
      if (pwd !== again) { console.error('Las contraseñas no coinciden.'); process.exit(1) }
      reportProfiles(await profileRequest('password-set', { password: pwd }))
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
  secret set <ns> <CLAVE> <valor>   guarda un secreto para el servicio <ns>
  secret rm <ns> <CLAVE>            borra un secreto
  secret list                       lista nombres de secretos (nunca valores)
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
