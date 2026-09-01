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
import { encodeInvite, inviteUrl, parseInvite } from '../lib/src/invite.js'
import { readConfig as readKekConfig, probe as probeKek, rekeyDir, encryptedFilesIn, CONFIG_FILE as KEK_CONFIG_FILE } from '../lib/src/atrest.js'
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
const D = '\x1b[2m' // apagado: para el dato que acompaña sin competir con el nombre

/**
 * La fecha en que entró un aparato, corta y en local. Sin hora: lo que se busca al mirar
 * esta lista es «¿de cuándo es este?», no el minuto exacto — y una fecha larga en cada
 * línea convierte la lista en un muro.
 *
 * En español, como el resto de esta CLI: con el idioma del sistema salía «Jul 29, 2026»
 * en medio de una frase en español, que es peor que cualquiera de los dos por separado.
 */
function fechaCorta (ms) {
  try { return new Date(ms).toLocaleDateString('es', { year: 'numeric', month: 'short', day: 'numeric' }) }
  catch (_) { return '' }
}
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
  // --approval: el aparato que entre pedirá tu aprobación (teléfono) en cada petición de
  // claves privadas. Por defecto NO pide; se cambia después con `caps <ID> +permiso`.
  const approval = args.includes('--approval')
  // --name <n>: CÓMO SE VA A LLAMAR el aparato que entre, decidido aquí y antes de nada.
  // Sin esto el nombre lo ponía el propio aparato, que por defecto usa el apodo del
  // PERFIL: acababas con varios dispositivos llamados igual que tú, y para distinguirlos
  // había que renombrarlos después —cuando ya no sabías cuál era cuál—.
  const nIdx = args.indexOf('--name')
  let label = null
  if (nIdx >= 0) {
    const v = args[nIdx + 1]
    if (!v || v.startsWith('-')) { console.error('uso: dotrino-vault pair --name "teléfono de casa"'); process.exit(2) }
    label = v.slice(0, 60)
  }
  // --admin: el aparato que entre por esta invitación podrá ADMINISTRAR (la consola).
  // El QR no lleva nada: es una nota local de la bóveda y el permiso se aplica al aprobar
  // con el código que tecleas aquí. Ahorra el `caps <ID> +administra` de después, que en un
  // contenedor es otro `docker exec` y una vuelta a buscar el ID.
  const admin = args.includes('--admin')
  // --quiet: escupe SOLO la invitación (una línea) y termina. Sin QR y sin esperar.
  // Para desplegar: en un contenedor no hay quien mire un QR pintado en una terminal, y un
  // `pair` que se queda 2 minutos y medio esperando no se puede meter en un script.
  const quiet = args.includes('--quiet')
  // --kms <config.json>: el sitio que se va a crear (--new-account o --adopt) NACE con
  // su clave de disco en el KMS. Va aquí y no en un paso posterior porque es el único
  // momento que sirve: la llave de este aparato se genera al crear el perfil, y una
  // migración posterior no deshace que haya existido bajo la clave de la máquina.
  const kmsIdx = args.indexOf('--kms')
  let pairKek = null
  if (kmsIdx >= 0) {
    const f = args[kmsIdx + 1]
    if (!f || f.startsWith('-')) { console.error('uso: dotrino-vault pair --adopt --kms <config.json>'); process.exit(2) }
    try { pairKek = JSON.parse(fs.readFileSync(f, 'utf8')) } catch (e) {
      console.error('No se pudo leer %s: %s', f, e.message); process.exit(2)
    }
    try { probeKek(dataDir(), pairKek) } catch (e) {
      console.error('El KMS no respondió (%s): %s', e.code || 'error', e.message)
      console.error('No se creó ninguna cuenta.'); process.exit(1)
    }
  }
  const scIdx = args.indexOf('--scope')
  let scope = null
  if (scIdx >= 0) {
    const raw = args[scIdx + 1]
    if (!raw || raw.startsWith('-')) { console.error('uso: dotrino-vault pair --scope sign,read,store,secrets:<ns>'); process.exit(2) }
    const ALIAS = { firma: 'sign', lee: 'read', guarda: 'store', contrasenas: 'passwords', 'contraseñas': 'passwords' }
    scope = []
    for (const tok of raw.split(',').map((t) => t.trim()).filter(Boolean)) {
      const t = ALIAS[tok] || tok
      if (t === 'admin' || t === 'administra') { console.error('`admin` no se empareja: concédelo desde el PC con  dotrino-vault caps <ID> +administra'); process.exit(2) }
      if (t === 'approve' || t === 'aprueba') { console.error('`approve` no se empareja: concédelo desde el PC con  dotrino-vault caps <ID> +aprueba'); process.exit(2) }
      if (t === 'sealer' || t === 'sella') { console.error('`sella` no se empareja: concédelo desde el PC con  dotrino-vault caps <ID> +sella'); process.exit(2) }
      if (t === 'sign' || t === 'read' || t === 'store') { scope.push('vault:' + t); continue }
      // El gestor de contraseñas SÍ se empareja con su permiso puesto: es lo único que
      // va a hacer ese aparato, y pedirlo en dos pasos era el paso que nadie daba.
      if (t === 'passwords') { scope.push('vault:passwords'); continue }
      const m = /^secrets:([a-z0-9-]{1,32})$/.exec(t)
      if (m) { scope.push('vault:secrets:' + m[1]); continue }
      console.error('permiso desconocido: %s  (sign | read | store | contrasenas | secrets:<ns>)', tok); process.exit(2)
    }
    if (service) scope.push('vault:secrets:' + service)
    scope = [...new Set(scope)]
  }
  // `--new-account [nombre]`: la otra respuesta a «¿a qué cuenta entra?». En vez de
  // meter el dispositivo en una cuenta que ya vive aquí, se ESTRENA una (vacía) y
  // entra a ella; las demás no se tocan. En la TUI esto es una pregunta con sus
  // opciones; en la CLI es una bandera, para que siga sirviendo en un script.
  // `--name` lleva su valor detrás: no puede confundirse con el nombre de la cuenta.
  const consumido = (i) => nIdx >= 0 && i === nIdx + 1
  const naIdx = args.findIndex((a) => a === '--new-account')
  if (naIdx >= 0) {
    const next = consumido(naIdx + 1) ? null : args[naIdx + 1]
    const name = (next && !next.startsWith('-')) ? next : `cuenta ${new Date().toISOString().slice(0, 10)}`
    const d = await profileRequest('add', { name, ...(pairKek ? { kek: pairKek } : {}) })
    if (d.error) { console.error('%s', d.error); process.exit(1) }
    if (!d.id) { console.error('El daemon no dijo qué cuenta creó.'); process.exit(1) }
    PROFILE = d.id // el emparejamiento y los comandos siguientes apuntan a ELLA
    console.log('Cuenta nueva%s: %s  (%s)', pairKek ? ' (clave del disco en el KMS)' : '', name, d.id)
  }
  // `--adopt [nombre]`: la TERCERA respuesta a «¿de qué cuenta hablamos?» — el camino A.
  // Aquí la cuenta NO sale de esta bóveda: la trae el aparato y esta bóveda pasa a
  // guardarla y a mandarla. Por eso se crea un perfil VACÍO, que nace a la espera de
  // adoptarla; sin ese sitio no habría dónde meterla.
  const adIdx = args.findIndex((a) => a === '--adopt')
  const adopt = adIdx >= 0
  if (adopt) {
    const next = consumido(adIdx + 1) ? null : args[adIdx + 1]
    const name = (next && !next.startsWith('-')) ? next : `cuenta del dispositivo`
    const d = await profileRequest('add', { name, adopt: true, ...(pairKek ? { kek: pairKek } : {}) })
    if (d.error) { console.error('%s', d.error); process.exit(1) }
    if (!d.id) { console.error('El daemon no dijo qué cuenta creó.'); process.exit(1) }
    PROFILE = d.id
    console.log('Cuenta a la espera de adoptar la del dispositivo%s: %s  (%s)', pairKek ? ' (clave del disco en el KMS)' : '', name, d.id)
  }
  // `--kms` sin un sitio que crear no hace NADA, y callárselo es lo peor que se puede
  // hacer aquí: el dueño se quedaría creyendo que su aparato nació en el KMS.
  if (pairKek && !adopt && naIdx < 0) {
    console.error('--kms solo sirve cuando se crea el sitio, porque la llave del aparato')
    console.error('se genera en ese momento. Úsalo con una de las dos:')
    console.error('  dotrino-vault pair --adopt      --kms <config.json>   (la cuenta la trae el aparato)')
    console.error('  dotrino-vault pair --new-account --kms <config.json>  (cuenta nueva, nacida aquí)')
    console.error('')
    console.error('Emparejar contra una cuenta que ya vive en esta bóveda no cambia su clave de')
    console.error('disco: esa ya se escribió cuando se creó. Ver docs/llaves-de-hardware.md.')
    process.exit(2)
  }

  // La petición se escribe SIEMPRE (aunque no haya --service): lleva a qué perfil
  // se empareja el dispositivo.
  writeReq('pair-request.json', { ...(service ? { service } : {}), ...(scope ? { scope } : {}), ...(adopt ? { mode: 'adopt' } : {}), ...(approval ? { approval: true } : {}), ...(admin ? { admin: true } : {}), ...(label ? { label } : {}) })
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
  // --quiet: la invitación y nada más, para poder capturarla desde un script.
  if (quiet) { console.log(url); return }
  if (acct) console.log('\nCuenta que se comparte: %s%s', acct, pair.profileName && pair.profile ? `  (${pair.profile})` : '')
  console.log('\nEscanea este QR con el dispositivo que quieres conectar (válido %d min):\n', mins)
  console.log(qrToString(url)) // el QR abre la consola de dispositivos y empareja solo
  if (admin) console.log(`${R}${B}⚠ Y además podrá ADMINISTRAR: admitir y quitar aparatos.${Z}`)
  console.log(`${R}${B}⚠ Este código deja LEER tus datos y FIRMAR con tu identidad.${Z}`)
  console.log(`${R}  NO lo compartas con nadie, ni con "soporte". Solo escanéalo en TU dispositivo.${Z}`)
  console.log('\nO abre esta dirección en el dispositivo:\n  ' + url)
  console.log('\nO pega este código en vault.dotrino.com/vault :\n  ' + b64)

  // --save [archivo]: escribe la invitación (.dpair) para transferirla y abrirla en profile.
  const saveIdx = args.indexOf('--save')
  if (saveIdx >= 0) {
    const next = args[saveIdx + 1]
    const file = (next && !next.startsWith('-')) ? next : 'dotrino-invite.dpair'
    try { fs.writeFileSync(file, url + '\n', { mode: 0o600 }); console.log('\nInvitación guardada en: %s\n  (ábrela en vault.dotrino.com/vault → «Abrir imagen o archivo». Es efímera y de un solo uso; no la compartas.)', file) }
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

/**
 * `dotrino-vault join <invitación>` — ESTA bóveda entra en la cuenta de OTRA.
 *
 * Es el papel contrario a `pair`: aquí no se invita, se acepta. Y lo que entra en el acta
 * es la llave de ESTA bóveda, no una de aparato inventada — por eso después se le puede
 * dar `+sella` y que sea el respaldo de verdad de la otra.
 *
 * El código que sale por pantalla hay que TIPEARLO en la otra bóveda (`approve`): una
 * invitación interceptada no basta para entrar.
 */
async function cmdJoin (rest) {
  const args = rest || []
  // `--name <n>`: cómo se va a llamar aquí la cuenta ajena. Es un perfil MÁS de esta
  // bóveda, y en una máquina que respalda a varias hace falta distinguirlas.
  const nIdx = args.indexOf('--name')
  const name = nIdx >= 0 && args[nIdx + 1] && !args[nIdx + 1].startsWith('-') ? args[nIdx + 1] : null
  // `--kms <config.json>`: el perfil que se cree para la cuenta ajena NACE con su clave de
  // disco en el KMS. Va aquí por la misma razón que en `pair`: es el único momento que
  // sirve, porque la llave de esta bóveda para esa cuenta se genera al crear el perfil.
  const kIdx = args.indexOf('--kms')
  let kek = null
  if (kIdx >= 0) {
    const f = args[kIdx + 1]
    if (!f || f.startsWith('-')) { console.error('uso: dotrino-vault join <invitación> --kms <config.json>'); process.exit(2) }
    try { kek = JSON.parse(fs.readFileSync(f, 'utf8')) } catch (e) {
      console.error('No se pudo leer %s: %s', f, e.message); process.exit(2)
    }
    try { probeKek(dataDir(), kek) } catch (e) {
      console.error('El KMS no respondió (%s): %s', e.code || 'error', e.message)
      console.error('No se creó ninguna cuenta.'); process.exit(1)
    }
  }
  // Lo que queda tras quitar las banderas Y SUS VALORES es la invitación.
  const consumidos = new Set()
  for (const [i, v] of [[nIdx, name], [kIdx, kek]]) if (i >= 0) { consumidos.add(i); if (v != null) consumidos.add(i + 1) }
  const texto = args.filter((a, i) => !consumidos.has(i) && !a.startsWith('-')).join(' ').trim()
  if (!texto) {
    console.error('uso: dotrino-vault join <invitación> [--name <n>] [--kms <config.json>]')
    console.error('     (la invitación es lo que imprime «pair» en la otra bóveda)')
    process.exit(2)
  }
  const qr = parseInvite(texto)
  // QUÉ HACE FALTA DE VERDAD: el nonce de la sesión (`sn`) y una forma de alcanzar a la
  // otra bóveda — la CITA del proxio (`conn`) en la invitación corta, o su llave (`iss`)
  // en la larga. Quien la consume es `enrollDevice`, que sabe canjear la cita.
  //
  // Esto exigía `iss` SIEMPRE, y la invitación corta no lo lleva (la llave dejó de viajar
  // cuando el QR se acortó, `lib/src/invite.js`). O sea que `join` rechazaba todas las
  // invitaciones que emite `pair` hoy: el multivault entero no se podía montar.
  if (!qr?.sn || !(qr?.conn || qr?.iss)) {
    console.error('Esa invitación no se entiende. Pega la línea completa que imprime «dotrino-vault pair».')
    process.exit(2)
  }
  const s = requireDaemon()
  const res = path.join(dir, 'join.json')
  try { fs.rmSync(res, { force: true }) } catch (_) {}
  writeReq('join-request.json', { qr, label: 'bóveda', ...(name ? { name } : {}), ...(kek ? { kek } : {}) })
  sendSignal(s.pid, 'SIGUSR2')

  console.log('Entrando en la cuenta de la otra bóveda…')
  let visto = null
  for (let i = 0; i < 900; i++) {          // hasta 3 min: hay un humano tipeando al otro lado
    await sleep(200)
    const d = readJson(res, null)
    if (!d) continue
    if (d.code && d.code !== visto) {
      visto = d.code
      console.log('\n  Tipea este código en la OTRA bóveda:   dotrino-vault approve %s\n', d.code)
    }
    if (d.state === 'done') {
      console.log('Listo: esta bóveda ya es miembro de esa cuenta (acta #%s).', d.seq ?? '?')
      if (d.profile) console.log('La cuenta vive aquí como el perfil %s  (dotrino-vault profile ls).', d.profile)
      console.log('Para que además pueda SELLAR, en la otra:  dotrino-vault caps <ID> +sella')
      return
    }
    if (d.state === 'error') { console.error('No se pudo entrar: %s', d.error); process.exit(1) }
  }
  console.error('Se agotó la espera. ¿Se aprobó el código en la otra bóveda?')
  process.exit(1)
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

  // `sealer` y `passwords` faltaban y salían crudos, en inglés, entre los demás en
  // español. Se resaltan como `admin` y `approve`: los cuatro cambian lo que ese aparato
  // puede hacerle a la cuenta, y eso se lee de un vistazo o no se lee.
  const CAP = {
    sign: 'firma', store: 'guarda', read: 'lee', secrets: 'lee sus claves',
    admin: `${B}administra el perfil${Z}`, approve: `${B}aprueba pedidos${Z}`,
    sealer: `${B}sella el acta${Z}`, passwords: `${B}pide contraseñas${Z}`
  }
  // El nombre del perfil es una pubkey JWK. Recortarla no la hace legible: la deja
  // pareciendo un error (`{"key_ops":["verify"],"e…`). Se muestra su huella corta, la
  // misma que se enseña al emparejar y en la lista de miembros.
  const profileId = await deviceIdOf(record.profileId).catch(() => '????-????')
  console.log('\n%sPerfil%s %s · acta #%d\n', B, Z, profileId, record.seq)
  for (const m of record.members) {
    const who = m.label || m.id
    const marks = [
      // Ya no hay UN master: la marca dice quién puede sellar, y pueden ser varios. El
      // permiso también sale abajo en la lista, pero aquí se ve de un vistazo — que es
      // justo lo que se busca al mirar quién es quién.
      m.isMaster ? `${B}Sella${Z}` : null,
      m.isMe ? 'este dispositivo' : null,
      m.cn ? `servicio «${m.cn}»` : null
    ].filter(Boolean)
    const caps = m.caps.length ? m.caps.map((c) => CAP[c] || c).join(', ') : '(sin permisos)'
    // CUÁNDO ENTRÓ. El nombre lo pone el propio aparato al emparejarse y muchas veces no
    // distingue nada —dos teléfonos con el mismo apodo, o «cli» a secas—, así que la fecha
    // es lo que deja reconocer cuál es cuál y ver si hay uno que no recuerdas haber
    // conectado. El acta ya la guardaba (`addedAt`); solo no se enseñaba.
    console.log('  %s  %s%s%s\n      %s', m.id, who,
      m.addedAt ? `  ${D}· conectado el ${fechaCorta(m.addedAt)}${Z}` : '',
      marks.length ? '  [' + marks.join(' · ') + ']' : '', caps)
    // Un servicio SIN llave de cifrado no puede leer ninguna variable privada: van
    // selladas a esa llave. Se dice aquí, junto a él, porque es el único sitio donde
    // se mira quién es quién — y en la lista de variables ya seria tarde.
    if (m.cn && !m.canSeal) console.log('      %ssin llave de cifrado: NO puede leer sus variables%s', R, Z)
  }
  console.log('\n  Cambiar permisos:  dotrino-vault caps <ID> +firma | -firma | +guarda | -guarda | +lee | -lee | +administra | +aprueba | +contrasenas | +sella | +permiso')
  console.log('  «Permiso»: ese aparato solo recibe claves privadas cuando lo apruebas desde un aparato con «aprueba» (en cada arranque).')
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

/**
 * `dotrino-vault approval <ID> on|off` — ese aparato solo recibe claves privadas con el
 * visto bueno de un aparato con `aprueba` (el teléfono). Es propiedad del APARATO, no del
 * cajón: el VPS desatendido no pide; la PC del dueño sí. Pide en cada petición, que para un
 * servicio bien hecho es una por arranque.
 */
async function cmdApproval (args = []) {
  const [id, val] = args
  if (!id || !['on', 'off'].includes(val)) { console.error('uso: dotrino-vault approval <ID> on|off'); process.exit(2) }
  const m = await findMember(id)
  writeReq('secret-request.json', { op: 'approval', pub: m.pub, id: m.id, approval: val === 'on' })
  sendSignal(requireDaemon().pid, 'SIGUSR2')
  console.log(val === 'on'
    ? `Listo: ${m.id} solo recibirá claves privadas cuando un aparato con  caps <ID> +aprueba  lo apruebe (en cada arranque).`
    : `Listo: ${m.id} vuelve a recibir sus claves sin aprobación.`)
}

/** `dotrino-vault caps <ID> ±permiso` — cambia lo que puede hacer un dispositivo. */
async function cmdCaps (args = []) {
  const [id, ...changes] = args
  if (!id || !changes.length) {
    console.error('uso: dotrino-vault caps <ID> +firma|-firma|+guarda|-guarda|+lee|-lee|+administra|-administra|+aprueba|-aprueba|+contrasenas|-contrasenas|+sella|-sella|+permiso|-permiso')
    process.exit(2)
  }
  const CAP_BY_WORD = {
    firma: 'sign', guarda: 'store', lee: 'read', administra: 'admin', aprueba: 'approve',
    // `sella`: SELLAR EL ACTA. Es lo que convierte a otra bóveda en respaldo de esta —
    // podrá admitir aparatos y cambiar permisos si esta se pierde. No es un traspaso:
    // quien manda sigue mandando. Como `administra`, no se empareja: se concede aquí.
    sella: 'sealer', sealer: 'sealer',
    // `contraseñas`: el gestor (la extensión, la app del teléfono) puede PEDIR
    // credenciales de a una. Se acepta con y sin tilde: nadie escribe la ñ en una CLI.
    contrasenas: 'passwords', 'contraseñas': 'passwords',
    sign: 'sign', store: 'store', read: 'read', admin: 'admin', approve: 'approve',
    passwords: 'passwords'
  }
  const s = requireDaemon()
  const m = await findMember(id)

  // `+permiso` / `-permiso` no es una capacidad del acta: es la marca de la bóveda «este
  // aparato pide aprobación al recibir claves». Se cambia aquí, como cualquier permiso.
  const rest = []
  for (const c of changes) {
    const w = c.slice(1).toLowerCase()
    if ((c[0] === '+' || c[0] === '-') && (w === 'permiso' || w === 'approval')) {
      writeReq('secret-request.json', { op: 'approval', pub: m.pub, id: m.id, approval: c[0] === '+' })
      sendSignal(s.pid, 'SIGUSR2')
      console.log(c[0] === '+' ? `Listo: ${m.id} pedirá tu aprobación en cada petición de claves.` : `Listo: ${m.id} ya no pide aprobación.`)
      await sleep(300)
    } else rest.push(c)
  }
  if (!rest.length) return
  const caps = new Set(m.caps)
  for (const c of rest) {
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

// DE DÓNDE SALE la clave que cifra el disco (`lib/src/kek.js`). Por defecto se deriva de
// esta máquina; se puede pasar a un KMS, y entonces una copia del disco deja de servir.
function cmdAtrest (rest) {
  // OJO: la clave es POR PERFIL. `dir` aquí dentro es el del perfil al que apunta el
  // comando (--profile, o el activo); la raíz de la bóveda es otra cosa y tiene la suya.
  const vaultRoot = dataDir()
  const dir = profileDir()
  const sub = rest[0] || 'status'

  if (sub === 'status') {
    const cfg = readKekConfig(dir)
    const archivos = encryptedFilesIn(dir)
    if (cfg.provider === 'machine') {
      console.log('Clave del disco: derivada de ESTA máquina (machine-id + salt).')
      console.log('  Aviso: el material vive en el mismo disco que los datos, así que una')
      console.log('  copia del disco entero la abre. Para cerrarlo: dotrino-vault atrest rekey <config.json>')
    } else {
      console.log('Clave del disco: envuelta por ' + (cfg.label || cfg.wrap?.cmd || 'un programa externo') + '.')
      console.log('  Una copia del disco NO basta: hace falta además poder desenvolverla.')
    }
    console.log('Archivos cifrados: ' + (archivos.length ? archivos.join(', ') : 'ninguno todavía'))

    // ES POR PERFIL, y eso hay que verlo: en la misma bóveda un perfil puede ir con KMS
    // y el de al lado con la clave de la máquina. Sin esta lista, «lo puse en el KMS» es
    // una creencia y no un hecho comprobable.
    const otros = (readState().profiles || [])
    if (otros.length > 1) {
      console.log('')
      console.log('Los demás perfiles de esta bóveda (cada uno lleva su propia clave):')
      for (const q of otros) {
        let pv = 'machine'
        try { pv = readKekConfig(path.join(vaultRoot, 'p', q.id)).provider } catch (_) { pv = '?' }
        const marca = q.current ? ' (activo)' : ''
        console.log('  ' + (q.name || q.id) + marca + ': ' + (pv === 'machine' ? 'esta máquina' : 'programa externo / KMS'))
      }
    }
    // El REGISTRO de perfiles vive en la raíz y tiene su propia clave: poner un perfil en
    // el KMS no lo cubre. Dentro está el verificador del candado y la lista de perfiles,
    // no el contenido de ninguno — pero conviene no creer que ya está protegido.
    let raiz = 'machine'
    try { raiz = readKekConfig(vaultRoot).provider } catch (_) {}
    if (raiz === 'machine' && cfg.provider !== 'machine') {
      console.log('')
      console.log('Ojo: el registro de perfiles (la raíz de la bóveda) sigue con la clave de')
      console.log('esta máquina. No guarda el contenido de ningún perfil, pero no está en el KMS.')
    }
    return
  }

  if (sub === 'test') {
    // Comprueba el ida y vuelta SIN tocar los datos: es lo que hay que correr ANTES de
    // un rekey, y lo que dice si el KMS sigue respondiendo.
    try {
      const r = probeKek(dir)
      if (r.provider === 'machine') console.log('OK — proveedor «machine»: no hay nada externo que probar.')
      else console.log('OK — ' + (r.label || 'el programa externo') + ' envuelve y desenvuelve (' + r.wrappedBytes + ' bytes).')
    } catch (e) {
      console.error('FALLA (' + (e.code || 'error') + '): ' + e.message)
      process.exitCode = 1
    }
    return
  }

  if (sub === 'rekey') {
    const file = rest[1]
    if (!file) {
      console.error('Falta el archivo de configuración: dotrino-vault atrest rekey <config.json>')
      console.error('Para volver a la clave de la máquina: dotrino-vault atrest rekey --machine')
      process.exitCode = 1; return
    }
    let cfg
    if (file === '--machine') cfg = { provider: 'machine' }
    else {
      try { cfg = JSON.parse(fs.readFileSync(file, 'utf8')) } catch (e) {
        console.error('No se pudo leer ' + file + ': ' + e.message); process.exitCode = 1; return
      }
    }
    // FRENO: recifrar un perfil que YA tiene identidad no le da raíz de hardware, y
    // dejar creer que sí es peor que no ofrecerlo. Su maestra se escribió bajo la clave
    // vieja; cualquier copia del disco anterior a este momento la sigue abriendo, y eso
    // no hay recifrado que lo deshaga. Lo que sí sirve está en el mensaje.
    const tieneIdentidad = fs.existsSync(path.join(dir, 'identity.json'))
    if (tieneIdentidad && cfg.provider !== 'machine' && !rest.includes('--anyway')) {
      console.error('Este perfil ya tiene identidad, así que recifrarlo NO le da raíz en el KMS.')
      console.error('')
      console.error('Su maestra se generó y se escribió bajo la clave de esta máquina. Una copia')
      console.error('del disco anterior a este momento la sigue abriendo, para siempre, y eso no')
      console.error('lo deshace ningún recifrado: solo protege de aquí en adelante.')
      console.error('')
      console.error('Para una identidad con raíz en el KMS, tiene que NACER así:')
      console.error('  1. dotrino-vault profile add <nombre> --kms <config.json>')
      console.error('  2. enrólalo al acta de la cuenta como un aparato más')
      console.error('  3. pásale el sellado y revoca el aparato viejo')
      console.error('  (el profileId no cambia: la génesis sigue siendo el nombre de la cuenta)')
      console.error('')
      console.error('Si aun así quieres recifrar —porque el disco nunca salió de tu control—:')
      console.error('  dotrino-vault atrest rekey %s --anyway', file)
      process.exitCode = 1; return
    }
    try {
      const r = rekeyDir(dir, cfg)
      console.log('Listo: ' + r.from + ' → ' + r.to + '. Recifrados ' + r.files.length + ' archivos.')
      if (r.backups.length) {
        console.log('Copias de seguridad (bórralas cuando compruebes que todo abre):')
        for (const b of r.backups) console.log('  ' + b)
      }
      console.log('Reinicia el servicio para que tome la clave nueva.')
    } catch (e) {
      console.error('NO se cambió nada (' + (e.code || 'error') + '): ' + e.message)
      process.exitCode = 1
    }
    return
  }

  console.error('Uso: dotrino-vault atrest [status|test|rekey <config.json>|rekey --machine]')
  process.exitCode = 1
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
  const [sub, ...rawArgs] = rest
  // `--kms <archivo>` se saca ANTES de armar el nombre: el nombre se compone juntando
  // los argumentos sueltos, así que si no se quita acabaría llamándose «midevault --kms
  // cfg.json».
  const kmsAt = rawArgs.indexOf('--kms')
  const kmsFile = kmsAt !== -1 ? rawArgs[kmsAt + 1] : null
  const args = kmsAt !== -1 ? rawArgs.filter((_, i) => i !== kmsAt && i !== kmsAt + 1) : rawArgs
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
      if (!name) { console.error('uso: dotrino-vault profile add <nombre> [--kms <config.json>]'); process.exit(2) }
      // NACER con el KMS es la única forma de que la maestra no haya existido nunca bajo
      // la clave de esta máquina. Migrar después no da lo mismo y no se ofrece como si
      // lo diera (ver el freno de `atrest rekey`).
      let kek = null
      if (kmsAt !== -1) {
        if (!kmsFile || kmsFile.startsWith('-')) { console.error('uso: --kms <config.json>'); process.exit(2) }
        try { kek = JSON.parse(fs.readFileSync(kmsFile, 'utf8')) } catch (e) {
          console.error('No se pudo leer %s: %s', kmsFile, e.message); process.exit(2)
        }
        // Probar aquí ANTES de mandar la orden: si el KMS no responde, mejor enterarse
        // sin haber creado nada.
        try { probeKek(dataDir(), kek) } catch (e) {
          console.error('El KMS no respondió (%s): %s', e.code || 'error', e.message)
          console.error('No se creó ningún perfil.'); process.exit(1)
        }
      }
      reportProfiles(await profileRequest('add', { name, ...(kek ? { kek } : {}) }))
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
  // El daemon devuelve cuánto aguanta abierto: se dice AQUÍ, al abrirlo, que es cuando
  // sirve de algo. Encontrárselo cerrado sin haberlo leído nunca parece una avería.
  const out = await profileRequest('unlock', { password: pwd })
  reportProfiles(out)
  const min = Math.max(1, Math.round((out?.autoLockMs || 5 * 60 * 1000) / 60000))
  console.log(`Ya puedes editar el perfil. Se vuelve a bloquear solo tras ${min} min sin usarse` +
    ' (o al reiniciar el servicio, o con: dotrino-vault lock).')
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
  pair --kms <config.json>
                      el sitio que se cree (--adopt o --new-account) NACE con su clave
                      de disco en el KMS. Es el único momento que sirve: la llave del
                      aparato se genera al crear el perfil
  pair --new-account [nombre]
                      estrena una cuenta VACÍA en este vault y mete ahí al dispositivo
                      (sin la bandera entra a la cuenta activa, o a la de --profile)
  pair --service <ns> empareja un SERVICIO (proxy, geo…) con acceso SOLO a sus secretos
  pair --name <nombre>  cómo se llamará el aparato que entre. Sin esto el nombre lo pone
                      ÉL, y por defecto usa el apodo del perfil: acabas con varios
                      dispositivos llamados igual que tú
  pair --approval       el aparato que entre pedirá tu aprobación (teléfono) al recibir claves
  pair --admin          el aparato que entre podrá ADMINISTRAR (es lo que es una consola).
                      El QR no lleva nada: el permiso se aplica al aprobar el código aquí
  pair --quiet          escupe SOLO la invitación (una línea) y termina: sin QR y sin
                      esperar. Para desplegar (un contenedor no mira un QR en pantalla)
  pair --scope <lista>  los PERMISOS del cert: sign,read,store,contrasenas,secrets:<ns> (sin esto: sign,read,store;
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
  join <invitación> [--name <n>] [--kms <config.json>]
                      ESTA bóveda ENTRA en la cuenta de otra (el papel contrario a pair).
                      Entra con su propia llave, así que después se le puede dar +sella
                      y ser el respaldo de esa cuenta. La cuenta ajena queda aquí como un
                      PERFIL más (--name la nombra; --kms le pone la clave de disco en el
                      KMS, y solo vale ahora: el perfil se está creando)
                      Al desplegar, esto mismo va por el entorno y sin entrar a nada:
                      DOTRINO_JOIN (o DOTRINO_JOIN_FILE) + DOTRINO_JOIN_NAME
  pending             muestra el dispositivo pendiente + su código a comparar
  approve <código>    aprueba el dispositivo tipeando el código que MUESTRA (el vault no lo sabe)
  reject <deviceId>   rechaza un dispositivo pendiente
  devices             lista dispositivos enrolados / revocados
  me                  tu perfil (nombre, foto, datos) tal como lo tiene la bóveda
  members             el acta del perfil: quién es tuyo y qué puede hacer
  label <ID> <nombre> renombra un dispositivo (el nombre con el que lo reconoces)
  caps <ID> ±permiso  cambia permisos (+firma -guarda +administra +contrasenas …)
                      +sella = OTRA BÓVEDA que puede sellar el acta de esta cuenta, para
                      que perder una máquina no se la lleve. No es un traspaso
  revoke <ID|nonce>   quita un dispositivo (con el ID, todos sus certificados)
  atrest status       de dónde sale la clave que cifra el disco (esta máquina, o un KMS)
  atrest test         comprueba que el KMS envuelve y desenvuelve, SIN tocar los datos
  atrest rekey <f>    cambia de proveedor: descifra con la vieja y recifra con la nueva
                      (--machine para volver a la clave de esta máquina). Editar
                      atrest.json a mano NO vale: dejaría el perfil ilegible
  activity [n]        bitácora de seguridad: firmas, renovaciones, enrolados, rechazos
  logs                últimos logs del servicio
  version             muestra la versión instalada

Perfiles (varias identidades tuyas en el mismo PC; todas atienden a la vez):
  profile ls                        lista los perfiles (* = el activo, el destino por defecto)
  profile add <nombre>              crea un perfil (identidad nueva, vacía)
  profile add <nombre> --kms <f>    ...y su clave de disco NACE en el KMS que diga <f>.
                                    Es la única forma de que la maestra no exista nunca
                                    bajo la clave de esta máquina: migrar después no da
                                    lo mismo (una copia vieja del disco la sigue abriendo)
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
  lock                              vuelve a bloquear (también solo, a los 5 min sin
                                    usarse, y al reiniciar el servicio)

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
    case 'join': return cmdJoin(rest)
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
    case 'approval': return cmdApproval(rest)
    case 'atrest': return cmdAtrest(rest)
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
