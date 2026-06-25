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
 *   logs              últimos logs del servicio
 */
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { pubkeyId } from '@dotrino/identity/capabilities'
import { dataDir, readJson } from './paths.js'
import { qrToString } from './qr.js'

const dir = dataDir()
const stateFile = path.join(dir, 'state.json')
const pairFile = path.join(dir, 'pair.json')
const pendingFile = path.join(dir, 'pending-enroll.json')
const devFile = path.join(dir, 'devices.json')

const R = '\x1b[31m', B = '\x1b[1m', Z = '\x1b[0m' // rojo / negrita / reset
// La versión se inyecta en build (esbuild --define); en dev cae a 'dev'.
const VERSION = (typeof __VAULT_VERSION__ !== 'undefined') ? __VAULT_VERSION__ : 'dev'
const PROFILE_URL = 'https://profile.dotrino.com/#vault='

function readState () {
  const s = readJson(stateFile, null)
  if (!s) {
    console.error('El vault no parece haber arrancado todavía (no hay state.json en %s).', dir)
    console.error('Arrancá el servicio:  systemctl --user start dotrino-vault')
    process.exit(2)
  }
  return s
}
function alive (pid) { try { return !!pid && (process.kill(pid, 0) || true) } catch { return false } }
function sleep (ms) { return new Promise((r) => setTimeout(r, ms)) }
function requireDaemon () {
  const s = readState()
  if (!alive(s.pid)) { console.error('El daemon no está corriendo. Arrancalo: systemctl --user start dotrino-vault'); process.exit(1) }
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
  console.log('  fingerprint : %s', s.fingerprint)
  console.log('  proxy       : %s', s.proxy)
  console.log('  pid         : %s%s', s.pid, up ? '' : ' (no responde)')
  console.log('  datos       : %s', dir)
  if (!up) process.exitCode = 1
}

function showChallenge (pe) {
  console.log('\n%sUn dispositivo quiere conectarse a tu bóveda:%s', B, Z)
  console.log('  dispositivo : %s%s%s', B, pe.deviceId, Z)
  console.log('\n  Ingresá el código que MUESTRA el dispositivo (el vault no lo conoce):')
  console.log('    %sdotrino-vault approve <código>%s', B, Z)
  console.log('  Si no reconocés este dispositivo:  dotrino-vault reject %s\n', pe.deviceId)
}

async function cmdPair (args = []) {
  const s = requireDaemon()
  try { fs.rmSync(pairFile, { force: true }) } catch (_) {}
  try { fs.rmSync(pendingFile, { force: true }) } catch (_) {}
  process.kill(s.pid, 'SIGUSR1')

  let pair = null
  for (let i = 0; i < 50; i++) { await sleep(100); const p = readJson(pairFile, null); if (p?.expiresAt > Date.now()) { pair = p; break } }
  if (!pair) { console.error('No se recibió respuesta del daemon para el emparejamiento.'); process.exit(1) }

  const payload = JSON.stringify(pair.qr)
  const b64 = Buffer.from(payload, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const url = PROFILE_URL + b64
  const mins = Math.round((pair.expiresAt - Date.now()) / 60000)
  console.log('\nEscaneá este QR con el dispositivo que querés conectar (válido %d min):\n', mins)
  console.log(qrToString(url)) // el QR abre profile.dotrino.com/#vault=… y empareja solo
  console.log(`${R}${B}⚠ Este código deja LEER tus datos y FIRMAR con tu identidad.${Z}`)
  console.log(`${R}  NO lo compartas con nadie, ni con "soporte". Solo escaneálo en TU dispositivo.${Z}`)
  console.log('\nO abrí esta dirección en el dispositivo:\n  ' + url)
  console.log('\nO pegá este código en profile.dotrino.com/#vault :\n  ' + payload)

  // --save [archivo]: escribe la invitación (.dpair) para transferirla y abrirla en profile.
  const saveIdx = args.indexOf('--save')
  if (saveIdx >= 0) {
    const next = args[saveIdx + 1]
    const file = (next && !next.startsWith('-')) ? next : 'dotrino-invite.dpair'
    try { fs.writeFileSync(file, url + '\n', { mode: 0o600 }); console.log('\nInvitación guardada en: %s\n  (ábrila en profile.dotrino.com/#vault → «Abrir imagen/archivo». Es efímera y de un solo uso; no la compartas.)', file) }
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
  fs.writeFileSync(path.join(dir, 'approve-request.json'), JSON.stringify({ code: String(code), at: Date.now() }), { mode: 0o600 })
  process.kill(s.pid, 'SIGUSR2')
  console.log('Aprobando con el código %s… verificá con: dotrino-vault devices', code)
}

function cmdReject (deviceId) {
  if (!deviceId) { console.error('uso: dotrino-vault reject <deviceId>'); process.exit(2) }
  const s = requireDaemon()
  fs.writeFileSync(path.join(dir, 'reject-request.json'), JSON.stringify({ deviceId, at: Date.now() }), { mode: 0o600 })
  process.kill(s.pid, 'SIGUSR2')
  console.log('Rechazado %s.', deviceId)
}

async function cmdDevices () {
  const s = requireDaemon()
  try { fs.rmSync(devFile, { force: true }) } catch (_) {}
  process.kill(s.pid, 'SIGUSR2')
  let snap = null
  for (let i = 0; i < 50; i++) { await sleep(100); const d = readJson(devFile, null); if (d?.at) { snap = d; break } }
  if (!snap) { console.error('El daemon no respondió.'); process.exit(1) }
  const active = snap.issued || snap.active || snap.delegations || []
  const revoked = snap.revoked || []
  console.log('Dispositivos enrolados: %d', active.length)
  for (const d of active) {
    const did = d.sub ? await deviceIdOf(d.sub) : '????-????'
    console.log('  · %s  %s%s%s', did, d.label || '(sin etiqueta)',
      d.exp ? '  exp=' + new Date(d.exp).toISOString() : '',
      d.nonce ? '  nonce=' + d.nonce : '')
  }
  if (revoked.length) {
    console.log('Revocados: %d', revoked.length)
    for (const r of revoked) console.log('  · nonce=%s', r.nonce)
  }
  console.log('\nPara revocar uno (y ordenarle autoborrarse):  dotrino-vault revoke <nonce>')
}

function cmdRevoke (nonce) {
  if (!nonce) { console.error('uso: dotrino-vault revoke <nonce>'); process.exit(2) }
  const s = requireDaemon()
  fs.writeFileSync(path.join(dir, 'revoke-request.json'), JSON.stringify({ nonce, at: Date.now() }), { mode: 0o600 })
  process.kill(s.pid, 'SIGUSR2')
  console.log('Revocación enviada para nonce=%s. El dispositivo se autoborrará al reconectar. Verificá: dotrino-vault devices', nonce)
}

function cmdLogs () {
  try { process.stdout.write(execFileSync('journalctl', ['--user', '-u', 'dotrino-vault', '-n', '40', '--no-pager'], { encoding: 'utf8' })) }
  catch { console.error('No se pudieron leer los logs. Probá:  journalctl --user -u dotrino-vault -f') }
}

function help () {
  console.log(`dotrino-vault — control del certificador personal

  status              estado del servicio + fingerprint
  pair [--save <f>]   inicia un emparejamiento (QR + espera); --save escribe la invitación (.dpair)
  pending             muestra el dispositivo pendiente + su código a comparar
  approve <código>    aprueba el dispositivo tipeando el código que MUESTRA (el vault no lo sabe)
  reject <deviceId>   rechaza un dispositivo pendiente
  devices             lista dispositivos enrolados / revocados
  revoke <nonce>      revoca un dispositivo (le ordena autoborrarse)
  logs                últimos logs del servicio
  version             muestra la versión instalada

El servicio se gestiona con systemd --user:
  systemctl --user {start,stop,restart} dotrino-vault · journalctl --user -u dotrino-vault -f`)
}

export async function runCtl (argv) {
  const [cmd, ...rest] = argv
  switch (cmd) {
    case 'status': return cmdStatus()
    case 'pair': return cmdPair(rest)
    case 'pending': return cmdPending()
    case 'approve': return cmdApprove(rest[0])
    case 'reject': return cmdReject(rest[0])
    case 'devices': return cmdDevices()
    case 'revoke': return cmdRevoke(rest[0])
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
