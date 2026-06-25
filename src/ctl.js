/**
 * ctl.js — CLI de control de dotrino-vault.
 *
 * NO abre la identidad ni el proxy: habla con el daemon (que es el único proceso
 * que custodia la maestra) leyendo archivos del dir de datos y enviándole señales.
 * Así no hay socket/puerto de control que escuchar (regla de privacidad) y no hay
 * dos procesos peleando por la clave.
 *
 *   dotrino-vault status            estado + fingerprint
 *   dotrino-vault pair              genera y muestra un QR de emparejamiento
 *   dotrino-vault devices           lista dispositivos enrolados / revocados
 *   dotrino-vault revoke <nonce>    (guía: se revoca reenviando al daemon)
 *   dotrino-vault logs              últimos logs del servicio (journal)
 */
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { dataDir, readJson } from './paths.js'
import { qrToString } from './qr.js'

const dir = dataDir()
const stateFile = path.join(dir, 'state.json')
const pairFile = path.join(dir, 'pair.json')
const devFile = path.join(dir, 'devices.json')

function readState () {
  const s = readJson(stateFile, null)
  if (!s) {
    console.error('El vault no parece haber arrancado todavía (no hay state.json en %s).', dir)
    console.error('Arrancá el servicio:  systemctl --user start dotrino-vault')
    process.exit(2)
  }
  return s
}

function alive (pid) {
  if (!pid) return false
  try { process.kill(pid, 0); return true } catch { return false }
}

function sleep (ms) { return new Promise((r) => setTimeout(r, ms)) }

function cmdStatus () {
  const s = readState()
  const up = alive(s.pid)
  console.log('dotrino-vault · %s', up ? 'corriendo' : 'DETENIDO (state.json viejo)')
  console.log('  fingerprint : %s', s.fingerprint)
  console.log('  proxy       : %s', s.proxy)
  console.log('  pid         : %s%s', s.pid, up ? '' : ' (no responde)')
  console.log('  datos       : %s', dir)
  if (!up) process.exitCode = 1
}

async function cmdPair () {
  const s = readState()
  if (!alive(s.pid)) {
    console.error('El daemon no está corriendo (pid %s). Arrancalo: systemctl --user start dotrino-vault', s.pid)
    process.exit(1)
  }
  // limpiar pair viejo y pedir uno nuevo al daemon
  try { fs.rmSync(pairFile, { force: true }) } catch (_) {}
  process.kill(s.pid, 'SIGUSR1')

  // esperar a que el daemon escriba pair.json fresco
  let pair = null
  for (let i = 0; i < 50; i++) {
    await sleep(100)
    const p = readJson(pairFile, null)
    if (p && p.expiresAt > Date.now()) { pair = p; break }
  }
  if (!pair) {
    console.error('No se recibió respuesta del daemon para el emparejamiento.')
    process.exit(1)
  }

  const payload = JSON.stringify(pair.qr)
  const mins = Math.round((pair.expiresAt - Date.now()) / 60000)
  console.log('\nEscaneá este QR con tu teléfono/laptop para enrolarlo (válido %d min):\n', mins)
  console.log(qrToString(payload))
  console.log('O pegá este objeto de emparejamiento manualmente:\n')
  console.log(payload)
  console.log('\nfingerprint del vault: %s', s.fingerprint)
}

async function cmdDevices () {
  const s = readState()
  if (!alive(s.pid)) { console.error('El daemon no está corriendo.'); process.exit(1) }
  try { fs.rmSync(devFile, { force: true }) } catch (_) {}
  process.kill(s.pid, 'SIGUSR2')
  let snap = null
  for (let i = 0; i < 50; i++) {
    await sleep(100)
    const d = readJson(devFile, null)
    if (d && d.at) { snap = d; break }
  }
  if (!snap) { console.error('El daemon no respondió.'); process.exit(1) }
  // devices.json = { v, at, ...identity.listDelegations() } → { issued, revoked }
  const active = snap.issued || snap.active || snap.delegations || []
  const revoked = snap.revoked || []
  console.log('Dispositivos enrolados: %d', active.length)
  for (const d of active) {
    console.log('  · %s%s%s', d.label || '(sin etiqueta)',
      d.nonce ? '  nonce=' + d.nonce : '',
      d.exp ? '  exp=' + new Date(d.exp).toISOString() : '')
  }
  if (revoked.length) {
    console.log('Revocados: %d', revoked.length)
    for (const r of revoked) console.log('  · nonce=%s', r.nonce)
  }
  console.log('\nPara revocar uno:  dotrino-vault revoke <nonce>')
}

function cmdRevoke (nonce) {
  if (!nonce) { console.error('uso: dotrino-vault revoke <nonce>'); process.exit(2) }
  // La revocación toca la identidad → debe hacerla el daemon. En v1 lo dejamos
  // explícito: escribimos la orden y reiniciamos no es ideal; el camino correcto
  // es un comando del daemon. Para no abrir un socket, exponemos la orden por un
  // archivo que el daemon consume al recibir SIGUSR2 con un revoke pendiente.
  const reqFile = path.join(dir, 'revoke-request.json')
  const s = readState()
  if (!alive(s.pid)) { console.error('El daemon no está corriendo.'); process.exit(1) }
  fs.writeFileSync(reqFile, JSON.stringify({ nonce, at: Date.now() }), { mode: 0o600 })
  process.kill(s.pid, 'SIGUSR2')
  console.log('Orden de revocación enviada para nonce=%s. Verificá con: dotrino-vault devices', nonce)
}

function cmdLogs () {
  try {
    const out = execFileSync('journalctl', ['--user', '-u', 'dotrino-vault', '-n', '40', '--no-pager'], { encoding: 'utf8' })
    process.stdout.write(out)
  } catch {
    console.error('No se pudieron leer los logs (¿journalctl disponible?).')
    console.error('Probá:  journalctl --user -u dotrino-vault -f')
  }
}

function help () {
  console.log(`dotrino-vault — control del certificador personal

  status            estado del servicio + fingerprint
  pair              genera y muestra un QR para emparejar un dispositivo
  devices           lista dispositivos enrolados / revocados
  revoke <nonce>    revoca un dispositivo
  logs              últimos logs del servicio

El servicio se gestiona con systemd --user:
  systemctl --user {start,stop,restart,status} dotrino-vault
  journalctl --user -u dotrino-vault -f`)
}

export async function runCtl (argv) {
  const [cmd, ...rest] = argv
  switch (cmd) {
    case 'status': return cmdStatus()
    case 'pair': return cmdPair()
    case 'devices': return cmdDevices()
    case 'revoke': return cmdRevoke(rest[0])
    case 'logs': return cmdLogs()
    case undefined:
    case 'help':
    case '--help':
    case '-h': return help()
    default:
      console.error('comando desconocido: %s', cmd)
      help()
      process.exit(2)
  }
}
