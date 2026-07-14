#!/usr/bin/env node
/**
 * dotrino-env — CLI del "dotenv contra el vault".
 *
 *   dotrino-env enroll --ns <ns> [--qr <invitación>]   enrola ESTA máquina/servicio (una vez)
 *   dotrino-env status                                  qué hay enrolado aquí
 *   dotrino-env check [--ns <ns>]                       pide los secretos y lista sus NOMBRES (nunca valores)
 *   dotrino-env run [--ns <ns>] -- <cmd> [args…]        corre un comando con los secretos en su entorno
 *
 * El enrolamiento es el registro del cliente contra el vault del dueño:
 *   1. en el vault:   dotrino-vault pair --service <ns>      (invitación con scope SOLO vault:secrets:<ns>)
 *   2. aquí:          dotrino-env enroll --ns <ns>           (pegas la invitación; se MUESTRA un código)
 *   3. en el vault:   dotrino-vault approve <código>         (lo tipeas leyéndolo de esta pantalla)
 */
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline/promises'
import { spawn } from 'node:child_process'
import { enrollService, readServiceIdentity } from '../src/service.js'
import { loadEnv, serviceDir, serviceRoot, listEnrolled, resolveNs } from '../src/env.js'

const argv = process.argv.slice(2)
const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : undefined }
const has = (name) => argv.includes('--' + name)

function help () {
  console.log(`dotrino-env — credenciales del vault en vez del .env

  enroll --ns <ns> [--qr <invitación>] [--dir <dir>]
        Registra ESTE servicio contra el vault (una sola vez).
        Antes, en el vault:  dotrino-vault pair --service <ns>
        Si no pasas --qr, se pide por consola (también acepta stdin).

  status                 servicios enrolados en esta máquina
  check [--ns <ns>]      pide los secretos al vault y lista sus NOMBRES (nunca los valores)
  run [--ns <ns>] -- <cmd> [args…]
                         ejecuta <cmd> con los secretos inyectados en su entorno

En tu código:
  import '@dotrino/vault/config'                       // ns por DOTRINO_NS
  import { loadEnv } from '@dotrino/vault/env'; await loadEnv({ ns: '<ns>' })

Entorno: DOTRINO_NS · DOTRINO_ENV_DIR · DOTRINO_ENV_HOME · DOTRINO_ENV_QUIET`)
}

/**
 * La invitación que imprime `dotrino-vault pair` viene en tres formas: el JSON
 * crudo, el base64url del payload, o la URL de profile con `#vault=<b64>`.
 * Aceptamos las tres para que el operador pegue lo que tenga a mano.
 */
function parseInvite (raw) {
  const s = String(raw || '').trim()
  if (!s) throw new Error('invitación vacía')
  if (s.startsWith('{')) return JSON.parse(s)
  const b64 = s.includes('#vault=') ? s.split('#vault=')[1] : (s.includes('#') ? s.split('#').pop() : s)
  const json = Buffer.from(b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
  if (!json.trim().startsWith('{')) throw new Error('no parece una invitación del vault')
  return JSON.parse(json)
}

async function readInvite () {
  if (!process.stdin.isTTY) return fs.readFileSync(0, 'utf8')
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question('Pega la invitación del vault (salida de `dotrino-vault pair --service <ns>`):\n> ')
  rl.close()
  return answer
}

async function cmdEnroll () {
  const ns = flag('ns')
  if (!ns) { console.error('falta --ns <ns>  (el mismo del `dotrino-vault pair --service <ns>`)'); process.exit(2) }
  const dir = flag('dir') || serviceDir(ns)
  if (readServiceIdentity(dir) && !has('force')) {
    console.error('ya hay un servicio enrolado en %s (usa --force para re-enrolar)', dir); process.exit(2)
  }
  const qr = parseInvite(flag('qr') || await readInvite())

  console.log('\nEnrolando el servicio "%s" contra el vault…', ns)
  const { cert } = await enrollService({
    qr,
    ns,
    dir,
    label: flag('label') || 'servicio:' + ns,
    onCode: ({ deviceId, code }) => {
      console.log('\n  Dispositivo: %s', deviceId)
      console.log('  APRUEBA en el vault tipeando este código:\n')
      console.log('      dotrino-vault approve %s\n', code)
      console.log('  (el vault NO conoce este código: tiene que leerlo de aquí un humano)')
    }
  })
  console.log('\nListo. Identidad del servicio en: %s', path.join(dir, 'service-identity.json'))
  console.log('Certificado con scope: %s  (vence %s)', (cert.scope || []).join(', '), new Date(cert.exp).toISOString())
  console.log('\nEn tu app:  import \'@dotrino/vault/config\'   (con DOTRINO_NS=%s)', ns)
}

function cmdStatus () {
  const found = listEnrolled()
  if (!found.length) {
    console.log('Ningún servicio enrolado en %s\n  Enrola uno:  dotrino-env enroll --ns <ns>', serviceRoot())
    return
  }
  for (const ns of found) {
    const id = readServiceIdentity(serviceDir(ns))
    const exp = id?.cert?.exp
    console.log('%s\n  dir:   %s\n  vault: %s…\n  scope: %s\n  cert:  vence %s',
      ns, serviceDir(ns), String(id.iss).slice(0, 24), (id.cert?.scope || []).join(', '),
      exp ? new Date(exp).toISOString() : '?')
  }
}

async function cmdCheck () {
  const ns = resolveNs(flag('ns'))
  const { secrets } = await loadEnv({ ns, wait: false })
  const keys = Object.keys(secrets)
  console.log('ns "%s": %d secreto(s)%s', ns, keys.length, keys.length ? ':' : '')
  for (const k of keys) console.log('  ' + k)   // NUNCA los valores
}

async function cmdRun () {
  const sep = argv.indexOf('--')
  const cmd = sep >= 0 ? argv.slice(sep + 1) : []
  if (!cmd.length) { console.error('uso: dotrino-env run [--ns <ns>] -- <cmd> [args…]'); process.exit(2) }
  await loadEnv({ ns: flag('ns') })
  const child = spawn(cmd[0], cmd.slice(1), { stdio: 'inherit', env: process.env })
  child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 0)))
}

const run = async () => {
  switch (argv[0]) {
    case 'enroll': return cmdEnroll()
    case 'status': return cmdStatus()
    case 'check': return cmdCheck()
    case 'run': return cmdRun()
    case undefined:
    case 'help':
    case '--help':
    case '-h': return help()
    default: console.error('comando desconocido: %s\n', argv[0]); help(); process.exit(2)
  }
}

run().catch((e) => { console.error('\n[dotrino-env] ' + e.message); process.exit(1) })
