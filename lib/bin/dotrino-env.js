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
import { enrollService, readServiceIdentity, fetchSecrets } from '../src/service.js'
import { loadEnv, serviceDir, serviceRoot, listEnrolled, resolveNs } from '../src/env.js'
// Se usaba sin importarlo: `enroll` —el comando principal— moría con
// «sharedParseInvite is not defined» en cuanto tocaba una invitación. Nunca
// llegó a funcionar, y por eso el único servicio enrolado del ecosistema (el
// proxy) lo hizo con su propio `enroll-vault.js` en vez de con esta CLI.
import { parseInvite as sharedParseInvite } from '../src/invite.js'

const argv = process.argv.slice(2)
const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : undefined }

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

El vault MANDA: sus valores pisan los del .env y los del entorno. Para una
corrida suelta sin que pise nada:  DOTRINO_ENV_OVERRIDE=0

Entorno: DOTRINO_NS · DOTRINO_ENV_DIR · DOTRINO_ENV_HOME · DOTRINO_ENV_QUIET
         DOTRINO_ENV_OVERRIDE`)
}

/**
 * La invitación que imprime `dotrino-vault pair`, en cualquiera de sus formas
 * (URL del QR, código pegable, formatos viejos). El parser es el compartido:
 * `lib/src/invite.js`, que lee la marca de formato en vez de adivinar.
 */
function parseInvite (raw) {
  const o = sharedParseInvite(raw)
  if (!o) throw new Error('no parece una invitación del vault')
  return o
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
  const qr = parseInvite(flag('qr') || await readInvite())

  console.log('\nEnrolando el servicio "%s" contra el vault…', ns)
  const { cert } = await enrollService({
    qr,
    ns,
    dir,
    label: flag('label') || 'servicio:' + ns,
    // Un agente tiene UNA identidad y se la da el vault: re-enrolar REEMPLAZA,
    // no acumula. Antes había una reja (`--force`) que hacía de esto un error a
    // desbloquear; sobra, porque no existe la alternativa de "quedarse con las
    // dos". Lo que sí corresponde es que se vea qué se está tirando.
    onReplace: (prev) => {
      console.log('\n  ⚠ Este agente YA tenía identidad (dispositivo %s, del %s).',
        prev.deviceId, new Date(prev.enrolledAt).toISOString().slice(0, 10))
      console.log('    Se DESCARTA: el vault le cede una nueva y la anterior deja de existir aquí.')
      console.log('    Si esa llave era además la identidad de red del servicio (el caso del')
      console.log('    proxio), su id de nodo cambia y sus peers lo rechazan hasta re-pinearlo.\n')
    },
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
  // `fetchSecrets` y no `loadEnv`: listar NO debe tener efectos secundarios. Con
  // `loadEnv` esto inyectaría el bundle en el entorno del propio `check`, que es
  // justo lo que un comando de diagnóstico no tiene por qué hacer.
  const secrets = await fetchSecrets({ dir: serviceDir(ns), ns })
  const keys = Object.keys(secrets)
  console.log('ns "%s": %d secreto(s)%s', ns, keys.length, keys.length ? ':' : '')
  for (const k of keys) console.log('  ' + k)   // NUNCA los valores
  // Delata el `.env` rancio: qué claves de esta máquina el vault pisaría.
  const chocan = keys.filter((k) => k in process.env && process.env[k] !== String(secrets[k]))
  if (chocan.length) {
    console.log('\nEl vault PISA estos valores del entorno de esta máquina:\n  %s', chocan.join(', '))
  }
}

async function cmdRun () {
  const sep = argv.indexOf('--')
  const cmd = sep >= 0 ? argv.slice(sep + 1) : []
  if (!cmd.length) { console.error('uso: dotrino-env run [--ns <ns>] -- <cmd> [args…]'); process.exit(2) }
  const { injected, overridden } = await loadEnv({ ns: flag('ns') })
  console.error('[dotrino-env] %d valor(es) en el entorno de %s%s', injected.length, cmd[0],
    overridden.length ? ` (pisados: ${overridden.join(', ')})` : '')
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
