#!/usr/bin/env node
/**
 * dotrino-env — CLI del "dotenv contra el vault".
 *
 *   dotrino-env enroll --vault <b> --ns <ns> [--qr <inv>]   enrola ESTA máquina (una vez)
 *   dotrino-env status                                  qué hay enrolado aquí
 *   dotrino-env check [--ns <ns>]                       pide los secretos y lista sus NOMBRES (nunca valores)
 *   dotrino-env run [--ns <ns>] -- <cmd> [args…]        corre un comando con los secretos en su entorno
 *
 * El enrolamiento es el registro del cliente contra el vault del dueño:
 *   1. en el vault:   dotrino-vault pair --service <ns>      (invitación con scope SOLO vault:secrets:<ns>)
 *   2. aquí:          dotrino-env enroll --vault <b> --ns <ns>  (pegas la invitación; se MUESTRA un código)
 *   3. en el vault:   dotrino-vault approve <código>         (lo tipeas leyéndolo de esta pantalla)
 */
import fs from 'node:fs'
import path from 'node:path'
import readline from 'node:readline/promises'
import { spawn } from 'node:child_process'
import { enrollService, readServiceIdentity, fetchSecrets } from '../src/service.js'
import { loadEnv, serviceDir, serviceRoot, listEnrolled, resolveNs, resolveVaultLabel, isValidVaultLabel } from '../src/env.js'
// Se usaba sin importarlo: `enroll` —el comando principal— moría con
// «sharedParseInvite is not defined» en cuanto tocaba una invitación. Nunca
// llegó a funcionar, y por eso el único servicio enrolado del ecosistema (el
// proxy) lo hizo con su propio `enroll-vault.js` en vez de con esta CLI.
import { parseInvite as sharedParseInvite } from '../src/invite.js'

const argv = process.argv.slice(2)
const flag = (name) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : undefined }

function help () {
  console.log(`dotrino-env — credenciales del vault en vez del .env

  enroll --vault <bóveda> --ns <ns> [--code <invitación>] [--dir <dir>]
        (--vault SOLO hace falta aquí, y para usarlo si el mismo <ns> está en dos bóvedas)
        Registra ESTE servicio contra el vault (una sola vez).
        Antes, en el vault:  dotrino-vault pair --service <ns>
        Si no pasas --code (alias --qr), se pide por consola (también acepta stdin).

  status                 servicios enrolados en esta máquina
  check [--ns <ns>]      pide los secretos al vault y lista sus NOMBRES (nunca los valores)
  run [--vault <bóveda>] [--ns <ns>] [--public] -- <cmd> [args…]
        --public  trae SOLO las variables públicas. No pide aprobación en el teléfono:
                  la aprobación es para las claves privadas, y una pública está en claro.
  ssh-agent [--ns <ns>] [--socket <ruta>]
                         agente SSH con las llaves (SSH_KEY_* del cajón) solo en memoria;
                         pide el cajón al arrancar. Pon SSH_AUTH_SOCK en la ruta que imprime.
                         ejecuta <cmd> con los secretos inyectados en su entorno

En tu código:
  import '@dotrino/vault/config'                       // ns por DOTRINO_NS
  import { loadEnv } from '@dotrino/vault/env'; await loadEnv({ ns: '<ns>' })

El vault MANDA: sus valores pisan los del .env y los del entorno. Para una
corrida suelta sin que pise nada:  DOTRINO_ENV_OVERRIDE=0

Entorno: DOTRINO_NS · DOTRINO_ENV_VAULT · DOTRINO_ENV_DIR · DOTRINO_ENV_HOME · DOTRINO_ENV_QUIET
         DOTRINO_ENV_OVERRIDE`)
}

/**
 * La invitación que imprime `dotrino-vault pair`, en cualquiera de sus formas
 * (URL del QR, código pegable, formatos viejos). El parser es el compartido:
 * `lib/src/invite.js`, que lee la marca de formato en vez de adivinar.
 */
function parseInvite (raw) {
  const o = sharedParseInvite(raw)
  if (!o) throw new Error('that does not look like a vault invitation')
  return o
}

async function readInvite () {
  if (!process.stdin.isTTY) return fs.readFileSync(0, 'utf8')
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const answer = await rl.question('Pega la invitación del vault (salida de `dotrino-vault pair --service <ns>`):\n> ')
  rl.close()
  return answer
}

/**
 * DE QUÉ BÓVEDA VINO, obligatorio. Etiqueta de ESTA máquina para agrupar sus cajones:
 * `~/.dotrino/service/<bóveda>/<ns>`. No viaja y no se compara con nada — solo evita que
 * dos bóvedas con un cajón del mismo nombre se pisen el directorio, que antes dejaba al
 * primero inservible.
 *
 * `--vault` y no `--profile`: `dotrino-vault --profile` ya significa otra cosa y los dos
 * comandos se usan seguidos.
 */
/**
 * La etiqueta de bóveda, si la hay. AL ENROLAR es obligatoria (`exigida: true`): ahí se está
 * creando el directorio y hay que decir de quién es. Para USARLO no: el `ns` se busca entre
 * las bóvedas enroladas y solo hace falta elegir si está en más de una (dueño, 2026-09-01).
 */
function etiquetaBoveda ({ exigida = false } = {}) {
  const v = resolveVaultLabel(flag('vault'))
  if (!v) {
    if (!exigida) return null
    console.error('falta --vault <nombre>  (o DOTRINO_ENV_VAULT)')
    console.error('')
    console.error('  Dice DE QUÉ BÓVEDA es este cajón. Es una etiqueta tuya, de esta máquina:')
    console.error('    ~/.dotrino/service/<bóveda>/<ns>')
    console.error('  Sirve para que dos bóvedas puedan tener un cajón llamado igual.')
    process.exit(2)
  }
  if (!isValidVaultLabel(v)) { console.error('etiqueta inválida: usa [a-z0-9-]{1,32}'); process.exit(2) }
  return v
}

async function cmdEnroll () {
  const ns = flag('ns')
  if (!ns) { console.error('falta --ns <ns>  (el mismo del `dotrino-vault pair --service <ns>`)'); process.exit(2) }
  const boveda = etiquetaBoveda({ exigida: true })
  const dir = flag('dir') || serviceDir(boveda, ns)
  const qr = parseInvite((flag('qr') || flag('code')) || await readInvite())

  console.log('\nEnrolando el servicio "%s" contra el vault…', ns)
  const { cert } = await enrollService({
    qr,
    ns,
    dir,
    label: flag('label') || 'service:' + ns,
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
  // El papel ya no vence: vale mientras el acta lo diga. Decir «vence» era describir un
  // reloj que ya no existe, y encima REVENTABA —`new Date(undefined).toISOString()` lanza
  // RangeError—, o sea que el comando de diagnóstico se caía justo cuando lo necesitas.
  console.log('Certificado con scope: %s  (%s)', (cert.scope || []).join(', '),
    typeof cert.seq === 'number' ? `acta #${cert.seq}` : `del modelo viejo, vence ${new Date(cert.exp).toISOString().slice(0, 10)}`)
  console.log('\nEn tu app:  import \'@dotrino/vault/config\'   (con DOTRINO_NS=%s)', ns)
}

function cmdStatus () {
  const found = listEnrolled()
  if (!found.length) {
    console.log('Ningún servicio enrolado en %s\n  Enrola uno:  dotrino-env enroll --vault <bóveda> --ns <ns>', serviceRoot())
    return
  }
  for (const e of found) {
    // LO QUE QUEDÓ EN EL FORMATO VIEJO se dice y no se usa. Repescarlo en silencio sería
    // fingir que la migración no hace falta; callarlo dejaría un servicio «desaparecido».
    if (e.legacy) {
      const viejo = path.join(serviceRoot(), e.ns)
      console.log('%s  ⚠ del formato anterior, sin la bóveda — no se usa', e.ns)
      console.log('  muévelo:  mkdir -p %s/<bóveda> && mv %s %s/<bóveda>/', serviceRoot(), viejo, serviceRoot())
      continue
    }
    const dir = serviceDir(e.vault, e.ns)
    const id = readServiceIdentity(dir)
    const c = id?.cert
    // El papel se describe por el ACTA a la que se ató. Uno del modelo viejo se dice tal
    // cual, con su fecha, porque ESO sí importa: es lo único que todavía caduca, y sabrá
    // el operador que le queda una migración por hacer.
    const papel = typeof c?.seq === 'number'
      ? `acta #${c.seq}`
      : (typeof c?.exp === 'number' ? `modelo viejo · vence ${new Date(c.exp).toISOString().slice(0, 10)}` : '?')
    console.log('%s/%s\n  dir:   %s\n  vault: %s…\n  scope: %s\n  cert:  %s',
      e.vault, e.ns, dir, String(id.iss).slice(0, 24), (c?.scope || []).join(', '), papel)
  }
}

async function cmdCheck () {
  const ns = resolveNs(flag('ns'))
  // `fetchSecrets` y no `loadEnv`: listar NO debe tener efectos secundarios. Con
  // `loadEnv` esto inyectaría el bundle en el entorno del propio `check`, que es
  // justo lo que un comando de diagnóstico no tiene por qué hacer.
  const secrets = await fetchSecrets({ dir: serviceDir(etiquetaBoveda(), ns), ns })
  const keys = Object.keys(secrets)
  console.log('ns "%s": %d secreto(s)%s', ns, keys.length, keys.length ? ':' : '')
  for (const k of keys) console.log('  ' + k)   // NUNCA los valores
  // Delata el `.env` rancio: qué claves de esta máquina el vault pisaría.
  const clashing = keys.filter((k) => k in process.env && process.env[k] !== String(secrets[k]))
  if (clashing.length) {
    console.log('\nEl vault PISA estos valores del entorno de esta máquina:\n  %s', clashing.join(', '))
  }
}

async function cmdRun () {
  const sep = argv.indexOf('--')
  const cmd = sep >= 0 ? argv.slice(sep + 1) : []
  if (!cmd.length) { console.error('uso: dotrino-env run [--vault <bóveda>] [--ns <ns>] [--public] -- <cmd> [args…]'); process.exit(2) }
  const onPending = () => console.error('[dotrino-env] waiting for approval on your phone…')
  // POR QUÉ SE REINTENTA, SIEMPRE. Sin esto la espera es muda: la bóveda contestaba, la
  // respuesta se caía por un motivo concreto —un aparato sin sobre en su cajón, por
  // ejemplo— y por fuera solo se veía «waiting for approval» una y otra vez, aunque el
  // dueño hubiera aprobado cada una. Un reintento que no dice su causa es un fallback: le
  // pone cara de espera a un error. (Ver CLAUDE.md, «nada de repliegues».)
  const onRetry = (e, ms) => console.error('[dotrino-env] failed: %s — retrying in %ds', e.message, Math.round(ms / 1000))
  // `--public`: SOLO las variables públicas, y por eso no hace sonar el teléfono de nadie.
  // La aprobación existe para soltar claves privadas; una pública está guardada en claro y
  // ya la ve quien administra. Es lo que quiere un arranque que solo necesita configuración
  // —una URL, un puerto— y no tiene por qué despertar al dueño.
  const publicOnly = argv.includes('--public')
  const { injected, overridden } = await loadEnv({ ns: flag('ns'), vault: etiquetaBoveda(), onPending, onRetry, publicOnly })
  console.error('[dotrino-env] %d valor(es) en el entorno de %s%s', injected.length, cmd[0],
    overridden.length ? ` (pisados: ${overridden.join(', ')})` : '')
  const child = spawn(cmd[0], cmd.slice(1), { stdio: 'inherit', env: process.env })
  child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 0)))
}

/**
 * Agente SSH con las llaves EN MEMORIA. Al arrancar pide su cajón a la bóveda (si este
 * aparato está marcado con `approval`, el teléfono tiene que decir que sí), carga las
 * variables `SSH_KEY_*` (el archivo de la llave, en base64) y sirve el protocolo de
 * `ssh-agent`. En el disco no queda nada; cerrar el agente es olvidar las llaves.
 *
 *   dotrino-vault secret set ssh SSH_KEY_DOTRINO "$(base64 -w0 ~/.ssh/id_ed25519)"
 *   dotrino-env ssh-agent --ns ssh          # imprime: export SSH_AUTH_SOCK=…
 */
async function cmdSshAgent () {
  const { startSshAgent, defaultSocketPath } = await import('../src/sshAgent.js')
  const { loadPrivateKey, publicLine } = await import('../src/sshKeys.js')
  const { serviceDir, resolveNs } = await import('../src/env.js')
  const { waitForSecrets } = await import('../src/service.js')
  const ns = resolveNs(flag('ns') || undefined)
  const dir = flag('dir') || serviceDir(etiquetaBoveda(), ns)
  const socketPath = flag('socket') || defaultSocketPath(dir)
  console.error('[dotrino-env] asking the vault for the keys of «%s»…', ns)
  const secrets = await waitForSecrets({ dir, ns, onPending: () => console.error('[dotrino-env] waiting for approval on your phone…') })
  const keys = []
  for (const [name, value] of Object.entries(secrets)) {
    if (!/^SSH_KEY_[A-Z0-9_]*$/.test(name)) continue
    try {
      const text = /^-----BEGIN/.test(value) ? value : Buffer.from(value, 'base64').toString('utf8')
      keys.push(loadPrivateKey(text, name.toLowerCase().replace(/_/g, '-')))
    } catch (e) { console.error('[dotrino-env] %s skipped: %s', name, e.message) }
  }
  if (!keys.length) { console.error('[dotrino-env] no SSH_KEY_* variables in «%s»: nothing to serve', ns); process.exit(1) }
  for (const k of keys) console.error('[dotrino-env] key %s %s', k.id, k.comment)
  const agent = startSshAgent({ socketPath, keys: () => keys, log: console.error })
  console.log('export SSH_AUTH_SOCK=%s', agent.socketPath)
  const stop = () => { agent.close(); process.exit(0) }
  process.on('SIGINT', stop); process.on('SIGTERM', stop)
  await new Promise(() => {})
}

const run = async () => {
  switch (argv[0]) {
    case 'enroll': return cmdEnroll()
    case 'status': return cmdStatus()
    case 'check': return cmdCheck()
    case 'run': return cmdRun()
    case 'ssh-agent': return cmdSshAgent()
    case undefined:
    case 'help':
    case '--help':
    case '-h': return help()
    default: console.error('comando desconocido: %s\n', argv[0]); help(); process.exit(2)
  }
}

run().catch((e) => { console.error('\n[dotrino-env] ' + e.message); process.exit(1) })
