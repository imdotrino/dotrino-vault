/**
 * LA BÓVEDA EN UNA AWS LAMBDA (prueba de concepto). Ver `README.md`.
 *
 * Corre en uno de tres modos (`DOTRINO_VAULT_MODE`, el parámetro `Mode` de la pila):
 *
 *   · `vault`: una cuenta entera, con su primer administrador.
 *   · `replica`: el replicador (`src/replica.js`) de una cuenta que ya existe. No tiene
 *     maestra, no abre nada y entra al acta con la invitación de su dueño.
 *   · `demo`: como `vault`, más el agente de Dotrino Terminal en el mismo proceso, para quien
 *     revisa la app en una tienda (`./demo.mjs`).
 *   · `join`: una SEGUNDA BÓVEDA de una cuenta que ya existe (la de $5 de `dotrino-accounts`).
 *     Tiene maestra y sella, entra con la invitación de su dueño, y la maestra va sellada con
 *     la contraseña que él puso (`lock.mjs`): cerrada sirve, y se abre desde su consola.
 *
 * Lo que atiende:
 *
 *   · `POST /wake?k=…` por su Function URL: la despierta el proxio. Comprueba el secreto, se
 *     invoca a sí misma en modo asíncrono y contesta 202 al instante: el proxio no se queda
 *     esperando una sesión que puede durar minutos.
 *   · `{ kind: 'session' }` (esa invocación asíncrona): una sesión (`./session.mjs`).
 *   · el recurso personalizado de CloudFormation: el primer arranque.
 *   · solo `replica` y `join`, y solo quien puede invocar la función (la cuenta de AWS que la
 *     creó): `{ kind: 'enroll', invitation }` lanza el alta y devuelve el código que el dueño
 *     aprueba en su bóveda —en `join`, antes, `{ ek, salt, … }` para la contraseña, que vuelve
 *     sellada con `{ kind: 'enroll-door', req, enc }`—; `{ kind: 'status' }` dice si ya está.
 *
 * Variables de entorno (las pone la plantilla):
 *
 *   DOTRINO_VAULT_MODE     `vault` (por defecto), `replica`, `join` o `demo`
 *   DOTRINO_VAULT_BUCKET   el bucket del perfil
 *   DOTRINO_VAULT_PREFIX   prefijo dentro del bucket (por defecto `vault/`)
 *   DOTRINO_KMS_KEY_ID     la llave de KMS que envuelve la del disco
 *   DOTRINO_PROXY_URL      el proxio (por defecto el de producción)
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const DIR = '/tmp/dotrino-vault/profile'
/** Lo que tarda como mucho la réplica en pedir el código, desde que se lanza el alta. */
const CODE_WAIT_MS = 40_000
/** Tras enrolarse, lo que se queda conectada esperando el primer empujón de la bóveda. */
const FIRST_PUSH_IDLE_MS = 30_000
/** La URL de la función, apuntada en el primer arranque: el alta la necesita para el timbre. */
const URL_FILE = '.function-url'

const MODE = process.env.DOTRINO_VAULT_MODE || 'vault'
/** Margen antes del tope de la función para desconectarse y guardar. */
const END_MARGIN_MS = 45_000

// Antes de cargar nada de la bóveda: en Lambda solo se puede escribir en `/tmp`, y el
// proveedor de KMS se busca donde lo deja la imagen del contenedor, que aquí es otra.
process.env.HOME = '/tmp'
// El de ESTE código, no el de `LAMBDA_TASK_ROOT`: con el cargador (`code.mjs`) puede correr una
// versión desempaquetada en `/tmp`, y su proveedor de KMS es el que trae ella. Una ruta que
// pusiera otro (la imagen de un contenedor) se respeta.
if (!process.env.DOTRINO_KMS_SCRIPT || process.env.DOTRINO_KMS_SCRIPT_FROM_LAMBDA) {
  process.env.DOTRINO_KMS_SCRIPT = fileURLToPath(new URL('../packaging/kms-aws.mjs', import.meta.url))
  process.env.DOTRINO_KMS_SCRIPT_FROM_LAMBDA = '1'
}
/** La versión de este código (el `package.json` que viaja en el zip). */
const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version

async function store () {
  const bucket = process.env.DOTRINO_VAULT_BUCKET
  if (!bucket) throw Object.assign(new Error('DOTRINO_VAULT_BUCKET is not set'), { code: 'no-bucket' })
  // SIN KMS NO SE ARRANCA. Sin él la llave del disco saldría de la máquina, y en Lambda la
  // máquina cambia con cada contenedor: la cuenta quedaría ilegible al primer frío.
  if (!process.env.DOTRINO_KMS_KEY_ID) throw Object.assign(new Error('DOTRINO_KMS_KEY_ID is not set'), { code: 'no-kms' })
  const { s3Store } = await import('./mirror.mjs')
  return s3Store({ bucket, prefix: process.env.DOTRINO_VAULT_PREFIX ?? 'vault/' })
}

/** `code/` del mismo bucket: el código que corre la función (`code.mjs`, `update.mjs`). */
async function codeStore () {
  const { s3Store } = await import('./mirror.mjs')
  const { CODE_PREFIX } = await import('./code.mjs')
  return s3Store({ bucket: process.env.DOTRINO_VAULT_BUCKET, prefix: CODE_PREFIX })
}

/**
 * MIRAR SI HAY VERSIÓN NUEVA mientras dura la sesión (`update.mjs`), y contarlo si esta es la
 * que acaba de entrar. Va por detrás: la sesión no espera a esto para atender, pero no se
 * apaga mientras siga (`busy`). La demo no se actualiza: su código no va en la release.
 */
function withFreshCode (start, { deadline, vaultOf }) {
  return async (args) => {
    const piece = await start(args)
    let running = (async () => {
      const [{ updateCode, announceIfNew }, code, upd, settings, approval] = await Promise.all([
        import('./update.mjs'), codeStore(), import('@dotrino/update'), import('../src/settings.js'), import('../src/updateApproval.js')
      ])
      const { fetchVerified } = await import('@dotrino/update/fetch')
      const vault = vaultOf()
      if (vault) await announceIfNew({ store: code, myVersion: VERSION, vault, log: args.log })
      await updateCode({
        store: code, dir: args.dir, myVersion: VERSION, vault, deadline: deadline - 30_000, log: args.log,
        deps: {
          latestRelease: () => upd.latestVersion({ source: 'github', repo: REPO, product: 'dotrino-vault', version: VERSION }),
          isNewer: upd.isNewer, fetchVerified, checkEveryMs: upd.CHECK_EVERY_MS, repo: REPO,
          readSettings: settings.readSettings, firstYes: approval.firstYes, readAsked: approval.readAsked,
          writeAsked: approval.writeAsked, clearAsked: approval.clearAsked, shouldAsk: approval.shouldAsk
        }
      })
    })().catch((e) => args.log(`[vault-lambda] update: ${e.code || ''} ${e.message}`)).finally(() => { running = null })
    return { ...piece, busy: () => piece.busy() || !!running, why: () => [piece.why?.(), running ? 'checking for a new version' : null].filter(Boolean).join(' · ') }
  }
}

const REPO = 'imdotrino/dotrino-vault'

async function session (context, { wakeBase, idleMs, onReady, lock = null, update = true } = {}) {
  const { runSession, vaultStarter, replicaStarter } = await import('./session.mjs')
  const fs = await import('node:fs')
  // Un contenedor que ya atendió una sesión tiene el perfil viejo en /tmp: se empieza de cero.
  fs.rmSync(DIR, { recursive: true, force: true })
  let vaultRef = null
  const keep = async (v) => { vaultRef = v; return onReady ? onReady(v) : null }
  let start
  if (MODE === 'replica') start = replicaStarter({ runReplica: (await import('../src/replica.js')).runReplica })
  else if (MODE === 'demo') {
    // El agente solo está en el zip de la demo (`build.sh --demo`).
    const { demoStarter, DEMO_IDLE_MS, pipePtyWhenNoTerminal } = await import('./demo.mjs')
    const agentEntry = import.meta.resolve('@dotrino/terminal-agent')
    if (pipePtyWhenNoTerminal(new URL(agentEntry).pathname)) console.log('[vault-lambda] no pseudo-terminals here: the demo consoles run over pipes')
    const { startAgent } = await import('@dotrino/terminal-agent')
    // El enlace es el del pilar que trae el agente: puede ir anidado bajo él, no en la raíz.
    const { createRequire } = await import('node:module')
    const { pathToFileURL } = await import('node:url')
    const linkPath = createRequire(import.meta.resolve('@dotrino/terminal-agent')).resolve('@dotrino/remote-agent/link')
    const { enroll, loadLink } = await import(pathToFileURL(linkPath).href)
    start = demoStarter({ startVault: (await import('../src/vault.js')).startVault, startAgent, enroll, loadLink, onReady })
    idleMs ??= DEMO_IDLE_MS
  } else start = vaultStarter({ startVault: (await import('../src/vault.js')).startVault, onReady: keep, locked: MODE === 'join', lock })
  const deadline = Date.now() + context.getRemainingTimeInMillis() - END_MARGIN_MS
  if (update && MODE !== 'demo') start = withFreshCode(start, { deadline, vaultOf: () => vaultRef })
  return runSession({
    store: await store(), dir: DIR, start,
    proxyUrl: process.env.DOTRINO_PROXY_URL || undefined,
    wakeBase,
    deadline,
    ...(idleMs !== undefined ? { idleMs } : {}),
    owner: context.awsRequestId,
    log: console.log
  })
}

/** Solo lo que entra en una cuenta ajena tiene alta: la réplica y la segunda bóveda. */
const enrollable = () => {
  if (MODE !== 'replica' && MODE !== 'join') throw Object.assign(new Error(`this function runs a ${MODE}: it does not join an account`), { code: 'not-enrollable' })
}

/** Espera en `PAIRING_FILE` lo que la alta deje para `req` y cumpla `ready`. */
async function waitPairing (st, req, ready, waitMs) {
  const { PAIRING_FILE } = await import('./session.mjs')
  const until = Date.now() + waitMs
  while (Date.now() < until) {
    await new Promise((resolve) => setTimeout(resolve, 500))
    let got = null
    try { got = JSON.parse((await st.get(PAIRING_FILE)).body.toString('utf8')) } catch (e) { if (e.code !== 'ENOENT' && e.name !== 'NoSuchKey') throw e }
    if (got?.req !== req) continue
    if (got.error) return { ok: false, error: got.error, message: got.message || '' }
    if (ready(got)) return { ok: true, got }
  }
  return null
}

/**
 * EL ALTA, desde fuera (`{ kind:'enroll', invitation }`). Contestar tiene que ser rápido y
 * esperar la aprobación no: se lanza el alta como otra invocación y aquí se espera solo a que
 * la réplica deje su código en el almacén.
 */
async function onEnroll (event, context) {
  enrollable()
  const invitation = typeof event.invitation === 'string' ? event.invitation.trim() : ''
  if (!invitation) return { ok: false, error: 'no-invitation' }
  const st = await store()
  const req = context.awsRequestId
  const { LambdaClient, InvokeCommand } = await import('@aws-sdk/client-lambda')
  await new LambdaClient({}).send(new InvokeCommand({
    FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
    InvocationType: 'Event',
    Payload: Buffer.from(JSON.stringify({ kind: 'enroll-run', invitation, req }))
  }))
  // La segunda bóveda pide antes la contraseña: devuelve con qué derivarla y a qué sellarla.
  if (MODE === 'join') {
    const r = await waitPairing(st, req, (got) => got.phase === 'door', CODE_WAIT_MS)
    if (!r) return { ok: false, error: 'no-door', message: 'the vault did not get ready for the password in time' }
    if (!r.ok) return r
    const { ek, salt, N, r: rr, p, len } = r.got
    return { ok: true, req, door: { ek, salt, N, r: rr, p, len } }
  }
  const r = await waitPairing(st, req, (got) => !!got.code, CODE_WAIT_MS)
  if (!r) return { ok: false, error: 'no-code', message: 'the replica did not get a code from the vault in time' }
  if (!r.ok) return r
  return { ok: true, deviceId: r.got.deviceId, code: r.got.code }
}

/**
 * LA CONTRASEÑA DE LA SEGUNDA BÓVEDA, sellada a la efímera del alta (`{ kind:'enroll-door',
 * req, enc }`). Quien la trae no puede leerla. Se deja donde la espera el alta y se devuelve
 * el código que el dueño teclea en su bóveda.
 */
async function onEnrollDoor (event) {
  if (MODE !== 'join') throw Object.assign(new Error(`this function runs a ${MODE}: it takes no password`), { code: 'not-join' })
  const req = typeof event.req === 'string' ? event.req : ''
  if (!req || !event.enc) return { ok: false, error: 'bad-door' }
  const { DOOR_FILE } = await import('./session.mjs')
  const st = await store()
  await st.put(DOOR_FILE, Buffer.from(JSON.stringify({ req, enc: event.enc, ts: Date.now() })))
  const r = await waitPairing(st, req, (got) => !!got.code, CODE_WAIT_MS)
  if (!r) return { ok: false, error: 'no-code', message: 'the vault did not get a code in time' }
  if (!r.ok) return r
  return { ok: true, deviceId: r.got.deviceId, code: r.got.code }
}

/** El alta de verdad: espera la aprobación del dueño y luego el primer empujón de su bóveda. */
async function onEnrollRun (event, context) {
  enrollable()
  const { enrollReplica, enrollJoin, PAIRING_FILE } = await import('./session.mjs')
  const fs = await import('node:fs')
  const st = await store()
  fs.rmSync(DIR, { recursive: true, force: true })
  const deadline = Date.now() + context.getRemainingTimeInMillis() - END_MARGIN_MS
  const account = process.env.DOTRINO_REPLICA_OWNER || ''
  let lock = null
  try {
    if (MODE === 'join') {
      const { nodePlatform } = await import('../src/platform.js')
      const { parseInvite } = await import('../lib/src/invite.js')
      const { makeEphemeralKey, openSealed } = await import('../lib/src/sealed.js')
      const r = await enrollJoin({
        store: st, dir: DIR, invitation: event.invitation, account, req: event.req,
        deadline: deadline - FIRST_PUSH_IDLE_MS - 15_000, owner: context.awsRequestId,
        openIdentity: ({ dir, openKey }) => nodePlatform(dir).openIdentity({ openKey: openKey ? () => openKey() : null, log: console.log }),
        parseInvite, makeEphemeralKey, openSealed, log: console.log
      })
      lock = r.lock
    } else {
      const { enrollWithVault } = await import('../lib/src/service.js')
      const { openReplicaStore, REPLICA_SCOPE } = await import('../src/replica.js')
      const { keyLabel } = await import('@dotrino/identity/capabilities')
      await enrollReplica({ store: st, dir: DIR, invitation: event.invitation, account, req: event.req, deadline: deadline - FIRST_PUSH_IDLE_MS - 15_000, owner: context.awsRequestId, enrollWithVault, openReplicaStore, keyLabel, scope: REPLICA_SCOPE, log: console.log })
    }
  } catch (e) {
    console.error(`[vault-lambda] enrollment failed: ${e.code || ''} ${e.message}`)
    // Quien espera el código tiene que enterarse de que no va a llegar, y por qué.
    await st.put(PAIRING_FILE, Buffer.from(JSON.stringify({ req: event.req, error: e.code || 'enroll-failed', message: e.message, ts: Date.now() })))
    return { ok: false, error: e.code || 'enroll-failed' }
  }
  // Ya está en el acta: una sesión corta para recibir el primer empujón y registrar el timbre.
  // La segunda bóveda la hace con el candado que acaba de nacer, todavía abierto: es el
  // momento de absorber el acta donde la admitieron y estrenar su llave de comunicación.
  let wakeBase = null
  try { wakeBase = (await st.get(URL_FILE)).body.toString('utf8').trim() || null } catch (e) { if (e.code !== 'ENOENT' && e.name !== 'NoSuchKey') throw e }
  try {
    const r = await session(context, { wakeBase, idleMs: FIRST_PUSH_IDLE_MS, lock })
    return { ok: true, reason: r.reason }
  } finally { lock?.close() }
}

async function onStatus () {
  enrollable()
  const fs = await import('node:fs')
  const dir = '/tmp/dotrino-vault/status'
  fs.rmSync(dir, { recursive: true, force: true })
  if (MODE === 'join') {
    const { joinStatus } = await import('./session.mjs')
    const { nodePlatform } = await import('../src/platform.js')
    return { ok: true, ...(await joinStatus({ store: await store(), dir, openIdentity: ({ dir: d }) => nodePlatform(d).openIdentity({ log: () => {} }) })) }
  }
  const { replicaStatus } = await import('./session.mjs')
  const { openReplicaStore } = await import('../src/replica.js')
  const { keyLabel } = await import('@dotrino/identity/capabilities')
  return { ok: true, ...(await replicaStatus({ store: await store(), dir, openReplicaStore, keyLabel })) }
}

const reply = (statusCode, obj) => ({ statusCode, headers: { 'content-type': 'application/json' }, body: JSON.stringify(obj) })

async function onWake (event) {
  const http = event.requestContext.http
  if (http.method !== 'POST' || http.path !== '/wake') return reply(404, { error: 'not found' })
  const { wakeSecret, sameSecret } = await import('./session.mjs')
  let secret
  try { secret = await wakeSecret(await store()) } catch (e) {
    // Sin secreto no hay bóveda que despertar: el 404 hace que el proxio quite el timbre.
    if (e.code === 'no-wake-secret') return reply(404, { error: 'no vault here' })
    throw e
  }
  if (!sameSecret(event.queryStringParameters?.k, secret)) return reply(403, { error: 'forbidden' })
  const { LambdaClient, InvokeCommand } = await import('@aws-sdk/client-lambda')
  await new LambdaClient({}).send(new InvokeCommand({
    FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
    InvocationType: 'Event',
    Payload: Buffer.from(JSON.stringify({ kind: 'session', wakeBase: `https://${event.requestContext.domainName}` }))
  }))
  return reply(202, { ok: true })
}

/** La respuesta a CloudFormation: un PUT a la URL firmada que trae el evento. */
async function answerStack (event, status, { reason = '', data = {} } = {}) {
  const body = JSON.stringify({
    Status: status, Reason: reason.slice(0, 1000) || status,
    PhysicalResourceId: event.PhysicalResourceId || `dotrino-vault-${event.LogicalResourceId}`,
    StackId: event.StackId, RequestId: event.RequestId, LogicalResourceId: event.LogicalResourceId, Data: data
  })
  const r = await fetch(event.ResponseURL, { method: 'PUT', headers: { 'content-type': '' }, body })
  if (!r.ok) console.error(`[vault-lambda] CloudFormation did not take the answer: HTTP ${r.status}`)
}

/**
 * AL CREAR LA PILA. Se apunta la URL de la función (la necesita el alta de una réplica para su
 * timbre). En modo `vault`, además, la primera sesión, sin esperar mensajes (`idleMs: 0`): nace
 * la cuenta, se registra la URL de despertar y se da de alta al administrador con la contraseña
 * que trae la pila (un parámetro NoEcho). Solo se usa la primera vez: con el administrador ya
 * dado de alta, `ensureAdmin` no la pide. En `replica` y `join` no nace nada: entran en la cuenta de su dueño con el alta.
 */
async function onStack (event, context) {
  if (event.RequestType === 'Delete') return answerStack(event, 'SUCCESS')
  try {
    const p = event.ResourceProperties || {}
    if (p.FunctionUrl) await (await store()).put(URL_FILE, Buffer.from(p.FunctionUrl))
    if (MODE === 'replica' || MODE === 'join') {
      console.log(`[vault-lambda] ${MODE}: waiting for its owner to enroll it`)
      return answerStack(event, 'SUCCESS')
    }
    const { ensureAdmin } = await import('./bootstrap.mjs')
    const { ready } = await session(context, {
      // El primer arranque no se actualiza: CloudFormation está esperando la respuesta.
      wakeBase: p.FunctionUrl, idleMs: 0, update: false,
      onReady: (vault) => ensureAdmin(vault, {
        user: p.AdminUser || 'admin',
        password: async () => {
          if (!p.AdminPassword) throw Object.assign(new Error('no admin password in the stack: the admin user must be created by hand'), { code: 'no-admin-password' })
          return p.AdminPassword
        }
      })
    })
    console.log(`[vault-lambda] admin ${ready.created ? 'created' : 'already there'}: ${ready.address}`)
    await answerStack(event, 'SUCCESS', { data: { Login: ready.address, Account: ready.account } })
  } catch (e) {
    console.error(`[vault-lambda] first start failed: ${e.code || ''} ${e.message}`)
    await answerStack(event, 'FAILED', { reason: `${e.code || 'error'}: ${e.message}` })
  }
}

/**
 * EL CÓDIGO FRESCO (`code.mjs`): si el bucket apunta a una versión más nueva que esta, la
 * invocación entera la atiende esa. Si lo apuntado no se puede cargar, se para y se dice.
 */
export async function handler (event, context) {
  if (MODE !== 'demo') {
    const { freshHandler } = await import('./code.mjs')
    const { isNewer } = await import('@dotrino/update')
    const fresh = await freshHandler({ store: await codeStore(), myVersion: VERSION, isNewer, log: console.log })
    if (fresh) return fresh(event, context)
  }
  return ownHandler(event, context)
}

async function ownHandler (event, context) {
  if (event?.RequestType && event?.ResponseURL) return onStack(event, context)
  if (event?.requestContext?.http) return onWake(event)
  if (event?.kind === 'session') {
    const r = await session(context, { wakeBase: event.wakeBase })
    return { ok: true, reason: r.reason }
  }
  try {
    if (event?.kind === 'enroll') return await onEnroll(event, context)
    if (event?.kind === 'enroll-door') return await onEnrollDoor(event)
    if (event?.kind === 'enroll-run') return await onEnrollRun(event, context)
    if (event?.kind === 'status') return await onStatus()
  } catch (e) {
    console.error(`[vault-lambda] ${event.kind}: ${e.code || ''} ${e.message}`)
    return { ok: false, error: e.code || 'error', message: e.message }
  }
  console.error('[vault-lambda] unknown event')
  return { ok: false, error: 'unknown event' }
}

export default { handler }
