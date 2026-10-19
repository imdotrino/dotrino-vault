/**
 * LA BÓVEDA EN UNA AWS LAMBDA (prueba de concepto). Ver `README.md`.
 *
 * Corre en uno de dos modos (`DOTRINO_VAULT_MODE`, el parámetro `Mode` de la pila):
 *
 *   · `vault`: una cuenta entera, con su primer administrador.
 *   · `replica`: el replicador (`src/replica.js`) de una cuenta que ya existe. No tiene
 *     maestra, no abre nada y entra al acta con la invitación de su dueño.
 *
 * Lo que atiende:
 *
 *   · `POST /wake?k=…` por su Function URL: la despierta el proxio. Comprueba el secreto, se
 *     invoca a sí misma en modo asíncrono y contesta 202 al instante: el proxio no se queda
 *     esperando una sesión que puede durar minutos.
 *   · `{ kind: 'session' }` (esa invocación asíncrona): una sesión (`./session.mjs`).
 *   · el recurso personalizado de CloudFormation: el primer arranque.
 *   · solo `replica`, y solo quien puede invocar la función (la cuenta de AWS que la creó):
 *     `{ kind: 'enroll', invitation }` lanza el alta y devuelve el código que el dueño aprueba
 *     en su bóveda; `{ kind: 'status' }` dice si ya está enrolada.
 *
 * Variables de entorno (las pone la plantilla):
 *
 *   DOTRINO_VAULT_MODE     `vault` (por defecto) o `replica`
 *   DOTRINO_VAULT_BUCKET   el bucket del perfil
 *   DOTRINO_VAULT_PREFIX   prefijo dentro del bucket (por defecto `vault/`)
 *   DOTRINO_KMS_KEY_ID     la llave de KMS que envuelve la del disco
 *   DOTRINO_PROXY_URL      el proxio (por defecto el de producción)
 */
import path from 'node:path'

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
process.env.DOTRINO_KMS_SCRIPT ||= path.join(process.env.LAMBDA_TASK_ROOT || '/var/task', 'packaging', 'kms-aws.mjs')

async function store () {
  const bucket = process.env.DOTRINO_VAULT_BUCKET
  if (!bucket) throw Object.assign(new Error('DOTRINO_VAULT_BUCKET is not set'), { code: 'no-bucket' })
  // SIN KMS NO SE ARRANCA. Sin él la llave del disco saldría de la máquina, y en Lambda la
  // máquina cambia con cada contenedor: la cuenta quedaría ilegible al primer frío.
  if (!process.env.DOTRINO_KMS_KEY_ID) throw Object.assign(new Error('DOTRINO_KMS_KEY_ID is not set'), { code: 'no-kms' })
  const { s3Store } = await import('./mirror.mjs')
  return s3Store({ bucket, prefix: process.env.DOTRINO_VAULT_PREFIX ?? 'vault/' })
}

async function session (context, { wakeBase, idleMs, onReady } = {}) {
  const { runSession, vaultStarter, replicaStarter } = await import('./session.mjs')
  const fs = await import('node:fs')
  // Un contenedor que ya atendió una sesión tiene el perfil viejo en /tmp: se empieza de cero.
  fs.rmSync(DIR, { recursive: true, force: true })
  const start = MODE === 'replica'
    ? replicaStarter({ runReplica: (await import('../src/replica.js')).runReplica })
    : vaultStarter({ startVault: (await import('../src/vault.js')).startVault, onReady })
  return runSession({
    store: await store(), dir: DIR, start,
    proxyUrl: process.env.DOTRINO_PROXY_URL || undefined,
    wakeBase,
    deadline: Date.now() + context.getRemainingTimeInMillis() - END_MARGIN_MS,
    ...(idleMs !== undefined ? { idleMs } : {}),
    owner: context.awsRequestId,
    log: console.log
  })
}

const replicaOnly = () => {
  if (MODE !== 'replica') throw Object.assign(new Error(`this function runs a ${MODE}, not a replica`), { code: 'not-a-replica' })
}

/**
 * EL ALTA, desde fuera (`{ kind:'enroll', invitation }`). Contestar tiene que ser rápido y
 * esperar la aprobación no: se lanza el alta como otra invocación y aquí se espera solo a que
 * la réplica deje su código en el almacén.
 */
async function onEnroll (event, context) {
  replicaOnly()
  const invitation = typeof event.invitation === 'string' ? event.invitation.trim() : ''
  if (!invitation) return { ok: false, error: 'no-invitation' }
  const { PAIRING_FILE } = await import('./session.mjs')
  const st = await store()
  const req = context.awsRequestId
  const { LambdaClient, InvokeCommand } = await import('@aws-sdk/client-lambda')
  await new LambdaClient({}).send(new InvokeCommand({
    FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
    InvocationType: 'Event',
    Payload: Buffer.from(JSON.stringify({ kind: 'enroll-run', invitation, req }))
  }))
  const until = Date.now() + CODE_WAIT_MS
  while (Date.now() < until) {
    await new Promise((resolve) => setTimeout(resolve, 500))
    let got = null
    try { got = JSON.parse((await st.get(PAIRING_FILE)).body.toString('utf8')) } catch (e) { if (e.code !== 'ENOENT' && e.name !== 'NoSuchKey') throw e }
    if (got?.req !== req) continue
    if (got.error) return { ok: false, error: got.error, message: got.message || '' }
    return { ok: true, deviceId: got.deviceId, code: got.code }
  }
  return { ok: false, error: 'no-code', message: 'the replica did not get a code from the vault in time' }
}

/** El alta de verdad: espera la aprobación del dueño y luego el primer empujón de su bóveda. */
async function onEnrollRun (event, context) {
  replicaOnly()
  const { enrollReplica, PAIRING_FILE } = await import('./session.mjs')
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { openReplicaStore, REPLICA_SCOPE } = await import('../src/replica.js')
  const { keyLabel } = await import('@dotrino/identity/capabilities')
  const fs = await import('node:fs')
  const st = await store()
  fs.rmSync(DIR, { recursive: true, force: true })
  const deadline = Date.now() + context.getRemainingTimeInMillis() - END_MARGIN_MS
  try {
    await enrollReplica({ store: st, dir: DIR, invitation: event.invitation, req: event.req, deadline: deadline - FIRST_PUSH_IDLE_MS - 15_000, owner: context.awsRequestId, enrollWithVault, openReplicaStore, keyLabel, scope: REPLICA_SCOPE, log: console.log })
  } catch (e) {
    console.error(`[vault-lambda] replica enrollment failed: ${e.code || ''} ${e.message}`)
    // Quien espera el código tiene que enterarse de que no va a llegar, y por qué.
    await st.put(PAIRING_FILE, Buffer.from(JSON.stringify({ req: event.req, error: e.code || 'enroll-failed', message: e.message, ts: Date.now() })))
    return { ok: false, error: e.code || 'enroll-failed' }
  }
  // Ya está en el acta: una sesión corta para recibir el primer empujón y registrar el timbre.
  let wakeBase = null
  try { wakeBase = (await st.get(URL_FILE)).body.toString('utf8').trim() || null } catch (e) { if (e.code !== 'ENOENT' && e.name !== 'NoSuchKey') throw e }
  const r = await session(context, { wakeBase, idleMs: FIRST_PUSH_IDLE_MS })
  return { ok: true, reason: r.reason }
}

async function onStatus () {
  replicaOnly()
  const { replicaStatus } = await import('./session.mjs')
  const { openReplicaStore } = await import('../src/replica.js')
  const { keyLabel } = await import('@dotrino/identity/capabilities')
  const fs = await import('node:fs')
  const dir = '/tmp/dotrino-vault/status'
  fs.rmSync(dir, { recursive: true, force: true })
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
 * dado de alta, `ensureAdmin` no la pide. En modo `replica` no nace nada.
 */
async function onStack (event, context) {
  if (event.RequestType === 'Delete') return answerStack(event, 'SUCCESS')
  try {
    const p = event.ResourceProperties || {}
    if (p.FunctionUrl) await (await store()).put(URL_FILE, Buffer.from(p.FunctionUrl))
    if (MODE === 'replica') {
      console.log('[vault-lambda] replica: waiting for its owner to enroll it')
      return answerStack(event, 'SUCCESS')
    }
    const { ensureAdmin } = await import('./bootstrap.mjs')
    const { ready } = await session(context, {
      wakeBase: p.FunctionUrl, idleMs: 0,
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

export async function handler (event, context) {
  if (event?.RequestType && event?.ResponseURL) return onStack(event, context)
  if (event?.requestContext?.http) return onWake(event)
  if (event?.kind === 'session') {
    const r = await session(context, { wakeBase: event.wakeBase })
    return { ok: true, reason: r.reason }
  }
  try {
    if (event?.kind === 'enroll') return await onEnroll(event, context)
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
