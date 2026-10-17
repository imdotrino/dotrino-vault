/**
 * LA BÓVEDA EN UNA AWS LAMBDA (prueba de concepto). Ver `README.md`.
 *
 * La función atiende tres cosas:
 *
 *   · `POST /wake?k=…` por su Function URL: la despierta el proxio. Comprueba el secreto, se
 *     invoca a sí misma en modo asíncrono y contesta 202 al instante: el proxio no se queda
 *     esperando una sesión que puede durar minutos.
 *   · `{ kind: 'session' }` (esa invocación asíncrona): una sesión (`./session.mjs`).
 *   · el recurso personalizado de CloudFormation: al crear la pila arranca la bóveda por
 *     primera vez, da de alta al administrador y devuelve su dirección para los Outputs.
 *
 * Variables de entorno (las pone la plantilla):
 *
 *   DOTRINO_VAULT_BUCKET   el bucket del perfil
 *   DOTRINO_VAULT_PREFIX   prefijo dentro del bucket (por defecto `vault/`)
 *   DOTRINO_KMS_KEY_ID     la llave de KMS que envuelve la del disco
 *   DOTRINO_PROXY_URL      el proxio (por defecto el de producción)
 */
import path from 'node:path'

const DIR = '/tmp/dotrino-vault/profile'
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
  const { runSession } = await import('./session.mjs')
  const { startVault } = await import('../src/vault.js')
  const fs = await import('node:fs')
  // Un contenedor que ya atendió una sesión tiene el perfil viejo en /tmp: se empieza de cero.
  fs.rmSync(DIR, { recursive: true, force: true })
  return runSession({
    store: await store(), dir: DIR, startVault,
    proxyUrl: process.env.DOTRINO_PROXY_URL || undefined,
    wakeBase,
    deadline: Date.now() + context.getRemainingTimeInMillis() - END_MARGIN_MS,
    ...(idleMs !== undefined ? { idleMs } : {}),
    onReady,
    owner: context.awsRequestId,
    log: console.log
  })
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
 * AL CREAR LA PILA: la primera sesión, sin esperar mensajes (`idleMs: 0`). Nace la cuenta, se
 * registra la URL de despertar y se da de alta al administrador. La contraseña se lee de
 * Secrets Manager y, una vez usada, se reescribe el secreto para que no quede en AWS.
 */
async function onStack (event, context) {
  if (event.RequestType === 'Delete') return answerStack(event, 'SUCCESS')
  try {
    const p = event.ResourceProperties || {}
    const { ensureAdmin } = await import('./bootstrap.mjs')
    const { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } = await import('@aws-sdk/client-secrets-manager')
    const sm = new SecretsManagerClient({})
    let used = false
    const { ready } = await session(context, {
      wakeBase: p.FunctionUrl, idleMs: 0,
      onReady: (vault) => ensureAdmin(vault, {
        user: p.AdminUser || 'admin',
        password: async () => {
          const s = await sm.send(new GetSecretValueCommand({ SecretId: p.AdminSecretArn }))
          const pwd = JSON.parse(s.SecretString || '{}').password
          if (!pwd) throw Object.assign(new Error('the admin password was already used or is empty: the admin user already exists or must be created by hand'), { code: 'no-admin-password' })
          used = true
          return pwd
        }
      })
    })
    if (used) await sm.send(new PutSecretValueCommand({ SecretId: p.AdminSecretArn, SecretString: JSON.stringify({ used: true }) }))
    console.log(`[vault-lambda] admin ${ready.created ? 'created' : 'already there'}: ${ready.address}`)
    await answerStack(event, 'SUCCESS', { data: { Login: ready.address } })
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
  console.error('[vault-lambda] unknown event')
  return { ok: false, error: 'unknown event' }
}

export default { handler }
