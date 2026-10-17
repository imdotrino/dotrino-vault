/**
 * LA BÓVEDA EN UNA AWS LAMBDA (prueba de concepto). Ver `README.md`.
 *
 * Una sola función, sin VPC: recibe por HTTP (Function URL o API Gateway), guarda el perfil
 * en S3 y saca la llave del disco de KMS. Variables de entorno:
 *
 *   DOTRINO_VAULT_BUCKET   (obligatoria)  el bucket del perfil
 *   DOTRINO_VAULT_PREFIX                  prefijo dentro del bucket (por defecto `vault/`)
 *   DOTRINO_KMS_KEY_ID     (obligatoria)  la llave de KMS que envuelve la del disco
 *   DOTRINO_PROXY_URL                     el proxio (por defecto el de producción)
 *
 * La concurrencia reservada va en 1: dos contenedores a la vez se pisarían el perfil. Si
 * aun así pasa (un contenedor viejo que despierta), la escritura condicional lo para y la
 * petición vuelve con 503 para que se reintente sobre el estado bueno.
 */
import path from 'node:path'

const DIR = '/tmp/dotrino-vault/profile'

// Antes de cargar nada de la bóveda: en Lambda solo se puede escribir en `/tmp`, y el
// proveedor de KMS se busca donde lo deja la imagen del contenedor, que aquí es otra.
process.env.HOME = '/tmp'
process.env.DOTRINO_KMS_SCRIPT ||= path.join(process.env.LAMBDA_TASK_ROOT || '/var/task', 'packaging', 'kms-aws.mjs')

let opening = null

async function desk () {
  if (!opening) {
    opening = (async () => {
      const bucket = process.env.DOTRINO_VAULT_BUCKET
      if (!bucket) throw Object.assign(new Error('DOTRINO_VAULT_BUCKET is not set'), { code: 'no-bucket' })
      // SIN KMS NO SE ARRANCA. Sin él la llave del disco saldría de la máquina, y en Lambda
      // la máquina cambia con cada contenedor: la cuenta quedaría ilegible al primer frío.
      if (!process.env.DOTRINO_KMS_KEY_ID) throw Object.assign(new Error('DOTRINO_KMS_KEY_ID is not set'), { code: 'no-kms' })
      const { s3Store } = await import('./mirror.mjs')
      const { openDesk } = await import('./desk.mjs')
      const { startVault } = await import('../src/vault.js')
      const store = await s3Store({ bucket, prefix: process.env.DOTRINO_VAULT_PREFIX ?? 'vault/' })
      return openDesk({ store, dir: DIR, startVault, proxyUrl: process.env.DOTRINO_PROXY_URL || undefined, log: console.log })
    })()
    opening.catch(() => { opening = null })
  }
  return opening
}

export async function handler (event) {
  const { answerHttp } = await import('./desk.mjs')
  const body = event?.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString('utf8') : (event?.body || '')
  const r = await answerHttp(desk, { method: event?.requestContext?.http?.method || event?.httpMethod, body }, {
    onConflict: () => { opening = null },
    log: console.error
  })
  return { statusCode: r.statusCode, headers: { 'content-type': 'application/json' }, body: JSON.stringify(r.body) }
}

export default { handler }
