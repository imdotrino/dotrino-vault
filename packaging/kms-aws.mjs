#!/usr/bin/env node
/**
 * kms-aws.mjs — envuelve y desenvuelve la clave del disco con AWS KMS.
 *
 * Cumple el contrato de `lib/src/kek.js`: **base64 por la entrada, base64 por la salida**.
 *
 *   kms-aws.mjs wrap    < dek.b64   > sobre.b64
 *   kms-aws.mjs unwrap  < sobre.b64 > dek.b64
 *
 * Por qué esto y no el CLI de AWS: el CLI pesa ~100 MB y traería Python a una imagen que
 * hoy son 40. Aquí solo hacen falta dos llamadas HTTPS firmadas con SigV4, y eso son
 * cien líneas con lo que ya trae Node. **Cero dependencias** — la misma razón por la que
 * `kek.js` habla con un programa de fuera en vez de enlazar un SDK.
 *
 * Configuración (variables de entorno):
 *   · `DOTRINO_KMS_KEY_ID`  (obligatoria)  id, ARN o `alias/loquesea`
 *   · `AWS_REGION`          (obligatoria)
 *   · credenciales, por orden: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
 *     (+`AWS_SESSION_TOKEN`), o el ROL de la instancia por IMDSv2 — que es lo que se usa
 *     en EC2 y lo que hay que preferir: sin secretos en el disco ni en el `docker run`.
 *
 * Permisos que hay que darle al rol, y ninguno más: `kms:Encrypt` y `kms:Decrypt` sobre
 * esa llave. No hace falta crear llaves, ni listarlas, ni borrarlas.
 *
 * Lo que esto NO cambia, y conviene tenerlo claro: la llave vive en AWS, así que **AWS
 * puede impedir que tu bóveda arranque** (cuenta suspendida, caída de región, un fallo de
 * facturación). Se gana que una copia del disco no sirva de nada; se paga con una
 * dependencia. Para no depender de nadie, el mismo contrato vale con OpenBao en tu propia
 * máquina — ver `docs/llaves-de-hardware.md`.
 */
import crypto from 'node:crypto'
import https from 'node:https'

const MODO = process.argv[2]
const REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION
const KEY_ID = process.env.DOTRINO_KMS_KEY_ID

const muere = (m) => { process.stderr.write('kms-aws: ' + m + '\n'); process.exit(2) }
if (MODO !== 'wrap' && MODO !== 'unwrap') muere('uso: kms-aws.mjs wrap|unwrap')
if (!REGION) muere('falta AWS_REGION')
if (!KEY_ID) muere('falta DOTRINO_KMS_KEY_ID (id, ARN o alias/… de la llave)')

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex')
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s).digest()

/** Petición HTTPS con cuerpo, devolviendo el JSON. */
function pedir (opts, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let d = ''
      res.on('data', (c) => { d += c })
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(d || '{}')) } catch (e) { reject(new Error('respuesta ilegible: ' + e.message)) }
        } else {
          // El cuerpo de un error de KMS dice EXACTAMENTE qué falta (permiso, llave,
          // credencial caducada). Se pasa tal cual: es lo único que ayuda a arreglarlo.
          reject(new Error(`HTTP ${res.statusCode}: ${d.slice(0, 400)}`))
        }
      })
    })
    req.on('error', reject)
    req.setTimeout(10000, () => req.destroy(new Error('se agotó el tiempo hablando con KMS')))
    if (body) req.write(body)
    req.end()
  })
}

/**
 * Credenciales: primero el entorno, y si no, el ROL de la instancia por IMDSv2.
 * IMDSv2 exige pedir un token antes — la v1 está desaconsejada y muchas cuentas ya la
 * tienen apagada, así que no se intenta siquiera.
 */
async function credenciales () {
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: process.env.AWS_SESSION_TOKEN || null
    }
  }
  const http = await import('node:http')
  const meta = (path, headers = {}, method = 'GET') => new Promise((resolve, reject) => {
    const r = http.request({ host: '169.254.169.254', path, method, headers, timeout: 2000 }, (res) => {
      let d = ''
      res.on('data', (c) => { d += c })
      res.on('end', () => (res.statusCode === 200 ? resolve(d) : reject(new Error('IMDS ' + res.statusCode))))
    })
    r.on('error', reject)
    r.on('timeout', () => r.destroy(new Error('IMDS no contesta')))
    r.end()
  })
  const token = await meta('/latest/api/token', { 'x-aws-ec2-metadata-token-ttl-seconds': '60' }, 'PUT')
  const h = { 'x-aws-ec2-metadata-token': token }
  const rol = (await meta('/latest/meta-data/iam/security-credentials/', h)).trim().split('\n')[0]
  const c = JSON.parse(await meta('/latest/meta-data/iam/security-credentials/' + rol, h))
  return { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.Token }
}

/** SigV4 sobre la API JSON de KMS. Es mecánico; el orden y las minúsculas importan. */
async function kms (accion, payload) {
  const cred = await credenciales()
  const host = `kms.${REGION}.amazonaws.com`
  const cuerpo = JSON.stringify(payload)
  const ahora = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dia = ahora.slice(0, 8)

  const cabeceras = {
    'content-type': 'application/x-amz-json-1.1',
    host,
    'x-amz-date': ahora,
    'x-amz-target': 'TrentService.' + accion,
    ...(cred.sessionToken ? { 'x-amz-security-token': cred.sessionToken } : {})
  }
  const firmadas = Object.keys(cabeceras).sort()
  const canonicas = firmadas.map((k) => `${k}:${cabeceras[k]}\n`).join('')
  const lista = firmadas.join(';')
  const canonica = ['POST', '/', '', canonicas, lista, sha256(cuerpo)].join('\n')

  const alcance = `${dia}/${REGION}/kms/aws4_request`
  const porFirmar = ['AWS4-HMAC-SHA256', ahora, alcance, sha256(canonica)].join('\n')
  const kFirma = hmac(hmac(hmac(hmac('AWS4' + cred.secretAccessKey, dia), REGION), 'kms'), 'aws4_request')
  const firma = crypto.createHmac('sha256', kFirma).update(porFirmar).digest('hex')

  return pedir({
    host,
    method: 'POST',
    path: '/',
    headers: {
      ...cabeceras,
      authorization: `AWS4-HMAC-SHA256 Credential=${cred.accessKeyId}/${alcance}, SignedHeaders=${lista}, Signature=${firma}`,
      'content-length': Buffer.byteLength(cuerpo)
    }
  }, cuerpo)
}

const leerEntrada = () => new Promise((resolve) => {
  let d = ''
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (c) => { d += c })
  process.stdin.on('end', () => resolve(d.trim()))
})

try {
  const entrada = await leerEntrada()
  if (!entrada) muere('no llegó nada por la entrada estándar')
  if (MODO === 'wrap') {
    // `EncryptionContext` ata el sobre a este uso: un sobre de la bóveda no se puede
    // abrir pidiéndoselo a KMS con otro propósito, aunque se tenga permiso sobre la llave.
    const r = await kms('Encrypt', {
      KeyId: KEY_ID,
      Plaintext: entrada,
      EncryptionContext: { app: 'dotrino-vault', use: 'atrest' }
    })
    process.stdout.write(r.CiphertextBlob)
  } else {
    const r = await kms('Decrypt', {
      CiphertextBlob: entrada,
      EncryptionContext: { app: 'dotrino-vault', use: 'atrest' }
    })
    process.stdout.write(r.Plaintext)
  }
} catch (e) {
  muere(e.message)
}
