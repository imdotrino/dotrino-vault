/**
 * EL DIRECTORIO DEL PERFIL, REFLEJADO EN UN ALMACÉN DE OBJETOS (S3).
 *
 * Una Lambda no tiene disco que dure: `/tmp` se va con el contenedor. Así que el perfil
 * vive en S3 y se baja a `/tmp` al arrancar en frío; después de cada petición se sube lo
 * que cambió. La bóveda corre sobre archivos de verdad, con la misma plataforma que el
 * binario (`src/platform.js`), y no se entera de nada de esto.
 *
 * Lo que llega a S3 ya va CIFRADO: la bóveda cifra en reposo cada archivo con la llave del
 * proveedor `command` (KMS, `packaging/kms-aws.mjs`). Los dos archivos que van en claro
 * (`atrest.json`, la config; `atrest.kek`, la DEK envuelta por KMS) no abren nada sin KMS.
 *
 * DOS ESCRITORES NO SE PISAN. Cada objeto se sube con la `ETag` que se le vio: si otro
 * contenedor lo cambió entretanto, S3 rechaza la escritura y esto LANZA `store-conflict`.
 * Quien llama tira el estado en memoria y vuelve a empezar desde S3; seguir escribiendo
 * encima perdería lo del otro sin que nadie lo viera.
 *
 * El almacén es una interfaz pequeña, para que las pruebas usen uno en memoria:
 *
 *   list()                           → [{ name, etag }]
 *   get(name)                        → { body: Buffer, etag }
 *   put(name, body, { ifMatch, ifNoneMatch }) → etag nueva; un choque LANZA con code 'store-conflict'
 *   remove(name, { ifMatch })
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

const hash = (buf) => crypto.createHash('sha256').update(buf).digest('hex')

/** Todos los archivos bajo `dir`, con nombre relativo y separador `/`. */
function walk (dir, base = dir, out = []) {
  let entries = []
  try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch (e) {
    if (e.code === 'ENOENT') return out
    throw e
  }
  for (const e of entries) {
    const full = path.join(dir, e.name)
    if (e.isDirectory()) walk(full, base, out)
    else if (e.isFile()) out.push(path.relative(base, full).split(path.sep).join('/'))
  }
  return out
}

/**
 * @param {object} store  el almacén (ver arriba)
 * @param {string} dir    el directorio local del perfil
 */
export function createMirror ({ store, dir }) {
  // Lo último que se sabe de cada objeto: su ETag en el almacén y el hash de lo que hay en
  // disco. Lo que no cambió de hash no se sube.
  const known = new Map()   // name → { etag, hash }

  return {
    /** Baja el perfil entero. Se llama UNA vez, al arrancar en frío y con `dir` vacío. */
    async pull () {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
      known.clear()
      for (const { name } of await store.list()) {
        const { body, etag } = await store.get(name)
        const file = path.join(dir, ...name.split('/'))
        fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
        fs.writeFileSync(file, body, { mode: 0o600 })
        known.set(name, { etag, hash: hash(body) })
      }
      return known.size
    },

    /** Sube lo que cambió y borra lo que ya no está. Devuelve cuántos objetos tocó. */
    async push () {
      let touched = 0
      const present = new Set(walk(dir))
      for (const name of present) {
        const body = fs.readFileSync(path.join(dir, ...name.split('/')))
        const h = hash(body)
        const prev = known.get(name)
        if (prev?.hash === h) continue
        const etag = await store.put(name, body, prev ? { ifMatch: prev.etag } : { ifNoneMatch: '*' })
        known.set(name, { etag, hash: h })
        touched++
      }
      for (const [name, prev] of known) {
        if (present.has(name)) continue
        await store.remove(name, { ifMatch: prev.etag })
        known.delete(name)
        touched++
      }
      return touched
    }
  }
}

/** Un almacén en memoria, con las mismas reglas de ETag que S3. Para las pruebas. */
export function memoryStore () {
  const objects = new Map()   // name → { body, etag }
  let n = 0
  const conflict = (name) => Object.assign(new Error(`store: ${name} changed underneath`), { code: 'store-conflict' })
  return {
    objects,
    async list () { return [...objects].map(([name, o]) => ({ name, etag: o.etag })) },
    async get (name) {
      const o = objects.get(name)
      if (!o) throw Object.assign(new Error(`store: ${name} does not exist`), { code: 'ENOENT' })
      return { body: Buffer.from(o.body), etag: o.etag }
    },
    async put (name, body, { ifMatch = null, ifNoneMatch = null } = {}) {
      const cur = objects.get(name)
      if (ifNoneMatch === '*' && cur) throw conflict(name)
      if (ifMatch && cur?.etag !== ifMatch) throw conflict(name)
      const etag = `"m${++n}"`
      objects.set(name, { body: Buffer.from(body), etag })
      return etag
    },
    async remove (name, { ifMatch = null } = {}) {
      const cur = objects.get(name)
      if (ifMatch && cur && cur.etag !== ifMatch) throw conflict(name)
      objects.delete(name)
    }
  }
}

/**
 * El almacén de verdad: un prefijo de un bucket de S3. Usa el SDK que ya trae el runtime de
 * Node de Lambda (`@aws-sdk/client-s3`), así que no entra como dependencia del paquete.
 *
 * Las escrituras condicionales (`If-Match` / `If-None-Match`) son las de S3: un 412 es un
 * choque con otro escritor.
 */
export async function s3Store ({ bucket, prefix = '', region = process.env.AWS_REGION } = {}) {
  if (!bucket) throw Object.assign(new Error('s3Store: bucket is required'), { code: 'no-bucket' })
  const { S3Client, ListObjectsV2Command, GetObjectCommand, PutObjectCommand, DeleteObjectCommand } = await import('@aws-sdk/client-s3')
  const s3 = new S3Client({ region })
  const key = (name) => prefix + name
  const isConflict = (e) => e?.$metadata?.httpStatusCode === 412 || e?.name === 'PreconditionFailed'
  const conflict = (name, e) => Object.assign(new Error(`store: ${name} changed underneath (${e.name})`), { code: 'store-conflict' })
  return {
    async list () {
      const out = []
      let token
      do {
        const r = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, ContinuationToken: token }))
        for (const o of r.Contents || []) out.push({ name: o.Key.slice(prefix.length), etag: o.ETag })
        token = r.IsTruncated ? r.NextContinuationToken : undefined
      } while (token)
      return out
    },
    async get (name) {
      const r = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key(name) }))
      return { body: Buffer.from(await r.Body.transformToByteArray()), etag: r.ETag }
    },
    async put (name, body, { ifMatch = null, ifNoneMatch = null } = {}) {
      try {
        const r = await s3.send(new PutObjectCommand({
          Bucket: bucket, Key: key(name), Body: body,
          ...(ifMatch ? { IfMatch: ifMatch } : {}),
          ...(ifNoneMatch ? { IfNoneMatch: ifNoneMatch } : {})
        }))
        return r.ETag
      } catch (e) {
        if (isConflict(e)) throw conflict(name, e)
        throw e
      }
    },
    async remove (name, { ifMatch = null } = {}) {
      try {
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key(name), ...(ifMatch ? { IfMatch: ifMatch } : {}) }))
      } catch (e) {
        if (isConflict(e)) throw conflict(name, e)
        throw e
      }
    }
  }
}

export default { createMirror, memoryStore, s3Store }
