/**
 * EL CÓDIGO FRESCO: la función corre la versión que dice su bucket, no la que trae la pila.
 *
 * Pedido por el dueño el 2026-10-25: cada Lambda es una bóveda aparte, y actualizar todas
 * pila por pila no escala. Así que la función que despliega la pila es solo el PUNTO DE
 * PARTIDA, y en cada arranque mira `code/current.json` de su propio bucket:
 *
 *   { v: 1, version, sha256, key, from, at, announced }
 *
 * Si ahí hay una versión MÁS NUEVA que la suya, baja `key`, comprueba que su sha256 es el
 * apuntado, lo deja desempaquetado en `/tmp` y le pasa la invocación. Si no, se corre ella.
 *
 * Quien escribe `current.json` es la bóveda en marcha (`update.mjs`), y solo después de
 * verificar el zip contra la atestación de la release: aquí ya no se decide nada, solo se
 * comprueba que lo que se va a ejecutar es lo que se apuntó. Si no cuadra, SE PARA: correr
 * la versión vieja en silencio dejaría una bóveda atrás sin que nadie lo viera.
 *
 * Solo hacia delante: una pila actualizada a mano a algo más nuevo que lo apuntado corre lo
 * suyo, y la siguiente actualización vuelve a escribir el marcador.
 */
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

export const CODE_PREFIX = 'code/'
export const CURRENT = 'current.json'
const ROOT = '/tmp/dotrino-vault/code'

const fail = (code, message) => Object.assign(new Error(message), { code })
const missing = (e) => e.code === 'ENOENT' || e.name === 'NoSuchKey'

/** El marcador, o `null` si todavía no hay (la función corre lo que trajo la pila). */
export async function readCurrent (store) {
  let body
  try { body = (await store.get(CURRENT)).body } catch (e) { if (missing(e)) return null; throw e }
  let cur
  try { cur = JSON.parse(body.toString('utf8')) } catch (_) { throw fail('code-marker-unreadable', `${CODE_PREFIX}${CURRENT} is not JSON`) }
  if (cur?.v !== 1 || typeof cur.version !== 'string' || !/^[0-9a-f]{64}$/.test(cur.sha256 || '') || typeof cur.key !== 'string') {
    throw fail('code-marker-unreadable', `${CODE_PREFIX}${CURRENT} does not say which code to run`)
  }
  return cur
}

export async function writeCurrent (store, cur) {
  await store.put(CURRENT, Buffer.from(JSON.stringify({ v: 1, ...cur })))
}

/**
 * Desempaqueta un zip (el de `build.sh`: sin zip64, guardado o deflate). Solo lo que hace
 * falta para el nuestro; cualquier otra cosa se rechaza en vez de adivinarla.
 */
export function unzip (buf, dest) {
  let eocd = -1
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break }
  }
  if (eocd < 0) throw fail('code-bad-zip', 'not a zip: no end of central directory')
  const count = buf.readUInt16LE(eocd + 10)
  let p = buf.readUInt32LE(eocd + 16)
  const root = path.resolve(dest)
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw fail('code-bad-zip', 'broken central directory')
    const method = buf.readUInt16LE(p + 10)
    const csize = buf.readUInt32LE(p + 20)
    const size = buf.readUInt32LE(p + 24)
    const nlen = buf.readUInt16LE(p + 28)
    const xlen = buf.readUInt16LE(p + 30)
    const clen = buf.readUInt16LE(p + 32)
    const mode = buf.readUInt32LE(p + 38) >>> 16
    const local = buf.readUInt32LE(p + 42)
    const name = buf.toString('utf8', p + 46, p + 46 + nlen)
    p += 46 + nlen + xlen + clen
    const out = path.resolve(root, name)
    if (out !== root && !out.startsWith(root + path.sep)) throw fail('code-bad-zip', `entry outside the folder: ${name}`)
    if (name.endsWith('/')) { fs.mkdirSync(out, { recursive: true }); continue }
    if (buf.readUInt32LE(local) !== 0x04034b50) throw fail('code-bad-zip', `broken entry: ${name}`)
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28)
    const raw = buf.subarray(start, start + csize)
    const data = method === 0 ? raw : method === 8 ? zlib.inflateRawSync(raw) : null
    if (!data) throw fail('code-bad-zip', `unsupported compression ${method}: ${name}`)
    if (data.length !== size) throw fail('code-bad-zip', `wrong size: ${name}`)
    fs.mkdirSync(path.dirname(out), { recursive: true })
    fs.writeFileSync(out, data, { mode: (mode & 0o777) || 0o644 })
  }
}

/**
 * El handler de la versión apuntada, o `null` si toca correr la propia.
 * @param {{ store, myVersion: string, isNewer: (a: string, b: string) => boolean, root?: string, log?: Function }} opts
 */
export async function freshHandler ({ store, myVersion, isNewer, root = ROOT, log = () => {} }) {
  const cur = await readCurrent(store)
  if (!cur || !isNewer(cur.version, myVersion)) return null
  const dir = path.join(root, cur.sha256)
  if (!fs.existsSync(path.join(dir, '.ok'))) {
    let body
    try { body = (await store.get(cur.key)).body } catch (e) {
      if (missing(e)) throw fail('code-missing', `${CODE_PREFIX}${CURRENT} points at ${cur.key}, which is not there`)
      throw e
    }
    const sha = createHash('sha256').update(body).digest('hex')
    if (sha !== cur.sha256) throw fail('code-mismatch', `${cur.key} is ${sha}, not the ${cur.sha256} that ${CURRENT} says`)
    const tmp = `${dir}.tmp`
    fs.rmSync(tmp, { recursive: true, force: true })
    unzip(body, tmp)
    fs.writeFileSync(path.join(tmp, '.ok'), cur.version)
    fs.rmSync(dir, { recursive: true, force: true })
    fs.renameSync(tmp, dir)
    log(`[vault-lambda] running ${cur.version} from ${cur.key} (the stack brought ${myVersion})`)
  }
  const mod = await import(pathToFileURL(path.join(dir, 'lambda', 'handler.mjs')).href)
  if (typeof mod.handler !== 'function') throw fail('code-no-handler', `${cur.key} has no lambda/handler.mjs`)
  return mod.handler
}

export default { freshHandler, readCurrent, writeCurrent, unzip, CODE_PREFIX, CURRENT }
