/**
 * kek.js — DE DÓNDE SALE la clave que cifra el disco.
 *
 * Antes había UNA forma cableada dentro de `atrest.js`: derivarla del material de la
 * máquina (`/etc/machine-id` + salt). Eso sigue siendo el proveedor por defecto y no
 * cambia nada — pero ahora es *un* proveedor, no *el* proveedor.
 *
 * Por qué importa: el hueco grande frente a un KMS es que no hay raíz de confianza en
 * hardware, y `machine-id` y el salt viven **en el mismo disco que los datos**, así que
 * una instantánea del disco se lo lleva todo. Cerrarlo pide que la clave salga de otro
 * sitio — una llave FIDO2, el TPM, un KMS — y cada uno de esos es un módulo pequeño
 * SIEMPRE QUE exista esta costura. Sin ella, cada opción es una cirugía.
 * Plan completo: `docs/llaves-de-hardware.md`.
 *
 * El contrato es deliberadamente mínimo: un proveedor devuelve 32 bytes para este
 * directorio. Nada más. Quien los guarda, los envuelve o los pide por red es asunto suyo.
 *
 * Proveedores:
 *   - `machine`  (por defecto)  lo de siempre: scrypt(material de la máquina + salt).
 *   - `command`                 envuelve una DEK aleatoria llamando a un programa de
 *                               fuera. Con eso vale CUALQUIER KMS (AWS, OpenBao, gcloud,
 *                               un script propio) sin meter un SDK aquí dentro.
 *
 * Por qué `command` y no un cliente de KMS de verdad, que es la pregunta obvia:
 *   1. **Todo esto es síncrono.** `atRestFor()` devuelve `{ encrypt, decrypt }` que usan
 *      cinco módulos sin `await`. Un SDK sería asíncrono y habría que tocarlos todos;
 *      `execFileSync` entra sin mover una línea de los llamantes.
 *   2. **Cero dependencias nuevas** y ningún módulo nativo: el binario único sigue siendo
 *      único.
 *   3. Sirve para el KMS que ya tenga el cliente, que es justo lo que pide una empresa.
 *
 * REGLA QUE NO SE TOCA: si el proveedor configurado falla, esto **revienta**. No se cae
 * al `machine` de reserva. Un repliegue silencioso convertiría «tumbo la red del vault»
 * en «el vault se cifra con la clave débil», que es un agujero, no una comodidad.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'

/** Config del proveedor. EN CLARO a propósito: hay que leerla para poder descifrar. */
export const CONFIG_FILE = 'atrest.json'
/** La DEK envuelta por el proveedor externo. Sin él, estos bytes no valen nada. */
export const WRAPPED_FILE = 'atrest.kek'
/** Huella de la máquina que escribió estos datos. Ver `assertSameMachine`. */
export const MACHINE_FILE = 'atrest.machine'

/**
 * Los errores cruzan procesos (el daemon los enseña, la CLI los distingue), así que
 * llevan `code` y se comprueban por ahí. Traducir la frase no debe romper a nadie.
 */
export class KekError extends Error {
  constructor (code, message) { super(message); this.name = 'KekError'; this.code = code }
}

/** Caché por proceso: sin ella, cinco `atRestFor()` = cinco viajes al KMS en cada arranque. */
const cache = new Map()
export const clearCache = () => cache.clear()

/**
 * Config efectiva del directorio. Sin archivo, `machine` — que es lo que hacía siempre,
 * así que una instalación existente no nota nada.
 */
export function readConfig (dir) {
  let raw
  try { raw = fs.readFileSync(path.join(dir, CONFIG_FILE), 'utf8') } catch (_) { return { provider: 'machine' } }
  let cfg
  try { cfg = JSON.parse(raw) } catch (e) {
    throw new KekError('kek-config', `${CONFIG_FILE} is not valid JSON: ${e.message}`)
  }
  const provider = cfg?.provider || 'machine'
  if (provider !== 'machine' && provider !== 'command') {
    throw new KekError('kek-config', `unknown kek provider: ${provider}`)
  }
  return { ...cfg, provider }
}

export function writeConfig (dir, cfg) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.writeFileSync(path.join(dir, CONFIG_FILE), JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 })
}

/**
 * Llama al programa de fuera: base64 por la entrada, base64 por la salida. Ese contrato
 * es a propósito el más tonto posible — cada CLI de KMS tiene sus manías con los binarios
 * y sus flags, y se resuelven en un envoltorio de tres líneas en vez de aquí dentro.
 */
function runStep (step, input, what) {
  if (!step || typeof step.cmd !== 'string' || !step.cmd) {
    throw new KekError('kek-config', `kek provider "command": missing ${what}.cmd`)
  }
  let out
  try {
    out = execFileSync(step.cmd, Array.isArray(step.args) ? step.args : [], {
      input: input.toString('base64'),
      encoding: 'utf8',
      timeout: Number(step.timeoutMs) || 15000,
      maxBuffer: 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe']
    })
  } catch (e) {
    // `stderr` es lo único que dice POR QUÉ (credenciales caducadas, sin permiso, sin red).
    const detail = (e.stderr ? String(e.stderr).trim().split('\n').slice(-3).join(' / ') : '') || e.message
    throw new KekError('kek-unavailable', `kek ${what} failed (${step.cmd}): ${detail}`)
  }
  const buf = Buffer.from(String(out).trim(), 'base64')
  if (!buf.length) throw new KekError('kek-unavailable', `kek ${what} returned nothing (${step.cmd})`)
  return buf
}

/** ¿Hay ya datos cifrados aquí? Si los hay, estrenar una DEK nueva los dejaría ilegibles. */
function hasEncryptedData (dir, magic) {
  let names = []
  try { names = fs.readdirSync(dir) } catch (_) { return false }
  for (const n of names) {
    if (n === CONFIG_FILE || n === WRAPPED_FILE) continue
    try {
      const fd = fs.openSync(path.join(dir, n), 'r')
      const head = Buffer.alloc(magic.length + 1)
      const read = fs.readSync(fd, head, 0, head.length, 0)
      fs.closeSync(fd)
      if (read === head.length && head.toString('utf8') === magic + '.') return true
    } catch (_) { /* directorios y archivos ilegibles: no cuentan */ }
  }
  return false
}

/**
 * La DEK del proveedor `command`. Si ya está envuelta en el disco, se desenvuelve; si no,
 * se estrena una — **pero solo si no hay nada cifrado todavía**.
 *
 * Ese portazo es el que evita el desastre silencioso: cambiar `atrest.json` a mano en un
 * perfil que ya tiene datos generaría una DEK nueva y **dejaría todo lo anterior
 * ilegible**, sin un solo aviso. Cambiar de proveedor es `atrest rekey`, no editar un JSON.
 */
function commandKey (dir, cfg, magic) {
  const wrappedPath = path.join(dir, WRAPPED_FILE)
  let wrapped = null
  try { wrapped = Buffer.from(fs.readFileSync(wrappedPath, 'utf8').trim(), 'base64') } catch (_) {}

  if (wrapped && wrapped.length) {
    const dek = runStep(cfg.unwrap, wrapped, 'unwrap')
    if (dek.length !== 32) throw new KekError('kek-unavailable', `kek unwrap returned ${dek.length} bytes, expected 32`)
    return dek
  }

  if (hasEncryptedData(dir, magic)) {
    throw new KekError('kek-needs-rekey',
      `${CONFIG_FILE} says provider "command" but ${WRAPPED_FILE} is missing and this profile already holds encrypted data. ` +
      'Switching providers requires re-encrypting: run `dotrino-vault atrest rekey`.')
  }

  // Estreno: envolver, COMPROBAR que se vuelve a abrir, y solo entonces escribir.
  const dek = crypto.randomBytes(32)
  const blob = runStep(cfg.wrap, dek, 'wrap')
  const back = runStep(cfg.unwrap, blob, 'unwrap')
  if (back.length !== dek.length || !crypto.timingSafeEqual(dek, back)) {
    throw new KekError('kek-verify', 'kek wrap/unwrap round-trip mismatch: refusing to write a key that will not open')
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = wrappedPath + '.tmp'
  fs.writeFileSync(tmp, blob.toString('base64') + '\n', { mode: 0o600 })
  fs.renameSync(tmp, wrappedPath)
  return dek
}

/**
 * ¿LOS ESCRIBIÓ ESTA MÁQUINA? Con el proveedor `machine` la clave sale del material de la
 * máquina, así que en otra los datos no abren. Eso es lo que se quiere — copiar el archivo
 * no basta— pero **cuando pasa por accidente, hay que decirlo**.
 *
 * El caso que lo hizo urgente: **un contenedor**. En una imagen Alpine no hay
 * `/etc/machine-id`, así que el material se cae al `hostname`, que en Docker es el ID DEL
 * CONTENEDOR y cambia en cada `docker run`. Con los datos en un volumen —o en un EBS— el
 * ciclo normal (`docker rm` y volver a levantar, actualizar la imagen, mover el disco a
 * otra instancia) dejaba la cuenta **ilegible para siempre**, y el único síntoma era un
 * «unable to authenticate data» de la librería de cripto. Comprobado, no supuesto.
 *
 * Se guarda una HUELLA (no el material) de quién escribió aquí. Si no coincide y ya hay
 * datos cifrados, se para y se explica, en vez de dejar al usuario delante de un error de
 * AES preguntándose qué hizo mal.
 */
export function assertSameMachine (dir, material, hasData) {
  const f = path.join(dir, MACHINE_FILE)
  const huella = crypto.createHash('sha256').update('dotrino-atrest-machine\u0000' + material).digest('hex').slice(0, 32)
  let previa = null
  try { previa = fs.readFileSync(f, 'utf8').trim() } catch (_) {}

  if (previa && previa !== huella && hasData) {
    throw new KekError('kek-machine-changed',
      'this data was written by a DIFFERENT machine and the key is derived from the machine itself, so it cannot be opened here. ' +
      'In a container this is usually the container id changing on every run: the fix is to stop deriving the key from the machine — ' +
      'give the profile a KMS provider (see docs/llaves-de-hardware.md) and re-create it, or restore this volume on the original host. ' +
      'Nothing was modified.')
  }
  if (!previa) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
      fs.writeFileSync(f, huella + '\n', { mode: 0o600 })
    } catch (_) { /* si no se puede escribir la huella, no se bloquea el arranque */ }
  }
}

/**
 * Los 32 bytes de este directorio, por el proveedor que diga su config.
 * `machineKeyFn` la inyecta `atrest.js` para no importarnos en círculo.
 */
export function resolveKey (dir, { password = '', machineKeyFn, materialFn = null, magic, config = null } = {}) {
  const cfg = config || readConfig(dir)
  if (cfg.provider === 'machine') {
    // La comprobación va ANTES de derivar: si la máquina cambió, el error tiene que
    // explicar por qué, no salir de las tripas de AES tres llamadas más abajo.
    if (typeof materialFn === 'function') {
      try { assertSameMachine(dir, materialFn(), hasEncryptedData(dir, magic)) } catch (e) {
        if (e instanceof KekError) throw e
      }
    }
    return machineKeyFn(dir, password)
  }

  const ck = 'command ' + path.resolve(dir)
  const hit = cache.get(ck)
  if (hit) return hit
  const dek = commandKey(dir, cfg, magic)
  cache.set(ck, dek)
  return dek
}

/**
 * Estrena una DEK y la envuelve, SIN escribir nada. La usa `rekey`, que necesita la
 * clave nueva en la mano mientras todavía está descifrando con la vieja — y que no puede
 * permitirse pisar el `atrest.kek` de la vieja hasta el final.
 */
export function mintKey (cfg) {
  if (cfg.provider !== 'command') throw new KekError('kek-config', 'mintKey only applies to the "command" provider')
  const dek = crypto.randomBytes(32)
  const blob = runStep(cfg.wrap, dek, 'wrap')
  const back = runStep(cfg.unwrap, blob, 'unwrap')
  if (back.length !== dek.length || !crypto.timingSafeEqual(dek, back)) {
    throw new KekError('kek-verify', 'kek wrap/unwrap round-trip mismatch: refusing to use a key that will not open')
  }
  return { dek, blob }
}

/**
 * EL PROVEEDOR QUE PIDE EL ENTORNO. Es lo que hace que un contenedor se pueda levantar con
 * KMS sin entrar a escribir un JSON dentro: se pasan variables y ya.
 *
 *   · `DOTRINO_KEK_CMD`        un programa cualquiera que cumpla el contrato (base64 ⇄ base64)
 *   · `DOTRINO_KMS_KEY_ID`     atajo para AWS: usa el `kms-aws.mjs` que viaja en la imagen
 *
 * Devuelve `null` si no hay nada configurado, que es el caso normal de un PC: ahí el
 * proveedor sigue siendo `machine` y nada cambia.
 *
 * Solo se consulta al CREAR un perfil. Un perfil que ya existe manda con su `atrest.json`,
 * porque cambiarle el proveedor por una variable de entorno lo dejaría ilegible — y eso se
 * hace con `atrest rekey`, mirando, no con un `docker run` distinto por accidente.
 */
export function configFromEnv (env = process.env) {
  if (env.DOTRINO_KEK_CMD) {
    return {
      provider: 'command',
      label: env.DOTRINO_KEK_LABEL || env.DOTRINO_KEK_CMD,
      wrap: { cmd: env.DOTRINO_KEK_CMD, args: ['wrap'] },
      unwrap: { cmd: env.DOTRINO_KEK_CMD, args: ['unwrap'] }
    }
  }
  if (env.DOTRINO_KMS_KEY_ID) {
    const script = env.DOTRINO_KMS_SCRIPT || '/app/packaging/kms-aws.mjs'
    return {
      provider: 'command',
      label: 'AWS KMS ' + env.DOTRINO_KMS_KEY_ID,
      wrap: { cmd: process.execPath, args: [script, 'wrap'] },
      unwrap: { cmd: process.execPath, args: [script, 'unwrap'] }
    }
  }
  return null
}

/** Prueba el ida y vuelta del proveedor SIN tocar los datos. Para `atrest test`. */
export function probe (dir, cfg = null) {
  const c = cfg || readConfig(dir)
  if (c.provider === 'machine') return { provider: 'machine', ok: true }
  const sample = crypto.randomBytes(32)
  const blob = runStep(c.wrap, sample, 'wrap')
  const back = runStep(c.unwrap, blob, 'unwrap')
  if (back.length !== sample.length || !crypto.timingSafeEqual(sample, back)) {
    throw new KekError('kek-verify', 'kek wrap/unwrap round-trip mismatch')
  }
  return { provider: 'command', ok: true, label: c.label || c.wrap?.cmd || null, wrappedBytes: blob.length }
}

export default { readConfig, writeConfig, resolveKey, mintKey, probe, clearCache, assertSameMachine, configFromEnv, KekError, CONFIG_FILE, WRAPPED_FILE, MACHINE_FILE }
