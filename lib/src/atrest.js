/**
 * atrest.js — cifrado EN REPOSO de los datos del vault, ligado a ESTA máquina.
 *
 * Qué resuelve: los archivos vivían en claro en el disco (0600). Copiar uno a un pendrive
 * y llevárselo a otra máquina bastaba para llevarse lo que hubiera dentro. Ahora van
 * cifrados con una clave derivada de material de la propia máquina, así que **el archivo
 * copiado a otro equipo no sirve**.
 *
 * Cubre TODO lo que se guarda, no solo la maestra — el contenido del usuario no es menos
 * sensible que la llave que lo firma:
 *   · `identity.json`  maestra, contactos, delegaciones
 *   · `vault.json`     árbol de contenido
 *   · `threads.json`   hilos, aperturas y el perfil del usuario
 *   · `secrets.json`   secretos de servicios (tokens y llaves de producción)
 *   · `service-identity.json` en la máquina del SERVICIO (`@dotrino/vault/env`):
 *     lleva la llave privada de su dispositivo, así que va igual de cifrado.
 *   · `activity.log`   la bitácora de auditoría, cifrada LÍNEA A LÍNEA (ver `LINE_FILES`)
 *   · `state.json`, `acta.json`, `secret-request.json`… el canal local con la CLI
 *     (`src/ipc.js`), por donde pasan la contraseña del perfil y los valores
 *   · `transport.json` el par de transporte de `@dotrino/proxy-client`, con su privada
 *
 * La bitácora estuvo fuera hasta 0.89, con el argumento de que «no guarda payloads». No
 * guarda valores, pero sí el mapa de la cuenta —qué aparatos, con qué permisos, contra
 * qué cajones y a qué hora—, que es lo que mira quien elige por dónde entrar.
 *
 * Qué NO resuelve, dicho sin adornos: **no protege contra alguien con acceso a esta misma
 * máquina como tu usuario o como root** — puede leer el mismo material que leemos nosotros.
 * Es subir el listón (de «copiar un archivo» a «tener tu máquina»), no una imposibilidad
 * criptográfica. Para eso hace falta un TPM o un enclave, que es otra pelea.
 *
 * Y en particular **no protege contra una copia del DISCO ENTERO**, que es el caso de un
 * vault en un VPS alquilado: el material de abajo vive en ese mismo disco, así que quien se
 * lleva el disco se lleva también con qué descifrarlo. Cerrar eso pide que la llave no esté
 * en la máquina — ver `docs/secretos-sellados.md`, diseñado y NO implementado porque hoy no
 * se paga (lo único que hay en ese VPS es una credencial rotable).
 *
 * Material que se mezcla:
 *   · `/etc/machine-id` — identifica la instalación del sistema
 *   · un SALT aleatorio local (`atrest.salt`, 0600) — se genera la primera vez
 *
 * **Y desde 0.55: de dónde sale la clave es CONFIGURABLE** (`kek.js`). Todo lo anterior
 * describe el proveedor `machine`, que sigue siendo el de por defecto y el que se usa si
 * no hay `atrest.json`. Con `provider: "command"` la clave la envuelve un KMS —el que
 * sea, incluido el del cliente— y entonces **sí** deja de estar en este disco, que es la
 * única forma de cerrar el párrafo de arriba. Cambiar de proveedor es `atrest rekey`;
 * editar el JSON a mano está expresamente bloqueado porque dejaría los datos ilegibles.
 *
 * `machineKey` **acepta** además una contraseña, pero **ningún llamante se la pasa** y no es
 * un descuido: los cinco (`src/store.js`, `src/secretsStore.js`, `src/vault.js`,
 * `src/threadStore.js`, `lib/src/service.js`) usan `atRestFor(dir)` a secas, porque el
 * candado es de la CONSOLA — un perfil bloqueado sigue sirviendo a sus agentes, y no podría
 * si sus datos necesitaran una contraseña que no está puesta. Si algún día se usa, tiene que
 * ser para un cajón aparte que solo haga falta al administrar, no para todo esto.
 *
 * Migración segura: se escribe el cifrado, se comprueba que se puede volver a leer, y solo
 * entonces se reemplaza el original. Si algo falla, el archivo en claro se queda intacto.
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { resolveKey, mintKey, readConfig, writeConfig, probe, clearCache, configFromEnv, KekError, CONFIG_FILE, WRAPPED_FILE, MACHINE_FILE } from './kek.js'

const MAGIC = 'DOTRINO-ATREST-v1'
const SALT_FILE = 'atrest.salt'

/**
 * Material de ESTA máquina, por sistema. Si no se encuentra nada, se cae al hostname
 * (peor —un hostname se adivina y se repite— pero deja el esquema funcionando).
 *
 *   · Linux    `/etc/machine-id` (y el de dbus)
 *   · Windows  `MachineGuid` del registro, que es el equivalente exacto
 *   · macOS    `IOPlatformUUID` del hardware
 */
function machineMaterial () {
  const parts = []
  if (process.platform === 'win32') {
    try {
      const out = execFileSync(
        path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe'),
        ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
        { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'ignore'] }
      )
      const m = /MachineGuid\s+REG_SZ\s+(\S+)/i.exec(out)
      if (m) parts.push(m[1])
    } catch (_) { /* sin registro accesible: cae al hostname */ }
  } else if (process.platform === 'darwin') {
    try {
      const out = execFileSync('/usr/sbin/ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'],
        { encoding: 'utf8', timeout: 4000, stdio: ['ignore', 'pipe', 'ignore'] })
      const m = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(out)
      if (m) parts.push(m[1])
    } catch (_) { /* idem */ }
  } else {
    for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
      try { parts.push(fs.readFileSync(f, 'utf8').trim()) } catch (_) {}
    }
  }
  if (!parts.length) parts.push(os.hostname())
  return parts.join('|')
}

/** Salt local, creado la primera vez y guardado junto a los datos (0600). */
function loadOrCreateSalt (dir) {
  const f = path.join(dir, SALT_FILE)
  try { return fs.readFileSync(f) } catch (_) {}
  const salt = crypto.randomBytes(32)
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.writeFileSync(f, salt, { mode: 0o600 })
  return salt
}

/**
 * Clave AES-256 derivada del material de la máquina + salt. `password` existe en la firma
 * pero **hoy nadie la pasa** (ver la cabecera): no asumas que el candado cifra algo.
 */
export function machineKey (dir, password = '') {
  const salt = loadOrCreateSalt(dir)
  return crypto.scryptSync(machineMaterial() + '\u0000' + String(password || ''), salt, 32, { N: 16384, r: 8, p: 1 })
}

/** ¿El contenido de este archivo está cifrado por nosotros? */
export const isEncrypted = (text) => typeof text === 'string' && text.startsWith(MAGIC + '.')

export function encryptText (plaintext, key) {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()])
  return [MAGIC, iv.toString('base64'), ct.toString('base64'), c.getAuthTag().toString('base64')].join('.')
}

export function decryptText (blob, key) {
  const [magic, iv, ct, tag] = String(blob).split('.')
  if (magic !== MAGIC) throw new Error('at-rest: formato desconocido')
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'))
  d.setAuthTag(Buffer.from(tag, 'base64'))
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8')
}

/**
 * La clave de ESTE directorio, por el proveedor que diga su `atrest.json`.
 *
 * Sin ese archivo el proveedor es `machine` y esto devuelve exactamente lo mismo que
 * `machineKey(dir, password)` — o sea, una instalación existente no nota el cambio.
 * Con `provider: "command"` la clave viene envuelta por un KMS (ver `kek.js`).
 *
 * **Usa esto, no `machineKey`, en cualquier código nuevo.** `machineKey` es ahora la
 * implementación de UN proveedor; llamarla directamente se salta la costura y deja de
 * funcionar en cuanto alguien configure otro.
 */
export function kekFor (dir, { password = '' } = {}) {
  return resolveKey(dir, { password, machineKeyFn: machineKey, materialFn: machineMaterial, magic: MAGIC })
}

/**
 * Adaptador para `@dotrino/identity/node`: cifra/descifra el archivo entero de la identidad.
 * Si el archivo está en claro (instalación anterior), lo lee igual y lo deja cifrado en la
 * primera escritura — sin pedirle nada al usuario.
 */
export function atRestFor (dir, { password = '' } = {}) {
  const key = kekFor(dir, { password })
  return {
    encrypt: (text) => encryptText(text, key),
    decrypt: (text) => (isEncrypted(text) ? decryptText(text, key) : text)
  }
}

/**
 * Cifra AHORA un archivo que esté en claro, verificando antes de reemplazar: se escribe a un
 * temporal, se vuelve a leer y descifrar, se compara, y solo entonces se renombra encima.
 * Devuelve 'ya-cifrado' | 'migrado' | 'sin-archivo'.
 */
export function migrateFile (file, key) {
  let text
  try { text = fs.readFileSync(file, 'utf8') } catch (_) { return 'sin-archivo' }
  if (isEncrypted(text)) return 'ya-cifrado'
  const blob = encryptText(text, key)
  if (decryptText(blob, key) !== text) throw new Error('at-rest: la comprobación falló, no se toca el original')
  const tmp = file + '.atrest.tmp'
  fs.writeFileSync(tmp, blob, { mode: 0o600 })
  fs.renameSync(tmp, file)
  return 'migrado'
}

/** Los archivos de este directorio que están cifrados por nosotros. */
/**
 * Archivos que van cifrados **línea a línea**, no de una pieza.
 *
 * La bitácora se ESCRIBE AÑADIENDO. Cifrarla entera obligaría a reescribir el archivo
 * completo en cada anotación, así que cada entrada se cierra sola. Eso la deja fuera del
 * barrido de abajo (una lectura de todo el archivo no descifra: son muchos textos pegados)
 * y la mete en su propio camino al cambiar de proveedor.
 */
export const LINE_FILES = Object.freeze(['activity.log'])

export function encryptedFilesIn (dir) {
  let names = []
  try { names = fs.readdirSync(dir) } catch (_) { return [] }
  return names.filter((n) => {
    if (n === CONFIG_FILE || n === WRAPPED_FILE || n === SALT_FILE || n === MACHINE_FILE) return false
    if (LINE_FILES.includes(n)) return false
    try { return isEncrypted(fs.readFileSync(path.join(dir, n), 'utf8')) } catch (_) { return false }
  })
}

/** Las bitácoras presentes en `dir`, con sus líneas. `[]` si no hay ninguna. */
export function lineFilesIn (dir) {
  return LINE_FILES.filter((n) => { try { return fs.statSync(path.join(dir, n)).isFile() } catch (_) { return false } })
}

/**
 * CAMBIAR DE PROVEEDOR: descifra todo con la clave vieja y lo vuelve a cifrar con la nueva.
 *
 * Sin esto, cambiar `atrest.json` a mano deja el perfil ilegible — la maestra incluida — y
 * no hay vuelta atrás. Por eso `kek.js` se niega a estrenar una DEK sobre datos que ya
 * están cifrados: el único camino para cambiar de proveedor es este.
 *
 * Cómo se protege, por orden:
 *   1. Se descifra TODO en memoria antes de escribir un solo byte. Si un archivo no abre,
 *      no se ha tocado nada.
 *   2. Se comprueba que lo recifrado se vuelve a leer igual, archivo por archivo.
 *   3. Se deja una copia `.bak-rekey` de cada original.
 *   4. La config nueva se escribe LA ÚLTIMA, cuando los datos ya están convertidos.
 *
 * Lo que NO se puede prometer, y se dice: renombrar varios archivos no es atómico. Si el
 * proceso muere a mitad, queda una mezcla — y se sale de ella restaurando los
 * `.bak-rekey`, que es justo lo que devuelve `backups`.
 */
export function rekeyDir (dir, newConfig, { password = '' } = {}) {
  const oldCfg = readConfig(dir)
  const nextCfg = { provider: 'machine', ...(newConfig || {}) }
  const oldKey = kekFor(dir, { password })

  // 1. Descifrar todo primero. Un fallo aquí no ha tocado nada.
  const files = encryptedFilesIn(dir)
  const plain = new Map()
  for (const n of files) {
    const p = path.join(dir, n)
    try { plain.set(n, decryptText(fs.readFileSync(p, 'utf8'), oldKey)) } catch (e) {
      throw new KekError('kek-rekey', `cannot decrypt ${n} with the current provider (${oldCfg.provider}): ${e.message}`)
    }
  }
  // Las bitácoras, por líneas. `decryptText` deja pasar el texto en claro, así que una
  // mitad vieja sin cifrar cruza intacta y sale cifrada con la clave nueva.
  const lineFiles = lineFilesIn(dir)
  const plainLines = new Map()
  for (const n of lineFiles) {
    const p = path.join(dir, n)
    try {
      const lines = fs.readFileSync(p, 'utf8').split('\n')
      plainLines.set(n, lines.map((l) => (l ? decryptText(l, oldKey) : l)))
    } catch (e) {
      throw new KekError('kek-rekey', `cannot decrypt ${n} with the current provider (${oldCfg.provider}): ${e.message}`)
    }
  }

  // 2. La clave nueva, todavía sin escribir su envoltorio.
  let newKey; let newBlob = null
  if (nextCfg.provider === 'machine') {
    newKey = machineKey(dir, password)
  } else {
    const minted = mintKey(nextCfg)
    newKey = minted.dek; newBlob = minted.blob
  }

  // 3. Recifrar y comprobar, todo en memoria.
  const out = new Map()
  for (const [n, text] of plain) {
    const blob = encryptText(text, newKey)
    if (decryptText(blob, newKey) !== text) throw new KekError('kek-verify', `re-encryption check failed for ${n}: nothing was written`)
    out.set(n, blob)
  }
  for (const [n, lines] of plainLines) {
    const blobs = lines.map((l) => (l ? encryptText(l, newKey) : l))
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] && decryptText(blobs[i], newKey) !== lines[i]) {
        throw new KekError('kek-verify', `re-encryption check failed for ${n} (line ${i + 1}): nothing was written`)
      }
    }
    out.set(n, blobs.join('\n'))
  }

  // 4. A disco. Copia de seguridad, temporal, renombrar.
  const backups = []
  for (const [n, blob] of out) {
    const p = path.join(dir, n)
    const bak = p + '.bak-rekey'
    fs.copyFileSync(p, bak); backups.push(bak)
    const tmp = p + '.rekey.tmp'
    fs.writeFileSync(tmp, blob, { mode: 0o600 })
    fs.renameSync(tmp, p)
  }

  // 5. El envoltorio nuevo y la config, al final: hasta aquí `atrest.json` seguía
  //    describiendo la clave con la que YA no están cifrados los datos.
  const wrappedPath = path.join(dir, WRAPPED_FILE)
  if (newBlob) {
    const tmp = wrappedPath + '.tmp'
    fs.writeFileSync(tmp, newBlob.toString('base64') + '\n', { mode: 0o600 })
    fs.renameSync(tmp, wrappedPath)
  } else {
    try { fs.unlinkSync(wrappedPath) } catch (_) { /* no lo había */ }
  }
  writeConfig(dir, nextCfg)
  clearCache()

  return { from: oldCfg.provider, to: nextCfg.provider, files: [...out.keys()], backups }
}

export default {
  machineKey, kekFor, atRestFor, migrateFile, isEncrypted, encryptText, decryptText,
  rekeyDir, encryptedFilesIn, lineFilesIn, LINE_FILES, readConfig, writeConfig, probe, KekError
}
export { readConfig, writeConfig, probe, configFromEnv, KekError, CONFIG_FILE, WRAPPED_FILE }
