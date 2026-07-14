/**
 * `@dotrino/vault/env` — el "dotenv contra el vault".
 *
 * Un proyecto Node cualquiera obtiene sus credenciales del vault del dueño en
 * vez de llevarlas en un `.env`:
 *
 *   import { loadEnv } from '@dotrino/vault/env'
 *   await loadEnv({ ns: 'miapp' })          // → process.env.API_KEY, …
 *
 * o, con la forma clásica de dotenv (side-effect, ns por `DOTRINO_NS`):
 *
 *   import '@dotrino/vault/config'
 *
 * Lo que queda en el disco del servicio NO es un secreto: es la llave del
 * dispositivo (generada aquí, nunca sale) y un certificado con scope
 * `vault:secrets:<ns>`. Los valores solo viven en memoria del proceso; si la
 * máquina se compromete, se revoca el cert y no había nada que robar.
 *
 * Enrolar una vez:  npx dotrino-env enroll --ns miapp   (ver bin/dotrino-env.js)
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fetchSecrets, waitForSecrets, readServiceIdentity } from './service.js'
import { isValidSecretsNs } from './protocol.js'

/** Raíz donde viven las identidades de servicio de esta máquina/usuario. */
export function serviceRoot () {
  return process.env.DOTRINO_ENV_HOME || path.join(os.homedir(), '.dotrino', 'service')
}

/** Directorio de la identidad del servicio `ns` (`DOTRINO_ENV_DIR` lo pisa). */
export function serviceDir (ns) {
  if (process.env.DOTRINO_ENV_DIR) return process.env.DOTRINO_ENV_DIR
  if (!isValidSecretsNs(ns)) throw new Error('ns inválido (usa [a-z0-9-]{1,32}, p. ej. "miapp")')
  return path.join(serviceRoot(), ns)
}

/** Namespaces ya enrolados en esta máquina. */
export function listEnrolled () {
  let names = []
  try { names = fs.readdirSync(serviceRoot()) } catch (_) { return [] }
  return names.filter((ns) => isValidSecretsNs(ns) && readServiceIdentity(path.join(serviceRoot(), ns)))
}

/**
 * Resuelve el ns cuando no se pasa explícito: `DOTRINO_NS`, y si no, el único
 * enrolado en esta máquina. Con varios, exige elegir (no adivinamos).
 */
export function resolveNs (ns) {
  ns = ns || process.env.DOTRINO_NS
  if (ns) {
    if (!isValidSecretsNs(ns)) throw new Error('ns inválido: ' + ns)
    return ns
  }
  const found = listEnrolled()
  if (found.length === 1) return found[0]
  if (found.length === 0) {
    throw new Error('no hay ningún servicio enrolado en esta máquina: corre `npx dotrino-env enroll --ns <tu-app>`')
  }
  throw new Error(`hay varios servicios enrolados (${found.join(', ')}): elige uno con DOTRINO_NS=<ns> o loadEnv({ ns })`)
}

/**
 * Trae los secretos del ns desde el vault y los pone en `process.env`.
 *
 * @param {Object} [opts]
 * @param {string} [opts.ns]         Namespace (por defecto: `DOTRINO_NS` o el único enrolado).
 * @param {string} [opts.dir]        Dónde está `service-identity.json` (por defecto: `serviceDir(ns)`).
 * @param {boolean} [opts.override]  `true` = pisa variables ya presentes en el entorno (default: no).
 * @param {boolean} [opts.wait]      `true` (default) = si el vault no está, ESPERA (reintenta) en vez de fallar.
 * @param {string[]} [opts.required] Claves que deben venir; si falta alguna, lanza.
 * @param {(e:Error, ms:number)=>void} [opts.onRetry]
 * @returns {Promise<{ns:string, secrets:Record<string,string>, injected:string[], skipped:string[]}>}
 */
export async function loadEnv ({ ns, dir, override = false, wait = true, required = [], onRetry } = {}) {
  ns = resolveNs(ns)
  dir = dir || serviceDir(ns)
  const load = wait ? waitForSecrets : fetchSecrets
  const secrets = await load({ dir, ns, onRetry })

  const missing = required.filter((k) => !(k in secrets))
  if (missing.length) {
    throw new Error(`faltan secretos en el ns "${ns}": ${missing.join(', ')} (agrégalos con \`dotrino-vault secret set ${ns} <CLAVE> <valor>\`)`)
  }

  const injected = []
  const skipped = []
  for (const [k, v] of Object.entries(secrets)) {
    if (!override && k in process.env) { skipped.push(k); continue }
    process.env[k] = String(v)
    injected.push(k)
  }
  return { ns, secrets, injected, skipped }
}
