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
 * EL VAULT MANDA: sus valores PISAN los del `.env` y los del entorno.
 *
 * No es el default de `dotenv` y es a propósito. El vault no viene a reemplazar
 * al `.env` —que sigue ahí y sigue siendo el arranque de cualquier máquina sin
 * enrolar—, viene a ser la ÚLTIMA palabra sobre las claves que administra. Esa
 * es justamente la pieza que hace barata la rotación: se cambia el valor en un
 * solo lugar y ningún `.env` viejo, olvidado en un VPS, puede seguir ganando.
 * Con la precedencia al revés, rotar exigía además ir a limpiar cada copia
 * rancia —que es exactamente el trabajo que se quería evitar—, y peor: el
 * servicio arrancaba con la llave vieja SIN decir nada.
 *
 * Escotilla para depurar: `DOTRINO_ENV_OVERRIDE=0` devuelve la precedencia
 * clásica (gana lo que ya está en el entorno) para una corrida suelta, sin
 * tocar el vault ni el código.
 */
function overrideByDefault () {
  return process.env.DOTRINO_ENV_OVERRIDE !== '0'
}

/**
 * Trae los secretos del ns desde el vault y los pone en `process.env`.
 *
 * @param {Object} [opts]
 * @param {string} [opts.ns]         Namespace (por defecto: `DOTRINO_NS` o el único enrolado).
 * @param {string} [opts.dir]        Dónde está `service-identity.json` (por defecto: `serviceDir(ns)`).
 * @param {boolean} [opts.override]  El vault pisa lo que ya esté en el entorno (default: SÍ, ver arriba).
 * @param {boolean} [opts.wait]      `true` (default) = si el vault no está, ESPERA (reintenta) en vez de fallar.
 * @param {string[]} [opts.required] Claves que deben venir; si falta alguna, lanza.
 * @param {(e:Error, ms:number)=>void} [opts.onRetry]
 * @returns {Promise<{ns, secrets, injected:string[], overridden:string[], skipped:string[]}>}
 *   `overridden` = las que YA tenían otro valor en el entorno y el vault pisó. Es
 *   el dato que delata un `.env` rancio, así que se reporta en vez de callarse.
 */
export async function loadEnv ({ ns, dir, override, wait = true, required = [], onRetry } = {}) {
  if (override === undefined) override = overrideByDefault()
  ns = resolveNs(ns)
  dir = dir || serviceDir(ns)
  const load = wait ? waitForSecrets : fetchSecrets
  const secrets = await load({ dir, ns, onRetry })

  const missing = required.filter((k) => !(k in secrets))
  if (missing.length) {
    throw new Error(`faltan secretos en el ns "${ns}": ${missing.join(', ')} (agrégalos con \`dotrino-vault secret set ${ns} <CLAVE> <valor>\`)`)
  }

  return { ns, secrets, ...applyEnv(secrets, override) }
}

/**
 * Vuelca un bundle de secretos en `process.env` y cuenta qué cambió.
 *
 * Separado de `loadEnv` porque un servicio que NO puede bloquear su arranque
 * esperando al vault (el proxy: el vault le habla POR el proxy, así que
 * esperarlo sería un abrazo mortal) igual necesita aplicar el bundle cuando
 * llegue, tarde y por su cuenta.
 *
 * @returns {{injected:string[], overridden:string[], skipped:string[]}}
 */
export function applyEnv (secrets, override = overrideByDefault()) {
  const injected = []
  const overridden = []
  const skipped = []
  for (const [k, v] of Object.entries(secrets || {})) {
    const previo = process.env[k]
    const tenia = k in process.env
    if (!override && tenia) { skipped.push(k); continue }
    const valor = String(v)
    process.env[k] = valor
    injected.push(k)
    if (tenia && previo !== valor) overridden.push(k)
  }
  return { injected, overridden, skipped }
}
