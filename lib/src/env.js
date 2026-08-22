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
import { fetchSecrets, waitForSecrets, readServiceIdentity, watchSecretsChanges } from './service.js'
import { isValidSecretsNs } from './protocol.js'

/** Raíz donde viven las identidades de servicio de esta máquina/usuario. */
export function serviceRoot () {
  return process.env.DOTRINO_ENV_HOME || path.join(os.homedir(), '.dotrino', 'service')
}

/** Directorio de la identidad del servicio `ns` (`DOTRINO_ENV_DIR` lo pisa). */
export function serviceDir (ns) {
  if (process.env.DOTRINO_ENV_DIR) return process.env.DOTRINO_ENV_DIR
  if (!isValidSecretsNs(ns)) throw new Error('invalid ns (use [a-z0-9-]{1,32}, e.g. "myapp")')
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
    if (!isValidSecretsNs(ns)) throw new Error('invalid ns: ' + ns)
    return ns
  }
  const found = listEnrolled()
  if (found.length === 1) return found[0]
  if (found.length === 0) {
    throw new Error('no service enrolled on this machine: run `npx dotrino-env enroll --ns <your-app>`')
  }
  throw new Error(`several services are enrolled (${found.join(', ')}): pick one with DOTRINO_NS=<ns> or loadEnv({ ns })`)
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

/** El último bundle que `applyEnv` puso a correr en este proceso (ver `watchEnv`). */
let lastApplied = null

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
export async function loadEnv ({ ns, dir, override, wait = true, required = [], onRetry, onPending } = {}) {
  if (override === undefined) override = overrideByDefault()
  ns = resolveNs(ns)
  dir = dir || serviceDir(ns)
  const load = wait ? waitForSecrets : fetchSecrets
  const secrets = await load({ dir, ns, onRetry, onPending })

  const missing = required.filter((k) => !(k in secrets))
  if (missing.length) {
    throw new Error(`missing secrets in ns "${ns}": ${missing.join(', ')} (add them with \`dotrino-vault secret set ${ns} <KEY> <value>\`)`)
  }

  return { ns, secrets, ...applyEnv(secrets, override) }
}

/**
 * Vuelca un bundle de secretos en `process.env` y cuenta qué cambió.
 *
 * ⚠ ESTO NO ES LA FORMA NORMAL. Un agente enrolado ESPERA al vault
 * (`loadEnv` / `import '@dotrino/vault/config'`): arrancar igual sería operar con
 * la configuración vieja del `.env`, que es justo lo que el vault vino a dejar de
 * ser, y la espera casi nunca duele porque estos agentes no son críticos.
 *
 * `applyEnv` existe para la ÚNICA excepción estructural: **el proxio**. El vault
 * habla con sus servicios POR el proxio, así que un proxio que espera al vault
 * espera a alguien que necesita el proxio escuchando — abrazo mortal, y con él se
 * cae el vault de todos. Ese caso arranca con lo que tenga y aplica el bundle
 * cuando llega, tarde y por su cuenta.
 *
 * Si tu agente no está en el camino por el que viaja el propio vault, no uses
 * esto: usa `loadEnv` y deja que espere.
 *
 * @returns {{injected:string[], overridden:string[], skipped:string[]}}
 */
export function applyEnv (secrets, override = overrideByDefault()) {
  // Lo último que este proceso puso a correr. `watchEnv` lo toma como referencia para
  // comparar, así que cualquier agente que use `loadEnv`/`applyEnv` —o sea, todos—
  // queda protegido del aviso perdido sin cablear nada.
  lastApplied = { ...(secrets || {}) }
  const injected = []
  const overridden = []
  const skipped = []
  for (const [k, v] of Object.entries(secrets || {})) {
    const previous = process.env[k]
    const had = k in process.env
    if (!override && had) { skipped.push(k); continue }
    const value = String(v)
    process.env[k] = value
    injected.push(k)
    if (had && previous !== value) overridden.push(k)
  }
  return { injected, overridden, skipped }
}

/**
 * Queda a la escucha de la bóveda y, cuando avisa que la configuración cambió,
 * TERMINA EL PROCESO para que el supervisor lo levante con todo fresco.
 *
 * Por qué salir en vez de recargar en caliente:
 *
 * 1. **Borra de memoria el valor viejo.** Es la razón de peso. En JavaScript un
 *    secreto no se puede borrar: los strings son inmutables, no hay `zeroize`, y
 *    el valor sigue en el heap hasta que al recolector le apetezca — más lo que
 *    capturó cada closure y cada caché derivada. Y una llave se rota casi siempre
 *    PORQUE SE FILTRÓ, así que dejarla viva en el proceso anula el motivo de
 *    rotarla. Un proceso nuevo empieza con el heap limpio.
 * 2. **Lee todo fresco.** Recargar en caliente exige que cada sitio que leyó una
 *    variable sepa releerla; esa lista hay que mantenerla para siempre y cuando se
 *    queda corta falla en silencio.
 * 3. **Sirve de interruptor de emergencia.** Revocar el cert de un agente ya no
 *    espera a que alguien se acuerde de reiniciarlo: se apaga, y al arrancar
 *    `fetchSecrets` recibe «no autorizado: revoked» y no vuelve.
 *
 * NO se reinicia solo: sale, y lo levanta quien lo supervisa (pm2, systemd con
 * `Restart=always`). Un proceso no puede reiniciarse a sí mismo de forma fiable, y
 * el supervisor ya trae backoff y tope de intentos, que es justo lo que evita que
 * una configuración rota se convierta en un ciclo.
 *
 * No depende solo del aviso: al conectar COMPARA su configuración con la de la bóveda
 * (`watchSecretsChanges`), porque un agente incomunicado se pierde el aviso y antes se
 * quedaba con lo viejo para siempre.
 *
 * OJO con lo que se compara: el bundle de la bóveda contra el bundle de la bóveda,
 * nunca contra el `.env`. Recibir la configuración por primera vez —tarde, que es como
 * la recibe el proxio— **no** es un cambio, y por eso esto no puede convertirse en un
 * ciclo de reinicios.
 *
 * @param {Object} [opts]
 * @param {string} [opts.ns]
 * @param {string} [opts.dir]
 * @param {Record<string,string>} [opts.applied]  Lo que este proceso tiene EN USO. Por
 *   defecto, lo último que pasó por `applyEnv` en este proceso — o sea, lo que puso a
 *   correr `loadEnv`.
 * @param {(info:{ns:string, ts:number, reason:'changed'|'revoked', via?:'notice'|'reconcile'})=>void} [opts.onUpdate]
 *   Reemplaza la salida por defecto. Úsalo cuando terminar el proceso no sea una
 *   opción — el caso del proxio, cuyo reinicio corta el transporte de todos.
 * @param {number} [opts.exitCode=0]  Salida LIMPIA: systemd con `Restart=on-failure`
 *   no levantaría un servicio que sale con 0, pero `Restart=always` sí, y pm2
 *   también. Se elige 0 porque salir a propósito no es un fallo.
 * @returns {Promise<{stop:()=>void}>}
 */
export async function watchEnv ({ ns, dir, applied = lastApplied ?? undefined, onUpdate, exitCode = 0, quiet = false, ...rest } = {}) {
  ns = resolveNs(ns)
  dir = dir || serviceDir(ns)
  const say = (m) => { if (!quiet) console.error(m) }

  const exitNow = (reason) => {
    say(`[dotrino-env] ${reason === 'revoked'
      ? 'the vault REVOKED this agent: exiting (it will not start again)'
      : 'new config in the vault: exiting so the supervisor brings it back clean'}`)
    process.exit(reason === 'revoked' ? 1 : exitCode)
  }

  return watchSecretsChanges({
    dir,
    ns,
    applied,
    log: say,
    onChange: ({ ts, via }) => (onUpdate ? onUpdate({ ns, ts, reason: 'changed', via }) : exitNow('changed')),
    // Un cert revocado sale con código de FALLO a propósito: si el supervisor lo
    // levanta, va a morir otra vez al no poder leer sus secretos, y el contador de
    // reinicios fallidos es lo que hace que se note en vez de girar en silencio.
    onRevoked: () => (onUpdate ? onUpdate({ ns, ts: Date.now(), reason: 'revoked' }) : exitNow('revoked')),
    ...rest
  })
}
