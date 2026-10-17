/**
 * UNA SESIÓN DE LA BÓVEDA EN UNA LAMBDA, sin nada de AWS dentro (ver `README.md`).
 *
 * La bóveda no vive conectada: el proxio la despierta cuando llega algo para su cuenta
 * (`push-subscribe` con `kind:'wake'`, websocket-proxy ≥ 1.7.0). Una sesión es:
 *
 *   1. poner el CERROJO (`.lease`): una sesión a la vez;
 *   2. bajar el perfil del almacén y arrancar la MISMA bóveda del binario (`src/vault.js`),
 *      que se conecta al proxio por WebSocket, se identifica y recibe lo encolado;
 *   3. atender como siempre, subiendo al almacén lo que cambie cada pocos segundos;
 *   4. apagarse cuando pasan `idleMs` sin mensajes y no queda nada esperando, o al llegar al
 *      tope de la función;
 *   5. desconectarse, subir lo último y quitar el cerrojo — en ese orden: lo que llegue
 *      después ya no lo atiende esta sesión, lo encola el proxio y despierta a la siguiente.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { createMirror, acquireLease } from './mirror.mjs'
import { configFromEnv, probe as probeKek, writeConfig as writeKekConfig, CONFIG_FILE } from '../src/atrest.js'
import { runStep } from '../lib/src/kek.js'

/** Sin mensajes durante esto, la sesión termina (decidido por el dueño, 2026-10-17). */
export const IDLE_MS = 60_000
/** Cada cuánto se sube al almacén lo que cambió mientras la sesión sigue. */
export const SYNC_EVERY_MS = 2_000
/** Cuánto espera una sesión nueva a que termine la anterior (que se está guardando). */
export const LEASE_WAIT_MS = 30_000
/** El secreto de la URL de despertar, cerrado por el servicio de llaves. No es del perfil. */
export const WAKE_FILE = '.wake'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * UN PERFIL NUEVO NACE CON LA LLAVE FUERA DE LA MÁQUINA, o no nace. Aquí la «máquina» es un
 * contenedor que cambia en cada frío: con la llave derivada de ella, la cuenta quedaría
 * ilegible en el siguiente arranque. Uno que ya existe manda con su propio `atrest.json`.
 */
function ensureKekConfig (dir, pulled) {
  if (fs.existsSync(path.join(dir, CONFIG_FILE))) return
  if (pulled) throw Object.assign(new Error(`the stored profile has no ${CONFIG_FILE}: refusing to guess how its disk is encrypted`), { code: 'no-kek-config' })
  const kek = configFromEnv()
  if (!kek) throw Object.assign(new Error('a new profile here needs a key service: set DOTRINO_KMS_KEY_ID or DOTRINO_KEK_CMD'), { code: 'no-kms' })
  probeKek(dir, kek)
  writeKekConfig(dir, kek)
}

/**
 * EL SECRETO DE LA URL DE DESPERTAR. Solo lo saben la bóveda y el proxio al que se la
 * registra: así nadie más puede tenerla despierta gastando. Se guarda cerrado con el mismo
 * servicio de llaves que el disco (`configFromEnv`), así que en el almacén no está en claro.
 *
 * @returns {Promise<string>} el secreto
 */
export async function wakeSecret (store, { create = false } = {}) {
  const kek = configFromEnv()
  if (!kek) throw Object.assign(new Error('the wake secret needs a key service: set DOTRINO_KMS_KEY_ID or DOTRINO_KEK_CMD'), { code: 'no-kms' })
  let cur = null
  try { cur = await store.get(WAKE_FILE) } catch (e) { if (e.code !== 'ENOENT' && e.name !== 'NoSuchKey') throw e }
  if (cur) return runStep(kek.unwrap, Buffer.from(cur.body.toString('utf8').trim(), 'base64'), 'unwrap').toString('base64url')
  if (!create) throw Object.assign(new Error('this vault has no wake secret yet'), { code: 'no-wake-secret' })
  const raw = crypto.randomBytes(32)
  const blob = runStep(kek.wrap, raw, 'wrap')
  await store.put(WAKE_FILE, Buffer.from(blob.toString('base64')), { ifNoneMatch: '*' })
  return raw.toString('base64url')
}

/** ¿El secreto que trae el POST es el de esta bóveda? En tiempo constante. */
export function sameSecret (a, b) {
  const x = Buffer.from(String(a || '')); const y = Buffer.from(String(b || ''))
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y)
}

/**
 * @param {object} opts
 * @param {object} opts.store        el almacén (`./mirror.mjs`)
 * @param {string} opts.dir          el directorio local del perfil
 * @param {Function} opts.startVault `src/vault.js#startVault`
 * @param {string} [opts.proxyUrl]
 * @param {string} [opts.wakeBase]   la URL de la función: con ella y el secreto se arma la de despertar
 * @param {number} opts.deadline     ms epoch en que la sesión tiene que haber terminado
 * @param {number} [opts.idleMs]
 * @param {Function} [opts.onReady]  `(vault) => any` al arrancar (el alta del admin)
 * @param {string} [opts.owner]      quién tiene el cerrojo (el id de la invocación)
 * @returns {Promise<{ ready: any, reason: string }>}
 */
export async function runSession ({ store, dir, startVault, proxyUrl, wakeBase = null, deadline, idleMs = IDLE_MS, onReady = null, owner = 'session', log = () => {} }) {
  if (!Number.isFinite(deadline)) throw Object.assign(new Error('runSession: a deadline is required'), { code: 'no-deadline' })
  const hasta = Date.now() + LEASE_WAIT_MS
  let lease
  for (;;) {
    try { lease = await acquireLease(store, { owner, ttlMs: deadline - Date.now() + 60_000 }); break } catch (e) {
      if (e.code !== 'lease-busy' || Date.now() >= hasta) throw e
      await sleep(1000)
    }
  }
  let vault = null
  const mirror = createMirror({ store, dir })
  try {
    const pulled = await mirror.pull()
    log(`[vault-lambda] profile pulled from the store: ${pulled} file(s)`)
    ensureKekConfig(dir, pulled)

    const wakeUrl = wakeBase ? `${wakeBase.replace(/\/+$/, '')}/wake?k=${await wakeSecret(store, { create: true })}` : null
    if (!wakeUrl) log('[vault-lambda] no function URL: the proxy will not be able to wake this vault')
    let last = Date.now()
    vault = await startVault({ dir, proxyUrl, log, platform: { wakeUrl, onActivity: () => { last = Date.now() } } })
    await mirror.push()
    const ready = onReady ? await onReady(vault) : null
    await mirror.push()

    let reason = 'idle'
    for (;;) {
      if (Date.now() >= deadline) { reason = 'deadline'; break }
      // Un emparejamiento esperando su código o un pedido esperando al aprobador no son
      // inactividad: apagarse ahí los perdería, porque viven en memoria.
      const busy = vault.listPending().length > 0 || vault.listApprovals().length > 0
      if (!busy && Date.now() - last >= idleMs) break
      await sleep(Math.min(SYNC_EVERY_MS, Math.max(0, deadline - Date.now())))
      await mirror.push()
    }
    log(`[vault-lambda] session ends (${reason})`)
    return { ready, reason }
  } finally {
    try { vault?.close() } catch (_) {}
    try { await mirror.push() } finally { await lease.release() }
  }
}

export default { runSession, wakeSecret, sameSecret, IDLE_MS, WAKE_FILE }
