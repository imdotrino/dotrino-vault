/**
 * UNA SESIÓN DE LA BÓVEDA EN UNA LAMBDA, sin nada de AWS dentro (ver `README.md`).
 *
 * La bóveda no vive conectada: el proxio la despierta cuando llega algo para su cuenta
 * (`push-subscribe` con `kind:'wake'`, websocket-proxy ≥ 1.7.0). Una sesión es:
 *
 *   1. poner el CERROJO (`.lease`): una sesión a la vez;
 *   2. bajar el perfil del almacén y arrancar la MISMA bóveda del binario (`src/vault.js`) —o
 *      el mismo replicador (`src/replica.js`)—, que se conecta al proxio por WebSocket, se
 *      identifica y recibe lo encolado;
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
import { PAIRING_TTL_MS } from '../lib/src/enroll.js'

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
 * QUÉ ARRANCA UNA SESIÓN. La sesión es la misma para las dos (cerrojo, reflejo en el almacén,
 * inactividad); lo que cambia es la pieza que corre dentro. Cada una devuelve
 * `{ ready, busy(), close() }`: `busy()` dice que hay algo vivo en memoria que se perdería al
 * apagarse.
 */
export const vaultStarter = ({ startVault, onReady = null }) => async ({ dir, proxyUrl, wakeUrl, onActivity, log, push }) => {
  const vault = await startVault({ dir, proxyUrl, log, platform: { wakeUrl, onActivity } })
  await push()
  const ready = onReady ? await onReady(vault) : null
  return {
    ready,
    // Un emparejamiento esperando su código o un pedido esperando al aprobador no son
    // inactividad: apagarse ahí los perdería, porque viven en memoria.
    busy: () => vault.listPending().length > 0 || vault.listApprovals().length > 0,
    close: () => vault.close()
  }
}

/** La réplica (`src/replica.js`): reparte lo que la bóveda ya firmó. No guarda nada en memoria. */
export const replicaStarter = ({ runReplica }) => async ({ dir, proxyUrl, wakeUrl, onActivity, log }) => {
  const r = await runReplica({ dir, proxyUrl, wakeUrl, onActivity, log })
  return { ready: { publickey: r.publickey, id: r.id }, busy: () => false, close: () => r.stop() }
}

/**
 * @param {object} opts
 * @param {object} opts.store        el almacén (`./mirror.mjs`)
 * @param {string} opts.dir          el directorio local
 * @param {Function} opts.start      `vaultStarter(...)` o `replicaStarter(...)`
 * @param {string} [opts.proxyUrl]
 * @param {string} [opts.wakeBase]   la URL de la función: con ella y el secreto se arma la de despertar
 * @param {number} opts.deadline     ms epoch en que la sesión tiene que haber terminado
 * @param {number} [opts.idleMs]
 * @param {string} [opts.owner]      quién tiene el cerrojo (el id de la invocación)
 * @returns {Promise<{ ready: any, reason: string }>}
 */
export async function runSession ({ store, dir, start, proxyUrl, wakeBase = null, deadline, idleMs = IDLE_MS, owner = 'session', log = () => {} }) {
  if (!Number.isFinite(deadline)) throw Object.assign(new Error('runSession: a deadline is required'), { code: 'no-deadline' })
  if (typeof start !== 'function') throw Object.assign(new Error('runSession: start is required'), { code: 'no-start' })
  const lease = await takeLease(store, { owner, deadline })
  let piece = null
  const mirror = createMirror({ store, dir })
  try {
    const pulled = await mirror.pull()
    log(`[vault-lambda] pulled from the store: ${pulled} file(s)`)
    ensureKekConfig(dir, pulled)

    const wakeUrl = wakeBase ? `${wakeBase.replace(/\/+$/, '')}/wake?k=${await wakeSecret(store, { create: true })}` : null
    if (!wakeUrl) log('[vault-lambda] no function URL: the proxy will not be able to wake this one')
    let last = Date.now()
    piece = await start({ dir, proxyUrl, wakeUrl, onActivity: () => { last = Date.now() }, log, push: () => mirror.push() })
    await mirror.push()

    let reason = 'idle'
    for (;;) {
      if (Date.now() >= deadline) { reason = 'deadline'; break }
      if (!piece.busy() && Date.now() - last >= idleMs) break
      await sleep(Math.min(SYNC_EVERY_MS, Math.max(0, deadline - Date.now())))
      await mirror.push()
    }
    log(`[vault-lambda] session ends (${reason})`)
    return { ready: piece.ready, reason }
  } finally {
    try { piece?.close() } catch (_) {}
    try { await mirror.push() } finally { await lease.release() }
  }
}

/** El cerrojo, esperando un poco a que termine de guardarse la sesión anterior. */
async function takeLease (store, { owner, deadline }) {
  const hasta = Date.now() + LEASE_WAIT_MS
  for (;;) {
    try { return await acquireLease(store, { owner, ttlMs: deadline - Date.now() + 60_000 }) } catch (e) {
      if (e.code !== 'lease-busy' || Date.now() >= hasta) throw e
      await sleep(1000)
    }
  }
}

/** Dónde deja la réplica el código para quien lo pidió (`handler.mjs`, `{ kind:'enroll' }`). */
export const PAIRING_FILE = '.pairing'

/**
 * EL ALTA DE LA RÉPLICA en la cuenta del cliente, con SU invitación (`docs/replicas.md` §8.bis,
 * `dotrino-accounts/docs/DISENO.md` §9.1). Nada entra al acta sin invitación y sin que el
 * dueño apruebe el código en su bóveda.
 *
 * El código se deja en el almacén (`PAIRING_FILE`) en cuanto la bóveda lo pide, para que quien
 * lanzó el alta lo enseñe, y aquí se sigue esperando la aprobación. Va en claro a propósito:
 * no abre nada por sí solo —solo sirve tecleado en la bóveda del dueño, que es quien decide— y
 * quien lo lee tiene que enseñárselo a él.
 *
 * Una réplica ya enrolada no se vuelve a enrolar: se dice y se para.
 *
 * @returns {Promise<{ device: string, deviceId: string }>}
 */
export async function enrollReplica ({ store, dir, invitation, req, deadline, owner = 'enroll', enrollWithVault, openReplicaStore, keyLabel, scope, log = () => {} }) {
  if (!invitation) throw Object.assign(new Error('enrollReplica: no invitation'), { code: 'no-invitation' })
  const lease = await takeLease(store, { owner, deadline })
  const mirror = createMirror({ store, dir })
  try {
    const pulled = await mirror.pull()
    ensureKekConfig(dir, pulled)
    const rs = openReplicaStore(dir)
    if (rs.link) throw Object.assign(new Error('this replica is already enrolled'), { code: 'already-enrolled' })
    const r = await enrollWithVault({
      qr: invitation,
      label: 'réplica en la nube',
      expectedScope: scope,
      // Sin llave de cifrado en el acta no hay a dónde envolverle un sobre: repartir no puede
      // convertirse en leer (`src/replica.js`).
      withEncKey: false,
      // No más de lo que dura la invitación: pasado eso la bóveda ya no la aprueba, y esperar el
      // resto de la función solo tenía el cerrojo tomado y no dejaba probar con otra.
      approveTimeoutMs: Math.max(0, Math.min(PAIRING_TTL_MS, deadline - Date.now())),
      onCode: ({ deviceId, code }) => {
        log(`[vault-lambda] replica ${deviceId}: waiting for code ${code} to be approved on the vault`)
        store.put(PAIRING_FILE, Buffer.from(JSON.stringify({ req, deviceId, code, ts: Date.now() })))
          .catch((e) => log(`[vault-lambda] could not leave the pairing code: ${e.message}`))
      }
    })
    rs.setLink({ device: r.device, cert: r.cert, iss: r.iss, proxy: r.proxy })
    await mirror.push()
    const deviceId = await keyLabel(r.device.publickey)
    log(`[vault-lambda] replica ${deviceId} enrolled`)
    return { device: r.device.publickey, deviceId }
  } finally {
    try { await mirror.push() } finally { await lease.release() }
  }
}

/** Si la réplica está enrolada y por qué acta va. Solo lee. */
export async function replicaStatus ({ store, dir, openReplicaStore, keyLabel }) {
  const mirror = createMirror({ store, dir })
  const pulled = await mirror.pull()
  if (!pulled) return { enrolled: false, deviceId: null, seq: 0 }
  ensureKekConfig(dir, pulled)
  const rs = openReplicaStore(dir)
  if (!rs.link) return { enrolled: false, deviceId: null, seq: 0 }
  return { enrolled: true, deviceId: await keyLabel(rs.link.device.publickey), seq: rs.seq }
}

export default { runSession, vaultStarter, replicaStarter, enrollReplica, replicaStatus, wakeSecret, sameSecret, IDLE_MS, WAKE_FILE, PAIRING_FILE }
