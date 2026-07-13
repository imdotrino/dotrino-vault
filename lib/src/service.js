/**
 * Cliente de SERVICIO del vault (Node ≥22). Para que un servicio del ecosistema
 * (proxy, geo, bots…) sea un CLIENTE IDENTIFICADO más y obtenga sus secretos
 * del vault en vez de llevarlos en el `.env`:
 *
 *   1. En el vault:  `dotrino-vault pair --service proxy`  (QR/código con scope
 *      SOLO `vault:secrets:proxy`) y `dotrino-vault secret set proxy TURN_KEY_ID …`
 *   2. En el servicio (una vez):  `enrollService({ qr, ns, dir })` — genera la
 *      llave del servicio, muestra el código de aprobación y persiste
 *      `service-identity.json` (device + cert + iss + proxy).
 *   3. En cada arranque:  `waitForSecrets({ dir, ns })` — pide los secretos y,
 *      si el vault no está, REINTENTA para siempre (regla del ecosistema: sin
 *      vault, el servicio espera; no arranca con secretos viejos ni vacíos).
 *
 * Seguridad: la petición va firmada por la llave del servicio + cert (cadena
 * D←maestra, scope `vault:secrets:<ns>`); la respuesta viene SELLADA (ECDH
 * efímero + AES-GCM → el proxy no ve los valores) y FIRMADA por la maestra
 * (verificada contra la `iss` pineada en el enrolamiento → un relay no puede
 * inyectar secretos falsos).
 */
import fs from 'node:fs'
import path from 'node:path'
import {
  makeDeviceKey, signWithDevice, verifyDelegation, verifyDeviceSig,
  makePairingCode, pubkeyId
} from '@dotrino/identity/capabilities'
import { MSG, secretsScope, isValidSecretsNs } from './protocol.js'
import { makeEphemeralKey, openSealed } from './sealed.js'

const IDENTITY_FILE = 'service-identity.json'
const FRESH_WINDOW_MS = 5 * 60 * 1000
const RENEW_BEFORE_MS = 7 * 24 * 60 * 60 * 1000 // renovar el cert si vence en <7 días

let _globalsInstalled = false
function installNodeGlobals () {
  if (_globalsInstalled) return
  _globalsInstalled = true
  // localStorage en memoria: @dotrino/proxy-client lo usa solo para su keypair
  // de canales (que un servicio no necesita persistir). Se define SIN leer el
  // getter nativo: en Node ≥22 acceder a `globalThis.localStorage` sin
  // `--localstorage-file` es no-funcional y además emite un warning.
  const desc = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  const isUsable = desc && 'value' in desc && typeof desc.value?.getItem === 'function'
  if (!isUsable) {
    const mem = new Map()
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: {
        getItem: (k) => (mem.has(k) ? mem.get(k) : null),
        setItem: (k, v) => mem.set(k, String(v)),
        removeItem: (k) => mem.delete(k),
        clear: () => mem.clear(),
        key: (i) => [...mem.keys()][i] ?? null,
        get length () { return mem.size }
      }
    })
  }
  if (typeof globalThis.WebSocket === 'undefined') {
    throw new Error('este entorno no tiene WebSocket global: usa Node ≥22')
  }
}

async function freshClient (proxyUrl) {
  installNodeGlobals()
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  return client
}

/** Identifica la conexión bajo la pubkey del servicio (para ser direccionable). */
async function identifyAsService (client, device) {
  const data = { op: 'identify', publickey: device.publickey, token: client.token, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  await client.identify({ data, signature })
}

function waitForMsg (client, predicate, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const off = client.on('message', (_from, payload) => {
      if (payload && typeof payload === 'object' && predicate(payload)) { cleanup(); resolve(payload) }
    })
    const t = setTimeout(() => { cleanup(); reject(new Error('timeout esperando respuesta del vault')) }, timeoutMs)
    const cleanup = () => { off(); clearTimeout(t) }
  })
}

const identityFileOf = (dir) => path.join(dir, IDENTITY_FILE)

/** Lee la identidad persistida del servicio ({device, cert, iss, proxy, ns}) o null. */
export function readServiceIdentity (dir) {
  try { return JSON.parse(fs.readFileSync(identityFileOf(dir), 'utf8')) } catch (_) { return null }
}

function writeServiceIdentity (dir, obj) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const f = identityFileOf(dir)
  fs.writeFileSync(f, JSON.stringify(obj, null, 2), { mode: 0o600 })
}

/**
 * Enrola ESTE servicio contra el vault (una sola vez; persiste la identidad).
 * En el vault se corre antes `dotrino-vault pair --service <ns>`; el QR/payload
 * de ese comando es el `qr` de aquí. Muestra un código por `onCode` (o stdout):
 * el dueño lo tipea en el vault (`dotrino-vault approve <código>`).
 *
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}|string} opts.qr  QR v2 (objeto o JSON string).
 * @param {string} opts.ns     Namespace de secretos del servicio (el mismo del pair).
 * @param {string} opts.dir    Dónde persistir `service-identity.json`.
 * @param {string} [opts.label]
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onCode]
 * @returns {Promise<{device, cert, iss:string}>}
 */
export async function enrollService ({ qr, ns, dir, label, onCode, approveTimeoutMs = 180000 } = {}) {
  if (typeof qr === 'string') { try { qr = JSON.parse(qr) } catch (_) { throw new Error('qr inválido: no es JSON') } }
  if (!qr?.iss || !qr?.proxy || !qr?.token || !qr?.sn) throw new Error('qr inválido (v2): faltan iss/proxy/token/sn')
  if (!isValidSecretsNs(ns)) throw new Error('ns inválido (usa [a-z0-9-]{1,32}, p.ej. "proxy")')
  if (!dir) throw new Error('falta dir (dónde persistir la identidad del servicio)')
  label = label || 'servicio:' + ns

  const client = await freshClient(qr.proxy)
  try {
    const device = await makeDeviceKey({ label })
    const deviceId = (await pubkeyId(device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // Código ALEATORIO generado AQUÍ: el vault no lo conoce; solo puede echarlo
    // de vuelta si el dueño lo tipeó (= tiene esta pantalla a la vista).
    const code = makePairingCode()
    const data = { op: 'enroll', dpub: device.publickey, token: qr.token, sn: qr.sn, label, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) {
          const show = onCode || (({ deviceId, code }) => console.log(`[vault-service] dispositivo ${deviceId} · aprueba en el vault:  dotrino-vault approve ${code}`))
          show({ deviceId, code })
        } else if (p.type === MSG.ENROLLED) { cleanup(); resolve(p) } else if (p.type === MSG.ERROR) { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout esperando la aprobación en el vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    // Validación estricta (igual que un dispositivo): cert de la maestra VISTA,
    // para ESTA llave, y el código echado debe ser el nuestro (anti vault falso).
    if (res.code !== code) throw new Error('el vault devolvió un código distinto al mostrado (posible relay malicioso)')
    const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, expectedScope: secretsScope(ns) })
    if (!v.ok) throw new Error('cert inválido: ' + v.reason)
    if (res.cert.iss !== qr.iss) throw new Error('cert firmado por una maestra distinta a la del QR')

    writeServiceIdentity(dir, { v: 1, ns, iss: qr.iss, proxy: qr.proxy, device, cert: res.cert, enrolledAt: Date.now() })
    return { device, cert: res.cert, iss: qr.iss }
  } finally { client.close() }
}

/**
 * Pide los secretos del ns al vault (una petición puntual; lanza si falla).
 * Usa la identidad persistida por `enrollService` salvo que se pase explícita.
 * Renueva el cert automáticamente si está por vencer (best-effort).
 * @returns {Promise<Record<string,string>>}  secretos KEY→valor
 */
export async function fetchSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, timeoutMs = 30000 } = {}) {
  let saved = null
  if (dir) saved = readServiceIdentity(dir)
  ns = ns || saved?.ns
  proxyUrl = proxyUrl || saved?.proxy
  masterPubkey = masterPubkey || saved?.iss
  device = device || saved?.device
  cert = cert || saved?.cert
  if (!isValidSecretsNs(ns)) throw new Error('ns inválido')
  if (!proxyUrl || !masterPubkey || !device || !cert) {
    throw new Error('servicio sin enrolar: corre primero enrollService() (falta service-identity.json)')
  }

  const client = await freshClient(proxyUrl)
  try {
    await identifyAsService(client, device)

    // Renovación de cert best-effort si vence pronto (mientras siga vigente).
    if (typeof cert.exp === 'number' && cert.exp - Date.now() < RENEW_BEFORE_MS && cert.exp > Date.now()) {
      try {
        const data = { op: 'renew', publickey: device.publickey, ts: Date.now() }
        const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
        const pending = waitForMsg(client, (p) => p.type === MSG.RENEWED || p.type === MSG.ERROR, 15000)
        client.sendByPubkey(masterPubkey, { type: MSG.RENEW, data, signature, cert })
        const res = await pending
        if (res.type === MSG.RENEWED && res.cert?.sub === device.publickey) {
          const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, expectedScope: secretsScope(ns) })
          if (v.ok) { cert = res.cert; if (dir && saved) writeServiceIdentity(dir, { ...saved, cert }) }
        }
      } catch (_) { /* la renovación no bloquea el fetch */ }
    }

    const eph = await makeEphemeralKey()
    const data = { op: 'secrets', ns, ek: eph.ek, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitForMsg(client, (p) => p.type === MSG.SECRETS_RESULT || p.type === MSG.ERROR, timeoutMs)
    client.sendByPubkey(masterPubkey, { type: MSG.SECRETS, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)

    // Autenticidad: el cuerpo viene firmado por la MAESTRA pineada.
    const body = res.body
    if (!body || body.op !== 'secrets.result' || body.ns !== ns) throw new Error('respuesta de secretos malformada')
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) throw new Error('respuesta de secretos vencida')
    const ok = await verifyDeviceSig({ publickey: masterPubkey, data: body, signature: res.signature })
    if (!ok) throw new Error('firma de la maestra inválida en la respuesta de secretos')

    const payload = await openSealed({ privateKey: eph.privateKey, enc: body.enc })
    if (!payload || typeof payload.secrets !== 'object') throw new Error('sobre de secretos malformado')
    return payload.secrets
  } finally { client.close() }
}

/**
 * Bucle de arranque de un servicio: pide los secretos y, si el vault no está
 * disponible, REINTENTA para siempre (con backoff hasta `maxRetryMs`). El
 * servicio no opera hasta que esto resuelva — esa es la regla.
 * @returns {Promise<Record<string,string>>}
 */
export async function waitForSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, retryMs = 5000, maxRetryMs = 60000, onRetry } = {}) {
  let delay = retryMs
  for (;;) {
    try {
      return await fetchSecrets({ dir, ns, proxyUrl, masterPubkey, device, cert })
    } catch (e) {
      // Lo NO transitorio no se arregla reintentando: falta de enrolamiento,
      // cert revocado/vencido o scope equivocado exigen re-emparejar → se corta.
      if (/sin enrolar|ns inválido|no autorizado: (revoked|expired|scope|untrusted-issuer|cert-device-mismatch)/.test(e.message)) throw e
      try { onRetry?.(e, delay) } catch (_) {}
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(maxRetryMs, Math.round(delay * 1.6))
    }
  }
}
