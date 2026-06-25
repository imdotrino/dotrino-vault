/**
 * Cliente de DISPOSITIVO (lado del que consulta el vault). Pensado para Node
 * (CLI/tests); en un dispositivo real (navegador/app) se usa el mismo flujo con
 * `@dotrino/identity/capabilities` + `@dotrino/proxy-client` directamente.
 *
 * El dispositivo genera su propia sub-clave `D` (la maestra nunca la ve), se
 * enrola contra el vault (que le firma un `cert`), y luego pide firmas/lecturas
 * adjuntando el `cert` + una firma con `D`. La maestra nunca sale del vault.
 */
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'
import { installNodeGlobals } from './node-globals.js'
import { MSG } from './protocol.js'

async function freshClient ({ proxyUrl, dir = '.dotrino-vault-device' }) {
  installNodeGlobals(dir)
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  return client
}

/** Espera el primer mensaje que cumpla `predicate` (o expira). */
function waitFor (client, predicate, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const off = client.on('message', (_from, payload) => {
      if (payload && typeof payload === 'object' && predicate(payload)) { cleanup(); resolve(payload) }
    })
    const t = setTimeout(() => { cleanup(); reject(new Error('timeout esperando respuesta del vault')) }, timeoutMs)
    const cleanup = () => { off(); clearTimeout(t) }
  })
}

/**
 * Enrola este dispositivo contra un vault.
 * @param {Object} opts
 * @param {{iss:string, proxy:string, token:string}} opts.qr  Contenido del QR del vault.
 * @param {string} [opts.label]
 * @returns {Promise<{ device, cert, iss:string }>}  GUARDAR `device` (incluye la privada) + `cert`.
 */
export async function enroll ({ qr, label = '', dir } = {}) {
  if (!qr?.iss || !qr?.proxy || !qr?.token) throw new Error('qr inválido: faltan iss/proxy/token')
  const client = await freshClient({ proxyUrl: qr.proxy, dir })
  try {
    const device = await makeDeviceKey({ label })
    const pending = waitFor(client, (p) => p.type === MSG.ENROLLED || p.type === MSG.ERROR)
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, dpub: device.publickey, token: qr.token, label })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return { device, cert: res.cert, iss: res.iss }
  } finally { client.close() }
}

/**
 * Pide a la maestra que firme `payload` (no autoriza nada más que el scope del cert).
 * @returns {Promise<{ signature:string, publickey:string }>}
 */
export async function requestSign ({ masterPubkey, proxyUrl, device, cert, payload, dir } = {}) {
  const client = await freshClient({ proxyUrl, dir })
  try {
    const data = { op: 'sign', payload, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitFor(client, (p) => p.type === MSG.SIGNED || p.type === MSG.ERROR)
    client.sendByPubkey(masterPubkey, { type: MSG.SIGN, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return { signature: res.signature, publickey: res.publickey }
  } finally { client.close() }
}

/**
 * Lee un nodo del árbol de contenidos del vault (scope `vault:read`).
 * @returns {Promise<{ id:string, node:any }>}
 */
export async function requestGet ({ masterPubkey, proxyUrl, device, cert, id = 'root', dir } = {}) {
  const client = await freshClient({ proxyUrl, dir })
  try {
    const data = { op: 'get', id, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitFor(client, (p) => p.type === MSG.DATA || p.type === MSG.ERROR)
    client.sendByPubkey(masterPubkey, { type: MSG.GET, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return { id: res.id, node: res.node }
  } finally { client.close() }
}
