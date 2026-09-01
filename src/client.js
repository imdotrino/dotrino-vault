/**
 * Cliente de DISPOSITIVO (lado del que consulta el vault). Pensado para Node
 * (CLI/tests); en un dispositivo real (navegador/app) se usa el mismo flujo con
 * `@dotrino/identity/capabilities` + `@dotrino/proxy-client`.
 *
 * Emparejamiento ENDURECIDO (docs/pairing-protocol.md): el dispositivo genera su
 * sub-clave `D`, FIRMA el ENROLL con ella (prueba de posesión) y adjunta el COMPROMISO
 * de un código de 6 dígitos que MUESTRA en pantalla (el código nunca viaja). El dueño lo
 * tipea en la bóveda, que recompone el compromiso y solo entonces firma el cert; al
 * recibirlo, el dispositivo comprueba que le ECHAN su código y VALIDA el cert
 * estrictamente (firmado por la maestra que vio en el QR, y para SU clave) antes de
 * guardarlo. La maestra nunca sale del vault.
 */
import { makeDeviceKey, signWithDevice, verifyDelegation, verifyDeviceSig, makePairingCode, commitCode, pubkeyId } from '@dotrino/identity/capabilities'
import { sealersOf } from '@dotrino/identity/acta'

/**
 * Con qué se juzga un papel: el ACTA que la bóveda manda junto a él. Sustituye a comparar
 * `cert.iss` con la maestra — con varias selladoras el emisor puede ser otra llave del mismo
 * perfil, así que lo que se fija es el PERFIL, no la llave.
 */
function contexto (acta) {
  if (!acta) throw new Error('the vault did not send its record: cannot check who signed this cert')
  return { actaSeq: acta.seq, sealers: sealersOf(acta) }
}
import { installNodeGlobals } from './node-globals.js'
import { MSG } from './protocol.js'

async function freshClient ({ proxyUrl, dir = '.dotrino-vault-device' }) {
  installNodeGlobals(dir)
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  return client
}

/** Identifica la conexión bajo la pubkey de dispositivo D (para ser direccionable). */
async function identifyAsDevice (client, device) {
  if (!client.token) return
  const data = { op: 'identify', publickey: device.publickey, token: client.token, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  await client.identify({ data, signature })
}

function waitFor (client, predicate, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const off = client.on('message', (_from, payload) => {
      if (payload && typeof payload === 'object' && predicate(payload)) { cleanup(); resolve(payload) }
    })
    const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for the vault response')) }, timeoutMs)
    const cleanup = () => { off(); clearTimeout(t) }
  })
}

/**
 * Enrola este dispositivo contra un vault (flujo endurecido).
 * @param {Object} opts
 * @param {{v:number, iss:string, proxy:string, token:string, sn:string}} opts.qr  QR v2 del vault.
 * @param {string} [opts.label]
 * @param {(c:{deviceId:string,code:string})=>void} [opts.onChallenge]  Para MOSTRAR el código que el usuario tipea en la bóveda.
 * @param {number} [opts.approveTimeoutMs]  Cuánto esperar la aprobación humana (def 3 min).
 * @returns {Promise<{ device, cert, iss:string }>}  GUARDAR `device` (incluye la privada) + `cert`. `iss` = qr.iss verificado.
 */
export async function enroll ({ qr, label = '', dir, onChallenge, approveTimeoutMs = 180000 } = {}) {
  if (!qr?.iss || !qr?.proxy || !qr?.token || !qr?.sn) throw new Error('invalid qr (v2): missing iss/proxy/token/sn')
  const client = await freshClient({ proxyUrl: qr.proxy, dir })
  try {
    const device = await makeDeviceKey({ label })
    const myDeviceId = (await pubkeyId(device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // ESTE dispositivo genera el código y lo MUESTRA; solo viaja su COMPROMISO. El vault
    // lo aprende cuando un humano lo tipea, y solo firma el cert si el compromiso coincide.
    const code = makePairingCode()
    const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
    // ENROLL firmado con D = prueba de posesión (un token robado ya no basta).
    const data = { op: 'enroll', dpub: device.publickey, token: qr.token, sn: qr.sn, commit, label, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) {
          onChallenge?.({ deviceId: myDeviceId, code }) // el código lo genera y muestra ESTE dispositivo
        } else if (p.type === MSG.ENROLLED) {
          // Aceptamos solo si la bóveda ECHA nuestro código: una que no lo conoce no nos enrola.
          if (String(p.code || '').trim() !== code) return
          cleanup(); resolve(p)
        } else if (p.type === MSG.ERROR) {
          cleanup(); reject(new Error(p.error))
        }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for approval at the vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    // VALIDACIÓN ESTRICTA antes de persistir (cierra inyección de cert / sustitución de maestra).
    if (res.acta?.profileId !== qr.iss) throw new Error('the record is from a profile other than the one you saw (possible malicious proxy)')
    const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, ...contexto(res.acta) })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)
    if (res.cert.sub !== device.publickey) throw new Error('cert issued for a different device')
    // OJO: devolvemos qr.iss (la maestra que el usuario VIO), NO res.iss.
    return { device, cert: res.cert, iss: qr.iss }
  } finally { client.close() }
}

/**
 * Verifica que un mensaje REVOKED es AUTÉNTICO (firmado por la maestra pineada y
 * para este dispositivo). SOLO si esto es true se debe ejecutar el self-wipe — un
 * `MSG.ERROR` plano o una firma de otra clave JAMÁS borra (cierra el wipe-DoS).
 */
export async function verifyRevoke ({ body, signature, master, devicePubkey }) {
  if (!body || body.op !== 'revoke' || body.sub !== devicePubkey) return false
  if (typeof body.exp === 'number' && Date.now() > body.exp) return false
  return verifyDeviceSig({ publickey: master, data: body, signature })
}

/** Pide a la maestra que firme `payload` (scope vault:sign). */
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

/** Lee un nodo del árbol del vault (scope vault:read). */
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

/**
 * RENUEVA el cert de este dispositivo (sigue siendo el mismo: no hay QR ni aprobación).
 *
 * No es solo estirar la fecha: el scope del cert nuevo lo decide **el acta**, así que
 * renovar es también como llega a un dispositivo un permiso que el dueño le concedió
 * después de emparejarlo —y como se le cae uno que le quitaron—. Un cert vencido o
 * revocado no se renueva: ahí toca volver a emparejar.
 */
export async function requestRenew ({ masterPubkey, proxyUrl, device, cert, dir } = {}) {
  const client = await freshClient({ proxyUrl, dir })
  try {
    const data = { op: 'renew', publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitFor(client, (p) => p.type === MSG.RENEWED || p.type === MSG.ERROR)
    client.sendByPubkey(masterPubkey, { type: MSG.RENEW, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    // Se valida antes de devolverlo, igual que en el enrolamiento: un cert que no está
    // firmado por la maestra que ya conocemos, o que no es para esta llave, no se guarda.
    if (res.acta?.profileId !== masterPubkey) throw new Error('the record is from a profile other than the pinned one')
    const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, ...contexto(res.acta) })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)
    return { cert: res.cert }
  } finally { client.close() }
}

/** Llama un método del store de hilos/aperturas del vault (scope vault:store). */
export async function requestStore ({ masterPubkey, proxyUrl, device, cert, method, args, dir } = {}) {
  const client = await freshClient({ proxyUrl, dir })
  try {
    const data = { op: 'store', method, args: args || {}, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitFor(client, (p) => p.type === MSG.STORE_RESULT || p.type === MSG.ERROR)
    client.sendByPubkey(masterPubkey, { type: MSG.STORE, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return res.result
  } finally { client.close() }
}

/**
 * CONSOLA REMOTA (scope `vault:admin`, docs/consola-remota.md): administrar el perfil
 * desde un dispositivo, sin venir al PC. `op`: pending · pair · approve · reject ·
 * revoke · audit.
 *
 * El `nonce` de un solo uso NO es decorativo: `approve` y `revoke` cambian estado, así
 * que la ventana de frescura de ±5 min no basta para descartar un replay.
 */
export async function requestAdmin ({ masterPubkey, proxyUrl, device, cert, op, dir, ...rest } = {}) {
  const client = await freshClient({ proxyUrl, dir })
  try {
    const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('')
    const data = { op, ...rest, publickey: device.publickey, ts: Date.now(), nonce }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitFor(client, (p) => p.type === MSG.ADMIN_RESULT || p.type === MSG.ERROR)
    client.sendByPubkey(masterPubkey, { type: MSG.ADMIN, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return res.result
  } finally { client.close() }
}

/**
 * Verifica que un `vault.admin.event` (entró o salió alguien del perfil) viene
 * FIRMADO por la maestra pineada. Un aviso sin firma no se muestra: si no, cualquiera
 * podría llenar de alarmas falsas los dispositivos del usuario.
 */
export async function verifyAdminEvent ({ body, signature, master }) {
  if (!body || typeof body.ev !== 'string') return false
  return verifyDeviceSig({ publickey: master, data: body, signature })
}

export { identifyAsDevice }
