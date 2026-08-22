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
import { createHash } from 'node:crypto'
import {
  makeDeviceKey, makeDeviceEncKey, importDeviceEncKey, signWithDevice, verifyDelegation,
  verifyDeviceSig, makePairingCode, commitCode, pubkeyId
} from '@dotrino/identity/capabilities'
import { openWrap, wrapForMember, decryptWithCek } from '@dotrino/identity/content'
import { verifyActa, sealKeyAt } from '@dotrino/identity/acta'
import { MSG, secretsScope, isValidSecretsNs } from './protocol.js'
import { makeEphemeralKey, openSealed } from './sealed.js'
import { parseInvite } from './invite.js'
import { atRestFor } from './atrest.js'

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
    throw new Error('this runtime has no global WebSocket: use Node >=22')
  }
}


/**
 * La respuesta al `hello` va firmada y con el `sn` DENTRO de lo firmado. Comprobarlo
 * ata la respuesta a ESTA sesión: no vale la de otro emparejamiento ni la de otra
 * bóveda. Ojo con lo que NO prueba: cualquiera puede firmar con una llave suya, así
 * que esto no dice que sea TU bóveda — eso lo dice el código de 6 dígitos, que solo
 * aprende la bóveda donde tú lo tecleas.
 */
async function verifyHello (p, sn) {
  const b = p?.body
  if (!b?.iss || b.sn !== sn) throw new Error('the vault answered a different pairing')
  if (!(await verifyDeviceSig({ publickey: b.iss, data: b, signature: p.signature }))) {
    throw new Error('the vault reply is not properly signed')
  }
  // El modo también viene aquí, y aquí viene FIRMADO por la bóveda. Se comprueba
  // de nuevo aunque ya se haya mirado el del QR: en la forma corta el QR es un
  // código que pasó por manos ajenas, y esta es la primera vez que la bóveda
  // dice de su puño y letra qué se propone hacer.
  rejectAdoption(b.m)
  return b
}

/**
 * UN AGENTE NUNCA TRANSFIERE SU IDENTIDAD: el vault propone, el agente acepta.
 *
 * El emparejamiento tiene dos modos y los declara la bóveda en la invitación:
 * `join` (el que se enrola entra a la cuenta de la bóveda) y `adopt` (la bóveda
 * se queda con la cuenta que trae el aparato). El segundo existe para APARATOS,
 * que llegan con una cuenta propia y una historia que conservar.
 *
 * Un agente no tiene nada de eso: es un servicio, su identidad se la da el vault
 * y no hay caso en que quiera empujar la suya hacia arriba. Así que este camino
 * no se negocia, se rechaza — y se rechaza ACÁ, cuando el humano pega la
 * invitación, en vez de dejar que el viaje termine en un «intent-mismatch» del
 * otro lado que no le explica nada a nadie.
 */
function rejectAdoption (mode) {
  if (mode !== 'adopt') return
  throw new Error(
    'this invitation was opened to ADOPT the device account, and an agent does not transfer its identity: ' +
    'the vault grants it one. Open the pairing without `--adopt` (`dotrino-vault pair --service <ns>`).'
  )
}

/**
 * Canjea la cita del QR y devuelve la instancia a la que apunta.
 *
 * Una cita se quema al usarse y caduca en minutos, así que un error acá casi
 * siempre significa lo mismo para quien lo lee: el código ya se usó o venció, y
 * hay que pedir otro en la bóveda. Se dice así, no con el error crudo.
 */
async function resolveAppointment (client, code) {
  if (!code) throw new Error('the invitation carries no pairing code')
  if (typeof client.redeemPairingCode !== 'function') {
    throw new Error('this proxy does not support pairing codes (update @dotrino/proxy-client)')
  }
  const r = await client.redeemPairingCode(code)
  if (!r?.ok || !r.instance) {
    throw new Error(`that code is no good: ${r?.error || 'not valid'}. Ask the vault for a new one.`)
  }
  return r.instance
}

async function freshClient (proxyUrl, connectTimeoutMs = 20000) {
  installNodeGlobals()
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  // connect() del cliente solo se resuelve con 'connected' y solo rechaza en el
  // evento 'error' de transporte: si el socket cierra LIMPIO antes de 'connected'
  // (p.ej. el proxy banea la IP y envía close 1008), la promesa quedaría colgada
  // para siempre y waitForSecrets no reintentaría. Le ponemos un timeout propio.
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout connecting to the proxy')), connectTimeoutMs)
  })
  try {
    await Promise.race([client.connect(), timeout])
  } catch (e) {
    try { client.close() } catch (_) {}
    // El 'error' de transporte del cliente puede llegar como un Event sin
    // `message` → sin esto el operador ve una línea de error vacía.
    const why = e?.message || e?.type || 'transport error'
    throw new Error(`could not connect to the proxy ${proxyUrl}: ${why}`)
  } finally {
    clearTimeout(timer)
  }
  return client
}

/** Identifica la conexión bajo la pubkey del servicio (para ser direccionable). */
async function identifyAsService (client, device) {
  const data = { op: 'identify', publickey: device.publickey, token: client.token, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  await client.identify({ data, signature })
}

/** Cuánto espera un agente a que alguien apruebe (el pedido vive 5 min en la bóveda). */
export const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000 + 10 * 1000

function waitForMsg (client, predicate, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const off = client.on('message', (_from, payload) => {
      if (payload && typeof payload === 'object' && predicate(payload)) { cleanup(); resolve(payload) }
    })
    const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for the vault reply')) }, timeoutMs)
    const cleanup = () => { off(); clearTimeout(t) }
  })
}

const identityFileOf = (dir) => path.join(dir, IDENTITY_FILE)

/**
 * Lee la identidad persistida del servicio ({device, cert, iss, proxy, ns}) o null.
 *
 * CIFRADA EN REPOSO (`atrest.js`) con una clave ligada a ESTA máquina: el archivo
 * lleva la llave privada del dispositivo, así que copiarlo a otro equipo no sirve.
 * Un archivo de una versión anterior (en claro) se lee igual y queda cifrado en la
 * primera escritura.
 */
export function readServiceIdentity (dir) {
  try {
    const text = fs.readFileSync(identityFileOf(dir), 'utf8')
    return JSON.parse(atRestFor(dir).decrypt(text))
  } catch (_) { return null }
}

function writeServiceIdentity (dir, obj) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const f = identityFileOf(dir)
  const blob = atRestFor(dir).encrypt(JSON.stringify(obj, null, 2))
  fs.writeFileSync(f, blob, { mode: 0o600 })
}

/**
 * Enrola ESTE servicio contra el vault y persiste su identidad.
 *
 * UN AGENTE TIENE UNA SOLA IDENTIDAD, Y SE LA DA EL VAULT. A diferencia de un
 * aparato —que puede llevar varios perfiles y hasta meter su cuenta al vault por
 * adopción—, un agente no acumula identidades ni transfiere la suya: se enrola,
 * el vault le cede una (llave propia + cert de la maestra) y **la anterior, si
 * había, se descarta**. No hay fusión ni convivencia, y no hace falta: un agente
 * es un servicio, no una persona; no tiene por qué "ser varios".
 *
 * Enrolar dos veces, entonces, no es un error a bloquear sino un REEMPLAZO — que
 * es además la forma de rotar la identidad de un agente comprometido. Lo que sí
 * hace falta es que se vea: se avisa por `onReplace` qué identidad se tira.
 *
 * En el vault se corre antes `dotrino-vault pair --service <ns>`; la invitación
 * que imprime ese comando es el `qr` de aquí (en cualquiera de sus formas).
 * Muestra un código por `onCode`: el dueño lo tipea en el vault
 * (`dotrino-vault approve <código>`).
 *
 * @param {Object} opts
 * @param {object|string} opts.qr  La invitación: objeto, URL del QR o código pegado.
 * @param {string} opts.ns     Namespace de secretos del servicio (el mismo del pair).
 * @param {string} opts.dir    Dónde persistir `service-identity.json`.
 * @param {string} [opts.label]
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onCode]
 * @param {(prev:{ns:string, enrolledAt:number, deviceId:string})=>void} [opts.onReplace]
 *   Se llama ANTES de enrolar si ya había una identidad: la que va a descartarse.
 * @returns {Promise<{device, cert, iss:string, replaced:object|null}>}
 */
/**
 * EL ENROLAMIENTO, a secas: con una invitación de la bóveda (en cualquiera de sus
 * formas) crea las DOS llaves del aparato —firma y cifrado—, pide el cert y lo
 * verifica. **No persiste nada**: devuelve la identidad y quien llama decide dónde
 * vive (`enrollService` la guarda como servicio; `@dotrino/remote-agent` como
 * `link.json`). Es el único sitio del ecosistema donde se enrola un agente headless:
 * si falta algo al enrolar, se añade aquí y lo heredan todos.
 *
 * @param {Object} opts
 * @param {object|string} opts.qr   La invitación: objeto, URL del QR o código pegado.
 * @param {string} [opts.label]
 * @param {string|null} [opts.expectedScope]  Scope que el cert DEBE traer (null = no se exige).
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onCode]
 * @param {number} [opts.approveTimeoutMs]
 * @returns {Promise<{device, enc:{publickey:string, privateJwk:object}, cert, iss:string, proxy:string}>}
 */
export async function enrollWithVault ({ qr, label = 'agent', expectedScope = null, onCode, approveTimeoutMs = 180000 } = {}) {
  // `parseInvite` y NO `JSON.parse`: el vault no imprime JSON desde hace rato.
  // `dotrino-vault pair` emite la URL del QR y el código compacto (`c…`/`t…`, ver
  // invite.js); `parseInvite` acepta todas las formas, incluida la vieja.
  if (typeof qr === 'string') {
    const o = parseInvite(qr)
    if (!o) throw new Error('that does not look like a vault invitation (paste the output of `dotrino-vault pair`)')
    qr = o
  }
  if (!qr?.sn || !(qr.iss || qr.conn)) throw new Error('invalid qr: missing the vault or the nonce')
  rejectAdoption(qr.m)

  const client = await freshClient(qr.proxy || 'wss://proxy.dotrino.com')
  // QR CORTO: se le pregunta a la bóveda quién es, punto a punto, presentando el `sn`.
  if (!qr.iss) {
    const target = await resolveAppointment(client, qr.conn)
    const hello = await new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (p?.type === MSG.HELLO_OK) { finish(); verifyHello(p, qr.sn).then(resolve, reject) }
        else if (p?.type === MSG.ERROR) { finish(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { finish(); reject(new Error('the vault did not answer: that code may have expired')) }, 15000)
      const finish = () => { off(); clearTimeout(t) }
      try { client.send(target, { type: MSG.HELLO, sn: qr.sn }) } catch (e) { finish(); reject(e) }
    })
    qr = { ...qr, iss: hello.iss, proxy: hello.proxy || qr.proxy }
  }
  try {
    const device = await makeDeviceKey({ label })
    // La llave de CIFRADO: es a la que la bóveda sella cada variable. Sin ella el
    // aparato entra al acta pero no le llega ningún secreto, y no da error.
    const enc = await makeDeviceEncKey()
    const deviceId = (await pubkeyId(device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // Código de emparejamiento ALEATORIO: se muestra y NO se envía. La bóveda lo
    // aprende solo cuando un humano lo tipea → aprobar exige TENER esta máquina.
    const code = makePairingCode()
    const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
    const data = { op: 'enroll', intent: 'join', dpub: device.publickey, encPub: enc.encPublickey, token: qr.token || qr.sn, sn: qr.sn, commit, label, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) {
          const show = onCode || (({ deviceId, code }) => console.log(`[vault] device ${deviceId} · approve it on the vault:  dotrino-vault approve ${code}`))
          show({ deviceId, code })
        } else if (p.type === MSG.ENROLLED) { cleanup(); resolve(p) } else if (p.type === MSG.ERROR) { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for approval on the vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    if (res.code !== code) throw new Error('the vault echoed a code other than the one shown (possible malicious relay)')
    const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, ...(expectedScope ? { expectedScope } : {}) })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)
    if (res.cert.iss !== qr.iss) throw new Error('cert signed by a master other than the one in the QR')

    return { device, enc: { publickey: enc.encPublickey, privateJwk: enc.encPrivateJwk }, cert: res.cert, iss: qr.iss, proxy: qr.proxy || 'wss://proxy.dotrino.com' }
  } finally { client.close() }
}

/**
 * Enrola ESTE servicio contra el vault y persiste su identidad.
 *
 * UN AGENTE TIENE UNA SOLA IDENTIDAD, Y SE LA DA EL VAULT. A diferencia de un
 * aparato —que puede llevar varios perfiles y hasta meter su cuenta al vault por
 * adopción—, un agente no acumula identidades ni transfiere la suya: se enrola,
 * el vault le cede una (llave propia + cert de la maestra) y **la anterior, si
 * había, se descarta**. No hay fusión ni convivencia, y no hace falta: un agente
 * es un servicio, no una persona; no tiene por qué "ser varios".
 *
 * Enrolar dos veces, entonces, no es un error a bloquear sino un REEMPLAZO — que
 * es además la forma de rotar la identidad de un agente comprometido. Lo que sí
 * hace falta es que se vea: se avisa por `onReplace` qué identidad se tira.
 *
 * En el vault se corre antes `dotrino-vault pair --service <ns>`; la invitación
 * que imprime ese comando es el `qr` de aquí (en cualquiera de sus formas).
 * Muestra un código por `onCode`: el dueño lo tipea en el vault
 * (`dotrino-vault approve <código>`).
 *
 * @param {Object} opts
 * @param {object|string} opts.qr  La invitación: objeto, URL del QR o código pegado.
 * @param {string} opts.ns     Namespace de secretos del servicio (el mismo del pair).
 * @param {string} opts.dir    Dónde persistir `service-identity.json`.
 * @param {string} [opts.label]
 * @param {(c:{deviceId:string, code:string})=>void} [opts.onCode]
 * @param {(prev:{ns:string, enrolledAt:number, deviceId:string})=>void} [opts.onReplace]
 *   Se llama ANTES de enrolar si ya había una identidad: la que va a descartarse.
 * @returns {Promise<{device, cert, iss:string, replaced:object|null}>}
 */
export async function enrollService ({ qr, ns, dir, label, onCode, onReplace, approveTimeoutMs = 180000 } = {}) {
  if (!isValidSecretsNs(ns)) throw new Error('invalid ns (use [a-z0-9-]{1,32}, e.g. "proxy")')
  if (!dir) throw new Error('dir required (where to persist the service identity)')
  label = label || 'service:' + ns

  // La identidad que va a quedar descartada. Se avisa antes de tocar nada: para
  // el proxy, por ejemplo, esta llave es además su identidad de red, así que
  // reemplazarla le cambia el id de nodo y sus peers dejan de reconocerlo hasta
  // que se re-pineen a mano.
  const previous = readServiceIdentity(dir)
  let replaced = null
  if (previous?.device?.publickey) {
    replaced = {
      ns: previous.ns,
      enrolledAt: previous.enrolledAt,
      deviceId: (await pubkeyId(previous.device.publickey)).slice(0, 8).toUpperCase()
    }
    try { onReplace?.(replaced) } catch (_) {}
  }

  const { device, enc, cert, iss, proxy } = await enrollWithVault({ qr, label, expectedScope: secretsScope(ns), onCode, approveTimeoutMs })
  // v2: suma `enc`. El `device` (la llave de FIRMA) no se toca — de él sale el
  // id de nodo del proxio y la fila del acta.
  writeServiceIdentity(dir, { v: 2, ns, iss, proxy, device, enc, cert, enrolledAt: Date.now() })
  return { device, enc, cert, iss, replaced }
}

export async function ensureEncKey ({ dir } = {}) {
  const saved = readServiceIdentity(dir)
  if (!saved) throw new Error('service not enrolled: run enrollService() first')
  if (saved.enc?.publickey && saved.enc?.privateJwk) return { encPub: saved.enc.publickey, created: false }
  const enc = await makeDeviceEncKey()
  writeServiceIdentity(dir, { ...saved, v: 2, enc: { publickey: enc.encPublickey, privateJwk: enc.encPrivateJwk } })
  return { encPub: enc.encPublickey, created: true }
}

/**
 * Registra en la bóveda la llave de cifrado de ESTE servicio, para que pueda sellarle
 * sus variables. Genera la llave si falta.
 *
 * Va por `MSG.SECRETS` con `op:'enckey'` a propósito: no hace falta una constante nueva
 * del protocolo, y así el trío de archivos vendorizado en el iframe de identidad no se
 * mueve. Registrar una llave no da acceso a nada por sí solo —quien firma esta petición
 * ya tiene la llave de firma del servicio, o sea ya lee ese namespace—, así que no exige
 * la contraseña del perfil.
 */
export async function registerEncKey ({ dir, ns, proxyUrl, masterPubkey, device, cert, timeoutMs = 30000 } = {}) {
  const saved = readServiceIdentity(dir)
  const { encPub, created } = await ensureEncKey({ dir })
  ns = ns || saved?.ns
  proxyUrl = proxyUrl || saved?.proxy
  masterPubkey = masterPubkey || saved?.iss
  device = device || saved?.device
  cert = cert || saved?.cert
  if (!proxyUrl || !masterPubkey || !device || !cert) throw new Error('service not enrolled')

  const client = await freshClient(proxyUrl)
  try {
    await identifyAsService(client, device)
    const data = { op: 'enckey', ns, encPub, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const pending = waitForMsg(client, (p) => p.type === MSG.SECRETS_RESULT || p.type === MSG.ERROR, timeoutMs)
    client.sendByPubkey(masterPubkey, { type: MSG.SECRETS, data, signature, cert })
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    return { encPub, created, ok: true }
  } finally { client.close() }
}

/**
 * Pide los secretos del ns al vault (una petición puntual; lanza si falla).
 * Usa la identidad persistida por `enrollService` salvo que se pase explícita.
 * Renueva el cert automáticamente si está por vencer (best-effort).
 * @returns {Promise<Record<string,string>>}  secretos KEY→valor
 */
export async function fetchSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, timeoutMs = 30000, onPending, approvalTimeoutMs = APPROVAL_TIMEOUT_MS } = {}) {
  let saved = null
  if (dir) saved = readServiceIdentity(dir)
  // Sin `dir`: la identidad viene entera por parámetros — es el caso de un agente
  // enrolado por `@dotrino/remote-agent` (su `link.json` trae `device`, `cert` y `enc`).
  // Un mismo enrolamiento sirve para el plano de control y para los secretos.
  if (!saved && enc) saved = { ns, iss: masterPubkey, proxy: proxyUrl, device, cert, enc }
  ns = ns || saved?.ns
  proxyUrl = proxyUrl || saved?.proxy
  masterPubkey = masterPubkey || saved?.iss
  device = device || saved?.device
  cert = cert || saved?.cert
  if (!isValidSecretsNs(ns)) throw new Error('invalid ns')
  if (!proxyUrl || !masterPubkey || !device || !cert) {
    throw new Error('service not enrolled: run enrollService() first (service-identity.json missing)')
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
    let res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)

    // CAJÓN CON APROBACIÓN: la bóveda contesta «pendiente» (firmado) y la respuesta de
    // verdad llega cuando el aparato que aprueba firme — por esta misma conexión, que
    // sigue identificada. Se espera lo que dura el pedido; denegado o vencido es error.
    if (res.body?.op === 'secrets.pending' && res.body.ns === ns) {
      const okPending = await verifyDeviceSig({ publickey: masterPubkey, data: res.body, signature: res.signature })
      if (!okPending) throw new Error('invalid master signature on the pending reply')
      try { onPending?.({ id: res.body.id, ns, exp: res.body.exp }) } catch (_) {}
      const until = typeof res.body.exp === 'number' ? Math.max(5000, res.body.exp - Date.now() + 5000) : approvalTimeoutMs
      res = await waitForMsg(client, (p) => (p.type === MSG.SECRETS_RESULT && p.body?.op === 'secrets.result') || p.type === MSG.ERROR, Math.min(until, approvalTimeoutMs))
        .catch((e) => { throw new Error(/timeout/.test(e.message) ? 'approval: nobody approved the request in time' : e.message) })
      if (res.type === MSG.ERROR) throw new Error(res.error)
    }

    // Autenticidad: el cuerpo viene firmado por la MAESTRA pineada.
    const body = res.body
    if (!body || body.op !== 'secrets.result' || body.ns !== ns) throw new Error('malformed secrets reply')
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) throw new Error('stale secrets reply')
    const ok = await verifyDeviceSig({ publickey: masterPubkey, data: body, signature: res.signature })
    if (!ok) throw new Error('invalid master signature on the secrets reply')

    const payload = await openSealed({ privateKey: eph.privateKey, enc: body.enc })

    // DOS CAPAS DE SOBRE, y hacen cosas distintas:
    //   · la de fuera (`ek` efímera, recién abierta) tapa el TRAMO — el proxio no ve
    //     ni los nombres de tus variables;
    //   · la de dentro (`sealed`) tapa el REPOSO — la bóveda guarda lo que reparte
    //     sin poder abrirlo.
    // Se quedan las dos: quitar la de fuera dejaría los nombres al aire.
    if (payload?.sealed) return openSealedBundle(payload.sealed, saved, payload.acta, masterPubkey)

    // Bóveda todavía en v3: manda los valores tal cual, como siempre. Desaparece
    // cuando el último vault haya migrado (ver `docs/secretos-sellados.md`).
    if (!payload || typeof payload.secrets !== 'object') throw new Error('malformed secrets envelope')
    return payload.secrets
  } finally { client.close() }
}

/**
 * AGENTE SSH DELGADO (`dotrino-env ssh-agent`): este proceso no custodia nada. Lista las
 * llaves públicas que la bóveda tiene registradas y, por cada reto, le pide a la bóveda
 * que lo convierta en un PEDIDO que el teléfono firma. Cualquier aparato con `vault:sign`
 * puede pedir; quien decide es el teléfono.
 */
function serviceArgs ({ dir, ns, proxyUrl, masterPubkey, device, cert }) {
  let saved = dir ? readServiceIdentity(dir) : null
  if (!saved && device && cert) saved = { ns, iss: masterPubkey, proxy: proxyUrl, device, cert }
  const out = { ns: ns || saved?.ns, proxyUrl: proxyUrl || saved?.proxy, masterPubkey: masterPubkey || saved?.iss, device: device || saved?.device, cert: cert || saved?.cert }
  if (!out.proxyUrl || !out.masterPubkey || !out.device || !out.cert) throw new Error('service not enrolled: run enrollService() first (service-identity.json missing)')
  return out
}
async function sshRpc (args, data, { timeoutMs = 30000, waitResult = null } = {}) {
  const { proxyUrl, masterPubkey, device, cert } = serviceArgs(args)
  const client = await freshClient(proxyUrl)
  try {
    await identifyAsService(client, device)
    const signed = { ...data, publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data: signed })
    const pending = waitForMsg(client, (p) => p.type === MSG.SECRETS_RESULT || p.type === MSG.ERROR, timeoutMs)
    client.sendByPubkey(masterPubkey, { type: MSG.SECRETS, data: signed, signature, cert })
    let res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)
    if (waitResult && res.body?.op === 'ssh.pending') {
      try { waitResult.onPending?.({ id: res.body.id, exp: res.body.exp }) } catch (_) {}
      const until = typeof res.body.exp === 'number' ? Math.max(5000, res.body.exp - Date.now() + 5000) : APPROVAL_TIMEOUT_MS
      res = await waitForMsg(client, (p) => (p.type === MSG.SECRETS_RESULT && p.body?.op === 'ssh.sign.result') || p.type === MSG.ERROR, Math.min(until, APPROVAL_TIMEOUT_MS))
        .catch((e) => { throw new Error(/timeout/.test(e.message) ? 'ssh: nobody approved the request in time' : e.message) })
      if (res.type === MSG.ERROR) throw new Error(res.error)
    }
    const ok = await verifyDeviceSig({ publickey: masterPubkey, data: res.body, signature: res.signature })
    if (!ok) throw new Error('invalid master signature on the reply')
    return res.body
  } finally { client.close() }
}
/** Las llaves SSH públicas registradas en la bóveda: `[{ id, blob, comment }]`. */
export async function listSshKeys (args = {}) {
  const body = await sshRpc(args, { op: 'ssh.keys.public' })
  return Array.isArray(body.items) ? body.items : []
}
/** Pide la firma SSH de `data` con la llave `keyId`; devuelve el blob de firma (Buffer). */
export async function requestSshSign (args = {}, { keyId, data, onPending } = {}) {
  const body = await sshRpc(args, { op: 'ssh.sign', key: keyId, data: Buffer.from(data).toString('base64') }, { waitResult: { onPending } })
  if (typeof body.sig !== 'string') throw new Error('ssh: malformed signature reply')
  return Buffer.from(body.sig, 'base64')
}

/**
 * Abre un bundle sellado: saca la CEK de la envoltura dirigida a este aparato y
 * descifra con ella las variables privadas. Las públicas vienen en claro.
 *
 * Un fallo al abrir es un ERROR DURO, nunca un salto a lo del scope ni un valor
 * omitido: silenciarlo convertiría una rotación mal sellada en «el servicio sigue
 * con el valor viejo y nadie se entera», que es el peor modo de fallo de todo esto.
 */
/**
 * ¿SALIÓ ESTE SOBRE DE MI BÓVEDA? (§8.8 de `dotrino-vault/docs/secretos-sellados.md`)
 *
 * Envolver una llave solo necesita públicas, así que **cualquiera puede fabricar un sobre
 * válido** para este servicio: abrirlo prueba que es para mí, no que lo escribió quien
 * debía. Lo que lo prueba es la firma, hecha con la llave de sellado que el acta nombra
 * para el `seq` con el que se firmó — y el acta la firma la maestra, que es la que este
 * agente lleva pineada desde que se enroló.
 *
 * Una firma que NO cuadra es un error duro: es exactamente el caso que esto viene a
 * cazar. Un sobre SIN firma se acepta y se avisa: los hay de antes de que esto existiera
 * y negarse a arrancar por eso apagaría servicios que llevan meses bien.
 */
export async function makeSealCheck (acta, masterPubkey, log = console.log) {
  if (!acta) return () => {}
  // El acta tiene que venir firmada por la maestra que este agente ya conoce. Si la
  // selló otro (un traspaso que este agente no ha visto), no se puede establecer
  // procedencia: se dice y se sigue, en vez de fingir que se comprobó.
  const ok = acta.sealedBy === masterPubkey && (await verifyActa({ acta })).ok
  if (!ok) {
    log('[vault] ⚠ the record does not come from the master this agent knows: envelope provenance NOT checked')
    return () => {}
  }
  let avisado = false
  return async (owner, key, gen, e, seal) => {
    if (!seal?.sig) {
      if (!avisado) { avisado = true; log('[vault] ⚠ some envelopes carry no signature (sealed before this vault could sign)') }
      return
    }
    const pub = sealKeyAt(acta, seal.seq)
    if (!pub) throw new Error(`${key}: the record has no sealing key for #${seal.seq} (the envelope claims a record that does not exist)`)
    const good = await verifyDeviceSig({ publickey: pub, data: { owner, key, gen, iv: e.iv, ct: e.ct }, signature: seal.sig })
    if (!good) throw new Error(`${key}: the envelope signature does not check out — it did not come from this vault`)
  }
}

async function openSealedBundle (sealed, ident, acta = null, masterPubkey = null) {
  if (!ident?.enc?.privateJwk) {
    throw new Error('this service has no encryption key: update @dotrino/vault and re-enroll it')
  }
  const mine = await importDeviceEncKey(ident.enc.privateJwk)

  // UNA LLAVE POR GENERACIÓN, no una por cajón. Desde v5 cada escritura estrena
  // generación —la bóveda no puede reutilizar una llave que no puede abrir—, así que dos
  // variables del mismo cajón pueden venir de generaciones distintas. El bundle trae
  // TODAS las envolturas de este aparato; se abren perezosamente, solo las que hagan
  // falta. `sealed.ns`/`sealed.dev` (una sola, la vigente) siguen entrando: es el bundle
  // de v4 y sirve para lo que ese vault selló.
  const porGen = { ns: new Map(), dev: new Map() }
  const añade = (cual, info) => { if (info?.wrap) porGen[cual].set(info.gen ?? 0, info.wrap) }
  añade('ns', sealed.ns); añade('dev', sealed.dev)
  for (const cual of ['ns', 'dev']) for (const info of sealed.wraps?.[cual] || []) añade(cual, info)

  const abiertas = { ns: new Map(), dev: new Map() }
  const cekDe = async (cual, gen) => {
    if (abiertas[cual].has(gen)) return abiertas[cual].get(gen)
    // Un bundle de v4 no traía `gen` en la envoltura: si solo hay una, es esa.
    const wrap = porGen[cual].get(gen) ?? (porGen[cual].size === 1 ? [...porGen[cual].values()][0] : null)
    if (!wrap) return null
    const cek = await openWrap({ wrap, myEncPrivateKey: mine })
    abiertas[cual].set(gen, cek)
    return cek
  }

  const comprobarFirma = await makeSealCheck(acta, masterPubkey)

  const out = {}
  for (const [key, e] of Object.entries(sealed.entries || {})) {
    if (e.pub) { out[key] = e.v; continue }
    // `owner` dice de qué cajón salió, y `gen` con qué llave de ese cajón se abre.
    const cual = String(e.owner || '').startsWith('dev:') ? 'dev' : 'ns'
    const gen = e.gen ?? e.e?.gen ?? 0
    await comprobarFirma(e.owner, key, gen, e.e, e.seal)
    const cek = await cekDe(cual, gen)
    if (!cek) throw new Error(`no key to open ${key}: this device has no wrapping for its drawer`)
    out[key] = await decryptWithCek({ cek, envelope: e.e })
  }
  return out
}

/**
 * Escucha los avisos de cambio de configuración de la bóveda.
 *
 * A diferencia de `fetchSecrets` —que abre, pide y cierra—, esto mantiene la
 * conexión ABIERTA e identificada con la llave del servicio: es la dirección a la
 * que la bóveda le habla. Por eso un agente que quiera enterarse de una rotación
 * deja de ser un cliente de paso y pasa a ser uno permanente.
 *
 * Lo que NO hace: recargar nada. El aviso no trae valores, y la reacción correcta
 * es que el proceso termine y lo levante su supervisor (ver `watchEnv`).
 *
 * NO SE CONFÍA SOLO EN EL AVISO: al (re)conectar, COMPARA. Un aviso es un mensaje y
 * los mensajes se pierden — el agente pudo estar vivo pero incomunicado, y entonces
 * el aviso se encola en el proxio (24 h), llega tarde y lo tira la ventana de
 * frescura (5 min), o caduca en la cola y no llega nunca. En los tres casos el
 * agente se quedaba con la configuración vieja PARA SIEMPRE, porque al reconectar
 * solo volvía a escuchar: nunca preguntaba. Ahora, cada vez que la conexión se
 * restablece, pide el bundle y compara su huella con la que tiene aplicada; si no
 * coincide, reacciona igual que si hubiera llegado el aviso. El aviso es el camino
 * rápido; esto es el que no se pierde.
 *
 * Y lo mismo salva al interruptor de emergencia: si el cert se revocó mientras
 * estaba incomunicado, el `REVOKED` se perdió igual, pero la comparación recibe
 * «unauthorized: revoked» y apaga al agente ahí mismo.
 *
 * Defensas, porque una señal que provoca reinicios es un arma si se descuida:
 * · **Firma de la maestra pineada** y `ns` que coincida. Sin esto, cualquiera
 *   reinicia la flota ajena cuando quiera.
 * · **Frescura y anti-replay**: `ts` dentro de la ventana y estrictamente mayor
 *   que el último obedecido. Un aviso viejo reproducido no vuelve a disparar.
 * · **Gracia de arranque y piso entre avisos**: no se obedece recién arrancado ni
 *   dos veces seguidas. Si la configuración nueva rompe el arranque, sin esto el
 *   servicio entra en un ciclo de reinicios.
 * · **Jitter**: diez agentes del mismo ns no pueden salir todos en el mismo
 *   segundo.
 *
 * @param {Object} opts
 * @param {string} opts.dir            Identidad del servicio (`service-identity.json`).
 * @param {string} [opts.ns]
 * @param {(info:{ns:string, ts:number, via:'notice'|'reconcile'})=>void} opts.onChange
 *   `via` dice por dónde se enteró: `notice` (llegó el aviso) o `reconcile` (nadie
 *   avisó y la comparación al reconectar encontró otra configuración).
 * @param {(info:{nonce:string})=>void} [opts.onRevoked]  Cert revocado: apagar YA.
 * @param {Record<string,string>} [opts.applied]  El bundle que el agente tiene EN USO.
 *   Pasarlo es lo que permite detectar un cambio ya en la PRIMERA conexión — el que
 *   ocurrió entre que el agente pidió su configuración y logró ponerse a escuchar. Sin
 *   él no se pierde la protección, solo empieza una conexión más tarde: la primera se
 *   limita a tomar la referencia.
 * @param {number} [opts.graceMs=30000]      No obedecer avisos durante los primeros N ms.
 *   La comparación también lo respeta, pero **aplazándose** (el aviso sí se descarta):
 *   es lo que impide que un fallo sistemático se convierta en un ciclo de reinicios,
 *   porque acota los reinicios por comparación a uno por ventana.
 * @param {number} [opts.minIntervalMs=60000] Mínimo entre dos avisos obedecidos.
 * @param {number} [opts.jitterMs=5000]      Espera aleatoria antes de avisar.
 * @param {number} [opts.reconcileMinMs=30000] Mínimo entre dos comparaciones. Sin él,
 *   una conexión que va y viene cada cinco segundos le pediría el bundle a la bóveda
 *   cada cinco segundos, y son N agentes.
 * @param {(m:string)=>void} [opts.log]
 * @returns {Promise<{stop:()=>void, reconcile:()=>Promise<boolean>}>}
 *   `reconcile()` fuerza la comparación (útil desde un chequeo de salud); devuelve si
 *   encontró un cambio.
 */
export async function watchSecretsChanges ({
  dir, ns, onChange, onRevoked, applied, graceMs = 30000, minIntervalMs = 60000, jitterMs = 5000,
  reconcileMinMs = 30000, log = () => {}
} = {}) {
  const saved = dir ? readServiceIdentity(dir) : null
  ns = ns || saved?.ns
  if (!saved?.device || !saved?.cert || !saved?.iss || !saved?.proxy) {
    throw new Error('service not enrolled: nobody to listen to')
  }
  const master = saved.iss
  const bornAt = Date.now()
  let lastTs = 0
  let lastObeyed = 0
  const inFlight = new Set()   // avisos cuya firma se está comprobando ahora mismo
  let stopped = false
  let client = null
  let retryTimer = null
  // Huella de la configuración EN USO. Comparar huellas y no valores es lo que permite
  // decir «esto no es lo que está corriendo» sin volver a manejar los secretos.
  let fingerprint = applied === undefined ? null : fingerprintOf(applied)
  let firstConnection = true
  let lastReconcile = 0
  let reconciling = false
  let reconcileRetry = null

  /**
   * REVOCACIÓN = interruptor de emergencia. Hasta ahora revocar un cert no le
   * quitaba nada a un servicio YA CORRIENDO: seguía operando con los secretos en
   * memoria hasta que alguien se acordara de reiniciarlo (el README decía lo
   * contrario). Teniendo la conexión abierta, el aviso llega y el agente se apaga
   * en el acto — y no vuelve, porque al arrancar `fetchSecrets` recibe
   * «unauthorized: revoked», que no se arregla reintentando.
   *
   * Sin gracia, sin piso y sin jitter, al revés que un cambio de configuración:
   * apagar algo comprometido es justo lo que no debe esperar su turno.
   */
  const handleRevocation = async (payload) => {
    const body = payload.body
    if (!body || body.op !== 'revoke') return
    // Que sea MI revocación y no la de otro dispositivo del mismo dueño.
    if (body.sub !== saved.device.publickey) return
    if (saved.cert?.nonce && body.nonce !== saved.cert.nonce) return
    if (!(await verifyDeviceSig({ publickey: master, data: body, signature: payload.signature }))) {
      return log('[vault] revocation notice BADLY SIGNED: ignored')
    }
    log('[vault] ⚠ the vault REVOKED this agent cert: shutting down')
    try { onRevoked?.({ nonce: body.nonce }) } catch (e) { log('[vault] ' + e.message) }
  }

  /**
   * REPARTIR LA LLAVE DE MI CAJÓN a un miembro nuevo (§8.11 del diseño).
   *
   * Un aparato que entra después de escrita una variable no tiene envoltura de ella, y
   * la bóveda no se la puede hacer: envolver exige abrir la llave, y abrirla pide la
   * frase. Este agente SÍ la tiene abierta, así que la reparte él. No gana ningún poder
   * haciéndolo —ya podía leer eso— y por eso es el único que puede hacerlo sin que
   * nadie ceda nada.
   *
   * NO SE FÍA DE LO QUE LE MANDAN, y esto es lo que hace que sea seguro incluso si la
   * bóveda estuviera comprometida:
   *
   *  · la petición va firmada por la MAESTRA;
   *  · el acta viaja dentro y se comprueba aparte (también la firma la maestra);
   *  · **la llave pública del destinatario se saca del ACTA, nunca del mensaje** — si
   *    se cogiera del mensaje, quien lo mandara podría hacer que este agente envolviera
   *    la llave para una pública suya;
   *  · y el destinatario tiene que ser de ESTE cajón (`cn === ns`): un servicio no puede
   *    ampliar el acceso a nada que no sea lo suyo.
   */
  const handleRewrap = async (payload) => {
    const body = payload?.body
    if (!body || body.op !== 'rewrap') return
    const mineOwners = [`ns:${ns}`, `dev:${saved.device.publickey}`]
    if (!mineOwners.includes(body.owner)) return log('[vault] rewrap for a drawer that is not mine: ignored')
    if (!(await verifyDeviceSig({ publickey: master, data: body, signature: payload.signature }))) {
      return log('[vault] rewrap request BADLY SIGNED: ignored')
    }
    const acta = body.acta
    if (!acta || acta.sealedBy !== master || !(await verifyActa({ acta })).ok) {
      return log('[vault] rewrap request without a valid record: ignored')
    }
    const target = (acta.members || []).find((m) => m.pub === body.target)
    if (!target?.encPub) return log('[vault] rewrap: the target is not in the record (or has no encryption key)')
    if (target.cn !== ns) return log(`[vault] rewrap: ${String(body.target).slice(0, 12)}… is not part of «${ns}»: refused`)

    try {
      const ident = readServiceIdentity(dir)
      if (!ident?.enc?.privateJwk) return log('[vault] rewrap: this agent has no encryption key')
      const cek = await openWrap({ wrap: body.wrap, myEncPrivateKey: await importDeviceEncKey(ident.enc.privateJwk) })
      const wrap = await wrapForMember({ cek, memberEncPub: target.encPub })
      const data = { op: 'rewrap.ok', owner: body.owner, gen: body.gen, target: body.target, wrap, ts: Date.now() }
      const { signature } = await signWithDevice({ privateJwk: saved.device.privateJwk, data })
      client.sendByPubkey(master, { type: MSG.REWRAP_OK, data, signature, cert: saved.cert })
      log(`[vault] key handed to ${String(body.target).slice(0, 12)}… for ${body.owner} (gen ${body.gen})`)
    } catch (e) {
      log('[vault] rewrap failed: ' + e.message)
    }
  }

  const handleMessage = async (payload) => {
    if (payload?.type === MSG.REVOKED) return handleRevocation(payload)
    if (payload?.type === MSG.REWRAP) return handleRewrap(payload)
    if (payload?.type !== MSG.SECRETS_CHANGED) return
    const body = payload.body
    if (!body || body.op !== 'secrets.changed' || body.ns !== ns) return
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) {
      return log('[vault] change notice dated outside the window: ignored')
    }
    if (body.ts <= lastTs) return log('[vault] repeated change notice: ignored')
    // Dos copias del MISMO aviso pueden llegar a la vez, y comprobar la firma es
    // asíncrono: sin esta marca las dos pasarían el corte de `lastTs` antes de
    // que ninguna lo actualizara, y el agente se reiniciaría por partida doble.
    // La marca se pone antes del `await` y el `lastTs` DESPUÉS de verificar, para
    // que un aviso falso con fecha lejana no pueda dejar fuera a los de verdad.
    if (inFlight.has(body.ts)) return
    inFlight.add(body.ts)
    let valid = false
    try {
      valid = await verifyDeviceSig({ publickey: master, data: body, signature: payload.signature })
    } finally { inFlight.delete(body.ts) }
    if (!valid) return log('[vault] change notice BADLY SIGNED: ignored (not from your vault)')
    if (body.ts <= lastTs) return
    lastTs = body.ts

    const now = Date.now()
    if (now - bornAt < graceMs) {
      return log('[vault] change notice right after start: ignored (avoids the restart loop)')
    }
    if (now - lastObeyed < minIntervalMs) {
      return log('[vault] change notice too close to the previous one: ignored')
    }
    lastObeyed = now

    const wait = Math.floor(Math.random() * jitterMs)
    log(`[vault] the vault reports config for "${ns}" changed (in ${wait} ms)`)
    setTimeout(() => { if (!stopped) { try { onChange?.({ ns, ts: body.ts, via: 'notice' }) } catch (e) { log('[vault] ' + e.message) } } }, wait)
  }

  /**
   * PREGUNTA en vez de esperar a que le cuenten: pide el bundle y lo compara con el
   * que está en uso. Es la red que recoge todo lo que el aviso deja caer — el que se
   * perdió mientras el agente estaba incomunicado, el que llegó fuera de la ventana de
   * frescura, el que caducó en la cola del proxio y el que el propio agente descartó.
   *
   * Lo que compara son DOS BUNDLES DE LA BÓVEDA, nunca el `.env` contra el bundle. Por
   * eso recibir la configuración por primera vez —tarde, que es como la recibe el
   * proxio— no es un cambio: la referencia es lo que el agente recibió, no lo que tenía
   * antes de recibir nada. Es la razón de fondo por la que esto no puede volverse un
   * ciclo de reinicios; el tope de frecuencia de abajo es el cinturón.
   *
   * No pasa por el piso entre avisos, y es a propósito: ese freno existe porque un aviso
   * es una señal que alguien podría repetir para provocar reinicios. Esto no es una
   * señal, es el estado real firmado por la maestra — si de verdad difiere, reiniciar es
   * siempre lo correcto, y al volver ya coincide.
   *
   * @returns {Promise<boolean>} si encontró (y anunció) un cambio.
   */
  const reconcile = async (trigger) => {
    if (stopped || reconciling) return false
    if (Date.now() - lastReconcile < reconcileMinMs) return false
    // TOPE DE FRECUENCIA, que es lo único que separa esto de un ciclo de reinicios.
    // Reiniciar por comparación no puede repetirse más de una vez por gracia de
    // arranque: si algo hiciera que la comparación fallara SIEMPRE, el proceso saldría
    // cada 30 s y no cada dos, que es la diferencia entre que el supervisor lo note y
    // que la máquina se pase el día arrancando.
    //
    // Y a diferencia del aviso, aquí no se DESCARTA: se APLAZA. Descartarlo era el
    // defecto que este cambio vino a cerrar, así que reintroducirlo por la puerta de
    // atrás sería el peor final posible.
    const sinceStart = Date.now() - bornAt
    if (sinceStart < graceMs) {
      clearTimeout(reconcileRetry)
      reconcileRetry = setTimeout(() => { reconcile(trigger).catch(() => {}) }, graceMs - sinceStart + 50)
      reconcileRetry.unref?.()
      return false
    }
    reconciling = true
    let bundle = null
    try {
      bundle = await fetchSecrets({ dir, ns })
    } catch (e) {
      // El cert revocado mientras estaba incomunicado: el `REVOKED` firmado se perdió
      // igual que el aviso, y esta es la única otra forma de enterarse. Lo demás (la
      // bóveda apagada, el proxio a medio levantar) es transitorio y se reintenta en la
      // siguiente conexión: no se apaga nada por no haber podido preguntar.
      if (/unauthorized: revoked/.test(e.message)) {
        log('[vault] ⚠ the vault REVOKED this agent cert (noticed on ' + trigger + '): shutting down')
        try { onRevoked?.({ nonce: saved.cert?.nonce || null }) } catch (err) { log('[vault] ' + err.message) }
      } else {
        log('[vault] could not check the config on ' + trigger + ': ' + e.message)
      }
      return false
    } finally {
      reconciling = false
      lastReconcile = Date.now()
    }
    const current = fingerprintOf(bundle)
    if (fingerprint === null) { fingerprint = current; return false }  // primera vez: solo tomar referencia
    if (current === fingerprint) return false
    fingerprint = current
    lastObeyed = Date.now()
    log(`[vault] the config for "${ns}" is not the one running (noticed on ${trigger}): the notice never arrived`)
    if (!stopped) { try { onChange?.({ ns, ts: Date.now(), via: 'reconcile' }) } catch (e) { log('[vault] ' + e.message) } }
    return true
  }

  const connect = async () => {
    if (stopped) return
    try {
      client = await freshClient(saved.proxy)
      await identifyAsService(client, saved.device)
      client.on('message', (_from, p) => { handleMessage(p).catch(() => {}) })
      // Reconectar solo: si se cae el proxio, el agente deja de ser avisable, y
      // eso es exactamente el momento en que uno querría enterarse de una rotación.
      client.on('disconnected', () => { if (!stopped) retryTimer = setTimeout(connect, 5000) })
      log('[vault] listening for config changes')
      // Y COMPARAR, porque el rato sin conexión es justo cuando se pierde un aviso.
      // También en la PRIMERA conexión, aunque el agente venga de pedir el bundle hace
      // un instante: entre aquello y esto pudo pasar cualquier cosa —si el proxio estaba
      // caído, esta primera conexión llega minutos después— y ahí ya no hay quien avise.
      // Cuesta una consulta por arranque; el hueco que tapa no tiene límite.
      const trigger = firstConnection ? 'startup' : 'reconnect'
      firstConnection = false
      reconcile(trigger).catch(() => {})
    } catch (e) {
      if (!stopped) retryTimer = setTimeout(connect, 5000)
    }
  }
  await connect()

  return {
    stop () {
      stopped = true
      clearTimeout(retryTimer)
      clearTimeout(reconcileRetry)
      try { client?.close() } catch (_) {}
    },
    reconcile: () => reconcile('demand')
  }
}

/**
 * Huella de un bundle. Las claves van ORDENADAS: el bundle se arma mezclando el cajón
 * del scope con el del aparato, así que el mismo contenido puede llegar en otro orden y
 * un cambio de orden no es un cambio de configuración.
 */
function fingerprintOf (secrets) {
  const pairs = Object.entries(secrets || {}).map(([k, v]) => [k, String(v)]).sort((a, b) => (a[0] < b[0] ? -1 : 1))
  return createHash('sha256').update(JSON.stringify(pairs)).digest('hex')
}

/**
 * Bucle de arranque de un servicio: pide los secretos y, si el vault no está
 * disponible, REINTENTA para siempre (con backoff hasta `maxRetryMs`). El
 * servicio no opera hasta que esto resuelva — esa es la regla.
 * @returns {Promise<Record<string,string>>}
 */
export async function waitForSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, retryMs = 5000, maxRetryMs = 60000, onRetry, onPending } = {}) {
  let delay = retryMs
  for (;;) {
    try {
      return await fetchSecrets({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, onPending })
    } catch (e) {
      // Lo NO transitorio no se arregla reintentando: falta de enrolamiento,
      // cert revocado/vencido o scope equivocado exigen re-emparejar → se corta.
      // Que te lo DENIEGUEN tampoco se reintenta: fue una decisión, no un tropiezo.
      if (/not enrolled|invalid ns|unauthorized: (revoked|expired|scope|cn|untrusted-issuer|cert-device-mismatch|denied)/.test(e.message)) throw e
      try { onRetry?.(e, delay) } catch (_) {}
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(maxRetryMs, Math.round(delay * 1.6))
    }
  }
}
