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
  verifyDeviceSig, makePairingCode, commitCode, pubkeyId } from '@dotrino/identity/capabilities'
import { openWrap, wrapForMember, decryptWithCek } from '@dotrino/identity/content'
import { verifyActa, sealKeyAt, sealersOf, memberCan } from '@dotrino/identity/acta'
import { MSG, secretsScope, isValidSecretsNs } from './protocol.js'
import { makeEphemeralKey, openSealed } from './sealed.js'
import { parseInvite } from './invite.js'
import { atRestFor } from './atrest.js'
import { connectLocal, hasLocalVault } from './localdesk.js'

const IDENTITY_FILE = 'service-identity.json'
const FRESH_WINDOW_MS = 5 * 60 * 1000

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

/**
 * EL MÁS CORTO PRIMERO: si la bóveda está en ESTA máquina, se le habla por su socket y no
 * se sale a internet (dueño, 2026-09-03: «estando en la misma máquina debería ser
 * inmediato»). Es el mismo protocolo y las mismas comprobaciones; lo único que cambia es
 * por dónde van los bytes.
 *
 * No es un repliegue que tape nada: el socket o está o no está, y no estar es el caso
 * normal —la bóveda suele vivir en otra máquina—. Lo que sí sería un repliegue es callar
 * un fallo del socket y salir por el proxio como si nada, así que se dice.
 */
async function freshClient (proxyUrl, connectTimeoutMs = 20000, master = null) {
  installNodeGlobals()
  // El id sale de la LLAVE de la bóveda, que es lo único que quien llama sabe seguro de
  // ella. Sin llave no se busca socket: no habría forma de saber cuál es el suyo.
  const masterId = master ? (await pubkeyId(master)).slice(0, 16) : null
  if (masterId && hasLocalVault(masterId)) {
    try { return await connectLocal({ masterId }) } catch (e) {
      console.error('[vault] the local desk is there but did not answer (%s): going out through the proxy', e.message)
    }
  }
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  // WEBRTC SOLO DONDE EXISTE. En Node no hay `RTCPeerConnection`, así que encenderlo
  // reventaría al negociar; en un navegador es nativo y es el camino directo que hay que
  // preferir. Se mira si está, en vez de apagarlo a mano para siempre: el día que este
  // código corra en un navegador —o que Node lo traiga— se enciende solo.
  const hayWebRTC = typeof globalThis.RTCPeerConnection === 'function'
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: hayWebRTC, autoReconnect: false })
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
/**
 * @param {boolean} [opts.withEncKey] Estrenar llave de CIFRADO y registrarla en el acta.
 *   Por defecto sí: sin ella el aparato entra pero no le llega ningún secreto.
 *
 *   Un REPLICADOR entra con `false`, y no es una optimización: es su garantía. Regla del
 *   dueño (2026-09-02), *«recibirá todos los sobres que se generen, ningún sobre firmado
 *   para él»*. Sin `encPub` en el acta no hay a dónde envolverle nada, así que repartir no
 *   puede convertirse en leer ni por descuido ni por un cambio futuro. Es el mismo cerrojo
 *   que tiene la llave de comunicación.
 */
/**
 * QR CORTO: se le pregunta a la bóveda QUIÉN ES, punto a punto, presentando el `sn`.
 *
 * Sale de dentro de `enrollWithVault` para poder preguntarlo ANTES de enrolar: quien
 * enrola necesita el nombre de la cuenta para saber dónde guardar (la etiqueta de bóveda
 * es una carpeta con ese nombre), y pedírselo al usuario cuando la bóveda ya lo sabe es
 * fricción sin nada a cambio.
 *
 * Devuelve el mismo `qr` con `iss`, `proxy` y `acct` puestos. Con un QR largo no pregunta
 * nada: ya los trae.
 */
export async function sayHello (client, qr) {
  if (qr.iss) return qr
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
  return { ...qr, iss: hello.iss, proxy: hello.proxy || qr.proxy, ...(hello.acct ? { acct: hello.acct } : {}) }
}

/**
 * Cómo se llama la cuenta de esa invitación, sin enrolar nada. Una conexión y una pregunta.
 */
export async function vaultAccountName (qr) {
  if (typeof qr === 'string') qr = parseInvite(qr)
  if (!qr?.sn) throw new Error('that does not look like a vault invitation')
  if (qr.acct) return qr.acct
  const client = await freshClient(qr.proxy || 'wss://proxy.dotrino.com')
  try { return (await sayHello(client, qr)).acct || '' } finally { try { client.close() } catch (_) {} }
}

export async function enrollWithVault ({ qr, label = 'agent', expectedScope = null, onCode, approveTimeoutMs = 180000, withEncKey = true } = {}) {
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
  qr = await sayHello(client, qr)
  try {
    const device = await makeDeviceKey({ label })
    // La llave de CIFRADO: es a la que la bóveda sella cada variable. Sin ella el
    // aparato entra al acta pero no le llega ningún secreto, y no da error. Un replicador
    // entra así A PROPÓSITO (ver `withEncKey`): reparte sobres cerrados y no abre ninguno.
    const enc = withEncKey ? await makeDeviceEncKey() : null
    const deviceId = (await pubkeyId(device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // Código de emparejamiento ALEATORIO: se muestra y NO se envía. La bóveda lo
    // aprende solo cuando un humano lo tipea → aprobar exige TENER esta máquina.
    const code = makePairingCode()
    const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
    const data = { op: 'enroll', intent: 'join', dpub: device.publickey, encPub: enc?.encPublickey || null, token: qr.token || qr.sn, sn: qr.sn, commit, label, ts: Date.now() }
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
    // EL ACTA VIAJA CON EL PAPEL, y hace falta para juzgarlo: el certificado ya no vence
    // por reloj, dice el `seq` del acta con el que se emitió, y quien lo emitió tiene que
    // ser SELLADORA de ese acta. Sin acta no se puede comprobar nada de eso, y entrar a
    // ciegas en un perfil es justo lo que no se hace.
    const acta = res.acta
    if (!acta) throw new Error('the vault did not send its record: cannot check who signed this cert')
    // Y el acta tiene que ser la DEL PERFIL DEL QR. Antes esto se comprobaba mirando que el
    // cert lo firmara `qr.iss`; con varias selladoras el emisor puede ser otra llave del
    // mismo perfil, así que lo que se fija es el perfil, no la llave.
    if (acta.profileId !== qr.iss) throw new Error('the record is from a profile other than the one in the QR')
    const v = await verifyDelegation({
      cert: res.cert, expectedSub: device.publickey,
      actaSeq: acta.seq, sealers: sealersOf(acta),
      ...(expectedScope ? { expectedScope } : {})
    })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)

    return { device, enc: enc ? { publickey: enc.encPublickey, privateJwk: enc.encPrivateJwk } : null, cert: res.cert, iss: qr.iss, proxy: qr.proxy || 'wss://proxy.dotrino.com' }
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
  label = label || ns

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

  const client = await freshClient(proxyUrl, 20000, masterPubkey)
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
export async function fetchSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, timeoutMs = 30000, onPending, onCert, approvalTimeoutMs = APPROVAL_TIMEOUT_MS, publicOnly = false } = {}) {
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

  const client = await freshClient(proxyUrl, 20000, masterPubkey)
  try {
    await identifyAsService(client, device)

    // ¿Nos quedamos atrás? Lo sabemos porque la bóveda manda su acta con cada respuesta y
    // apuntamos su `seq` al guardarla. Si esa acta es más nueva que el papel, puede que el
    // dueño nos haya cambiado los permisos: se pide uno al día siguiente de enterarnos, no
    // por calendario.
  /**
   * Guarda en disco lo que hemos aprendido, SIN pisar lo demás.
   *
   * `saved` se lee una vez al entrar, así que hay que actualizarlo en memoria además de
   * escribirlo: si no, la segunda escritura parte de la foto vieja y deshace la primera.
   * Eso pasó — renovar guardaba el papel nuevo y acto seguido apuntar el acta lo pisaba con
   * el viejo, que ya estaba revocado. Al siguiente arranque: «unauthorized: revoked».
   */
  const recordar = (patch) => {
    if (!saved) return
    saved = { ...saved, ...patch }
    if (dir) { try { writeServiceIdentity(dir, saved) } catch (_) {} }
  }
  /**
   * Hasta qué acta hemos visto. Dispara la renovación la próxima vez, y desde que hay
   * replicadores es además el freno anti-rollback (`verifyResponder`).
   *
   * SOLO SUBE. Antes escribía cualquier `seq` que llegara, también uno MENOR: bastaba que
   * alguien contestara con un acta vieja para que el pin bajara y dejara de proteger de
   * ahí en adelante. Un pin que retrocede no es un pin — se llama `maxSeq` en el diseño
   * justo por esto (`acta-de-perfil.md` §2.3).
   */
  const anotarActa = (acta) => {
    if (typeof acta?.seq !== 'number') return
    if (typeof saved?.actaSeq === 'number' && acta.seq <= saved.actaSeq) return
    // Y QUIÉNES REPARTEN. Sale del acta, que llega firmada en cada respuesta, así que no
    // hay una lista que mantener a mano ni un `.env` que se olvide: darle `replica` a un
    // aparato basta para que sus servicios sepan preguntarle cuando la bóveda no esté.
    const replicas = (acta.members || []).filter((m) => memberCan(acta, m.pub, 'replica')).map((m) => m.pub)
    recordar({ actaSeq: acta.seq, replicas })
  }

    // DOS MOTIVOS PARA PEDIR PAPEL NUEVO:
    //   · el nuestro es del MODELO VIEJO (lleva `exp` y no `seq`). Ese hay que cambiarlo sí
    //     o sí: se acepta por el repliegue de migración, pero muere en su fecha y con él el
    //     servicio. Sin esta rama la migración no terminaba nunca — el disparador comparaba
    //     `seq` contra `seq`, y un papel viejo no tiene ninguno, así que no saltaba jamás.
    //   · o el acta que hemos visto va por delante del papel: el dueño cambió permisos.
    const legado = !!cert && typeof cert.seq !== 'number'
    const atrasado = typeof saved?.actaSeq === 'number' && typeof cert?.seq === 'number' && saved.actaSeq > cert.seq
    const renovar = legado || atrasado

    // RENOVAR YA NO ES UNA TAREA DE CALENDARIO. El papel no vence: lo único que obliga a
    // pedir otro es que la bóveda diga que el nuestro se quedó atrás respecto del acta, y
    // eso lo contesta ella cuando lo pide (`acta-vieja`). Aquí se intenta una vez y no se
    // insiste: si falla, se sigue con el papel que hay — que probablemente valga.
    if (renovar) {
      try {
        const data = { op: 'renew', publickey: device.publickey, ts: Date.now() }
        const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
        const pending = waitForMsg(client, (p) => p.type === MSG.RENEWED || p.type === MSG.ERROR, 15000)
        client.sendByPubkey(masterPubkey, { type: MSG.RENEW, data, signature, cert })
        const res = await pending
        if (res.type === MSG.RENEWED && res.cert?.sub === device.publickey) {
          cert = res.cert
          recordar({ cert })
          // QUIEN NO PASA `dir` GUARDA ÉL. Un servicio que lleva su identidad en su propio
          // archivo (`link.json`) y nos pasa el enlace a mano no tiene `saved`, así que
          // `recordar` no escribe nada: sin esto renovaba en cada arranque y volvía a
          // empezar, y su papel del modelo viejo no se cambiaba NUNCA.
          try { onCert?.(cert) } catch (_) {}
        }
      } catch (_) { /* la renovación no bloquea el fetch */ }
    }

    const eph = await makeEphemeralKey()
    // `publicOnly` VIAJA FIRMADO (va dentro de `data`), así que nadie lo puede quitar ni
    // poner por el camino. Quien decide qué se manda es la bóveda; esto solo es la petición.
    const data = { op: 'secrets', ns, ek: eph.ek, publickey: device.publickey, ts: Date.now(), ...(publicOnly ? { publicOnly: true } : {}) }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    // A QUIÉN SE LE PREGUNTA: primero a la bóveda, y si no contesta, a los REPLICADORES
    // que el acta nombraba la última vez que la vimos (`docs/replicas.md` §8: «el servicio
    // lleva una lista de bóvedas y las prueba en orden»).
    //
    // Sin esto, un replicador no servía absolutamente para nada: el mensaje se mandaba a
    // la llave de la bóveda y, con la bóveda apagada, no llegaba a ninguna parte. Lo
    // destapó el smoke con las dos máquinas encendidas y la bóveda muerta, que es
    // exactamente el caso que un replicador existe para cubrir.
    //
    // La bóveda va PRIMERO siempre: un replicador solo puede estar igual de al día o menos.
    const destinos = [masterPubkey, ...(saved?.replicas || []).filter((k) => k !== masterPubkey)]
    // El plazo se reparte: no tiene sentido esperar el timeout entero a una bóveda apagada
    // y quedarse sin tiempo para preguntarle a quien sí está.
    const porDestino = Math.max(4000, Math.round(timeoutMs / destinos.length))
    let res = null
    let ultimo = null
    for (const destino of destinos) {
      const pending = waitForMsg(client, (p) => p.type === MSG.SECRETS_RESULT || p.type === MSG.ERROR, porDestino)
      client.sendByPubkey(destino, { type: MSG.SECRETS, data, signature, cert })
      try { res = await pending; break } catch (e) { ultimo = e }
    }
    if (!res) throw ultimo || new Error('nobody answered: neither the vault nor any replica')
    if (res.type === MSG.ERROR) throw new Error(res.error)

    // CAJÓN CON APROBACIÓN: la bóveda contesta «pendiente» (firmado) y la respuesta de
    // verdad llega cuando el aparato que aprueba firme — por esta misma conexión, que
    // sigue identificada. Se espera lo que dura el pedido; denegado o vencido es error.
    if (res.body?.op === 'secrets.pending' && res.body.ns === ns) {
      await verifyResponder({ body: res.body, seal: res.seal, acta: res.acta, masterPubkey, knownSeq: saved?.actaSeq ?? null })
      anotarActa(res.acta)
      try { onPending?.({ id: res.body.id, ns, exp: res.body.exp }) } catch (_) {}
      const until = typeof res.body.exp === 'number' ? Math.max(5000, res.body.exp - Date.now() + 5000) : approvalTimeoutMs
      res = await waitForMsg(client, (p) => (p.type === MSG.SECRETS_RESULT && p.body?.op === 'secrets.result') || p.type === MSG.ERROR, Math.min(until, approvalTimeoutMs))
        .catch((e) => { throw new Error(/timeout/.test(e.message) ? 'approval: nobody approved the request in time' : e.message) })
      if (res.type === MSG.ERROR) throw new Error(res.error)
    }

    // AUTENTICIDAD: la firma NO es de la maestra. El acta dice qué llave vale para esto
    // (`sealPub`, buscada por `seq`), que es la misma regla que ya gobierna los sobres.
    // La maestra solo sella el acta y reenvuelve; servir no es cosa suya, y por eso puede
    // quedarse cerrada.
    const body = res.body
    if (!body || body.op !== 'secrets.result' || body.ns !== ns) throw new Error('malformed secrets reply')
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) throw new Error('stale secrets reply')

    // Se abre ANTES de comprobar la firma, y no es un descuido: el sobre de fuera va
    // sellado a la efímera que acabamos de estrenar, así que abrirlo no prueba nada ni
    // confía en nadie — solo saca el acta con la que SÍ se comprueba. Nada de lo que hay
    // dentro se usa hasta después de verificar.
    const payload = await openSealed({ privateKey: eph.privateKey, enc: body.enc })
    await verifyResponder({ body, seal: res.seal, acta: payload?.acta, masterPubkey, knownSeq: saved?.actaSeq ?? null })
    anotarActa(payload?.acta)

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
 * Abre un bundle sellado: saca la CEK de la envoltura dirigida a este aparato y
 * descifra con ella las variables privadas. Las públicas vienen en claro.
 *
 * Un fallo al abrir es un ERROR DURO, nunca un salto a lo del scope ni un valor
 * omitido: silenciarlo convertiría una rotación mal sellada en «el servicio sigue
 * con el valor viejo y nadie se entera», que es el peor modo de fallo de todo esto.
 */
/**
 * ¿QUIÉN CONTESTÓ, Y PUEDE? La misma regla que gobierna los sobres, aplicada al
 * transporte: **el acta dice qué llave firma qué**.
 *
 * La maestra no entra aquí. Sus dos trabajos son sellar el acta y reenvolver los sobres
 * de todos los aparatos; servir una petición no es ninguno de los dos, así que exigir su
 * firma la obligaba a estar despierta todo el tiempo — y de paso hacía imposible que
 * sirviera nadie más.
 *
 * Lo que se comprueba, en orden:
 *   1. el acta que llega va firmada por la maestra que este agente lleva pineada desde
 *      que se enroló (o por la que aquella nombró al traspasar);
 *   2. la firma del cuerpo cuadra con la llave de sellado que ESA acta nombra para el
 *      `seq` con el que se firmó.
 *
 * Sin el paso 1 el paso 2 no vale nada: un acta cualquiera nombraría la llave que
 * quisiera.
 */
/**
 * ¿QUIÉN PUEDE HABERME CONTESTADO ESTO? Hay dos respuestas legítimas y una condición.
 *
 *   · **La bóveda.** Firma con la llave de sellado que el acta nombra para ese `seq`. Es
 *     el camino de siempre y no cambia.
 *   · **Un REPLICADOR** (`seal.by`). No tiene esa llave —no tiene maestra— así que firma
 *     con la suya de aparato, y lo que la autoriza es que el acta le reconozca `replica`.
 *     Reparte lo que la bóveda ya selló: los sobres de dentro se siguen comprobando contra
 *     la llave de sellado (`makeSealCheck`), así que un replicador no puede inventarse
 *     contenido, solo entregarlo.
 *
 * LA CONDICIÓN, y es la que cierra el agujero que `replicas.md` §6.1 llama «construir el
 * ataque»: **un replicador solo le contesta a quien YA conoce la cuenta.** Un replicador
 * atrasado presenta un acta donde un aparato revocado sigue siendo miembro; contra eso, a
 * quien tiene `maxSeq` pineado lo protege el pin, pero a un aparato que llega nuevo no hay
 * con qué compararlo. Así que sin pin no se le cree: que conteste la bóveda.
 *
 * El precio, dicho en voz alta: un aparato nuevo necesita la bóveda encendida una vez. El
 * oráculo de frescura (§2.4.2 del acta) es lo que quitaría ese precio; mientras no exista,
 * esto es el freno, y es un freno de verdad y no un aviso.
 *
 * @param {number|null} [knownSeq] El `seq` más alto que este agente ya vio de esta cuenta.
 *   `null`/ausente = no conoce la cuenta, y entonces un replicador no vale.
 */
export async function verifyResponder ({ body, seal, acta, masterPubkey, knownSeq = null }) {
  if (!seal?.sig) {
    throw new Error('the reply carries no sealing signature: this vault is too old to serve (update it)')
  }
  if (!acta) throw new Error('the reply carries no record: cannot tell which key was allowed to sign it')
  if (acta.sealedBy !== masterPubkey) {
    throw new Error('the record was not sealed by the master this agent knows: refusing the reply')
  }
  if (!(await verifyActa({ acta })).ok) throw new Error('the record does not verify')

  // NUNCA HACIA ATRÁS. Vale para los dos caminos: un acta con `seq` menor del que ya
  // vimos es un rollback, venga de donde venga.
  if (typeof knownSeq === 'number' && typeof acta.seq === 'number' && acta.seq < knownSeq) {
    throw Object.assign(
      new Error(`the record went backwards (#${acta.seq} after #${knownSeq}): refusing the reply`),
      { code: 'stale-record' })
  }

  if (seal.by) {
    if (typeof knownSeq !== 'number') {
      throw Object.assign(
        new Error('a replica answered, and this device has never seen the account: ask the vault itself the first time'),
        { code: 'replica-unknown-account' })
    }
    if (!memberCan(acta, seal.by, 'replica')) {
      throw new Error('the reply comes from a device the record does not allow to serve as a replica')
    }
    if (!(await verifyDeviceSig({ publickey: seal.by, data: body, signature: seal.sig }))) {
      throw new Error('the replica signature does not check out')
    }
    return
  }

  if (typeof seal.seq !== 'number') {
    throw new Error('the reply carries no sealing signature: this vault is too old to serve (update it)')
  }
  const pub = sealKeyAt(acta, seal.seq)
  if (!pub) throw new Error(`the record names no sealing key for #${seal.seq}`)
  if (!(await verifyDeviceSig({ publickey: pub, data: body, signature: seal.sig }))) {
    throw new Error('the reply signature does not check out against the key the record names')
  }
}

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
    // UNA PÚBLICA SE ABRE IGUAL QUE UNA PRIVADA (dueño, 2026-09-02). Aquí había un atajo
    // —`if (e.pub) out[key] = e.v`— porque una pública se guardaba en claro. Ya no: `pub`
    // solo dice si se despacha sin aprobación, y el sobre es el mismo. Dejar el atajo
    // sería aceptar un valor en claro dentro de un paquete que se supone todo sellado, o
    // sea la puerta para colar uno.
    if (typeof e.v === 'string' && !e.e) {
      // TAMPOCO SE ARREGLA ESPERANDO, igual que `no-wrapping`. El valor está guardado en
      // claro en la bóveda, de antes de que todo viajara sellado, y solo vuelve a
      // escribirlo quien puede abrirla. Reintentar no lo sella: solo vuelve a timbrar.
      throw Object.assign(
        new Error(`${key} arrived in the clear: since 2026-09-02 every variable travels sealed` +
          ` — rewrite it in the vault (dotrino-vault unlock, then secret set ${ident?.ns || '<ns>'} ${key} …) or remove it`),
        { code: 'plaintext-var' })
    }
    // `owner` dice de qué cajón salió, y `gen` con qué llave de ese cajón se abre.
    const cual = String(e.owner || '').startsWith('dev:') ? 'dev' : 'ns'
    const gen = e.gen ?? e.e?.gen ?? 0
    await comprobarFirma(e.owner, key, gen, e.e, e.seal)
    const cek = await cekDe(cual, gen)
    if (!cek) {
      // NO ES UN TROPIEZO: ES UN ESTADO QUE HAY QUE ARREGLAR EN LA BÓVEDA.
      //
      // Un aparato que entra después de escrita una variable no tiene envoltura de ella, y
      // NO PUEDE tenerla: envolver exige abrir la llave del cajón, y eso solo pasa cuando
      // el dueño abre la bóveda. Reintentar no la crea. Lleva `code` porque el mensaje lo
      // empareja otra capa y una frase no es un contrato (ver `dotrino-error-strings`).
      throw Object.assign(
        new Error(`no key to open ${key}: this device has no wrapping in its drawer — open the vault (dotrino-vault unlock) so it hands it the key`),
        { code: 'no-wrapping' })
    }
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
      // POR EL PROXIO, A PROPÓSITO, aunque la bóveda esté en esta misma máquina.
      //
      // El mostrador local es pregunta y respuesta. Los avisos que la bóveda manda POR SU
      // CUENTA —«tu configuración cambió», una revocación— salen por el proxio, así que un
      // oyente conectado solo en local no se enteraría de nada y se quedaría corriendo con
      // la configuración vieja para siempre. Lo cazaron los E2E de avisos.
      //
      // El atajo local es para el ARRANQUE, que es donde se nota la latencia: pedir las
      // claves una vez. Escuchar es otra cosa y necesita que la bóveda pueda alcanzarte.
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
/**
 * ¿ESTE FALLO SE ARREGLA SOLO ESPERANDO? Si no, reintentar es peor que rendirse.
 *
 * Lo NO transitorio exige que alguien haga algo: falta de enrolamiento, cert revocado o
 * vencido, scope equivocado → re-emparejar. Que te lo DENIEGUEN tampoco se reintenta: fue
 * una decisión, no un tropiezo.
 *
 * Y no tener ENVOLTURA en el cajón (`no-wrapping`) es el que costó una tarde. La bóveda
 * pedía aprobación, el teléfono timbraba, el dueño aprobaba, la bóveda contestaba un bundle
 * que este aparato no podía abrir, y el agente volvía a pedir — así que el teléfono
 * timbraba otra vez. «Sigo aprobando y aprobando», textual. Ninguna aprobación iba a crear
 * esa envoltura: envolver exige abrir la llave del cajón, o sea ABRIR la bóveda.
 *
 * Se decide por `e.code` donde lo hay: emparejar un mensaje por su texto se rompe en
 * silencio en cuanto alguien lo reescribe (ver `dotrino-error-strings`).
 */
const FINAL_CODES = new Set([
  'no-wrapping',   // falta la envoltura, y solo la fabrica el dueño abriendo la bóveda
  'plaintext-var'  // el valor está en claro en la bóveda: hay que volver a escribirlo
])

export function isFinal (e) {
  if (FINAL_CODES.has(e?.code)) return true
  return /not enrolled|invalid ns|unauthorized: (revoked|expired|scope|cn|untrusted-issuer|cert-device-mismatch|denied)/.test(e?.message || '')
}

/**
 * CUÁNTO ESPERAR ANTES DE VOLVER A PEDIR, y por qué no siempre es el backoff.
 *
 * Un cajón con aprobación hace sonar el teléfono en CADA petición. Con el reintento a
 * cinco segundos, un fallo posterior a la aprobación volvía a pedir enseguida y el dueño
 * veía dos avisos del mismo cajón: aprobaba el primero para nada. La regla es que un
 * reintento no llegue nunca antes de que venza el pedido que ya está sonando.
 *
 * La otra mitad importa igual: si el intento se pasó la ventana entera esperando a que
 * alguien aprobara, no se le suma otra ventana — ahí ya no hay nada sonando, y hacerle
 * esperar cinco minutos más sería un cuelgue.
 *
 * @param {number} backoffMs  lo que tocaría por el backoff normal
 * @param {number} rangAt     cuándo timbró este intento (0 si no timbró)
 * @param {number} approvalTimeoutMs  lo que dura un pedido de aprobación
 * @param {number} now
 */
export function retryDelay (backoffMs, rangAt, approvalTimeoutMs = APPROVAL_TIMEOUT_MS, now = Date.now()) {
  if (!rangAt) return backoffMs
  return Math.max(backoffMs, approvalTimeoutMs - (now - rangAt))
}

export async function waitForSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, retryMs = 5000, maxRetryMs = 60000, approvalTimeoutMs = APPROVAL_TIMEOUT_MS, onRetry, onPending, onCert, publicOnly = false } = {}) {
  let backoff = retryMs
  let rangAt = 0   // cuándo timbró ESTE intento; 0 = no hubo aprobación de por medio
  const notePending = (info) => { rangAt = Date.now(); onPending?.(info) }
  for (;;) {
    try {
      return await fetchSecrets({ dir, ns, proxyUrl, masterPubkey, device, cert, enc, approvalTimeoutMs, onPending: notePending, onCert, publicOnly })
    } catch (e) {
      if (isFinal(e)) throw e
      const wait = retryDelay(backoff, rangAt, approvalTimeoutMs)
      rangAt = 0
      try { onRetry?.(e, wait) } catch (_) {}
      await new Promise((r) => setTimeout(r, wait))
      backoff = Math.min(maxRetryMs, Math.round(backoff * 1.6))
    }
  }
}
