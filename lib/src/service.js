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
  makeDeviceKey, signWithDevice, verifyDelegation, verifyDeviceSig,
  makePairingCode, commitCode, pubkeyId
} from '@dotrino/identity/capabilities'
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
export async function enrollService ({ qr, ns, dir, label, onCode, onReplace, approveTimeoutMs = 180000 } = {}) {
  // `parseInvite` y NO `JSON.parse`: el vault no imprime JSON desde hace rato.
  // `dotrino-vault pair --service` emite la URL del QR y el código compacto
  // (`c…`/`t…`, ver invite.js), así que un `JSON.parse` fallaba SIEMPRE con
  // «qr inválido: no es JSON» y el enrolamiento de un servicio era imposible por
  // este camino. Lo tapaba que el único servicio enrolado del ecosistema lo hizo
  // cuando el formato todavía era JSON. `parseInvite` acepta todas las formas,
  // incluida la vieja, así que esto entiende cualquier invitación.
  if (typeof qr === 'string') {
    const o = parseInvite(qr)
    if (!o) throw new Error('that does not look like a vault invitation (paste the output of `dotrino-vault pair --service <ns>`)')
    qr = o
  }
  if (!qr?.sn || !(qr.iss || qr.conn)) throw new Error('invalid qr: missing the vault or the nonce')
  rejectAdoption(qr.m)
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

  const client = await freshClient(qr.proxy || 'wss://proxy.dotrino.com')
  // QR CORTO: se le pregunta a la bóveda quién es, punto a punto, presentando el `sn`.
  if (!qr.iss) {
    // `qr.conn` es una CITA (código de 6 caracteres, un solo uso): hay que
    // canjearla para saber a qué conexión apunta. El canje lo resuelve el proxio
    // que la emitió —lo dice el prefijo del propio código—, así que funciona
    // aunque la bóveda esté en otro proxio de la malla.
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
    const deviceId = (await pubkeyId(device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
    // Código ALEATORIO generado AQUÍ: el vault no lo conoce; solo puede echarlo
    // de vuelta si el dueño lo tipeó (= tiene esta pantalla a la vista).
    const code = makePairingCode()
    // El COMPROMISO del código (nunca el código): la bóveda lo recompone con lo que
    // tipeas y solo entonces firma el cert → aprobar exige haber leído esta pantalla.
    const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
    // `intent: 'join'` EXPLÍCITO. La bóveda lo compara con el modo que abrió y,
    // si falta, asume `join` — pero un agente no debe apoyarse en un default
    // para algo que decide de quién es la cuenta. Yendo dentro de `data`, viaja
    // firmado: nadie en el medio puede convertirlo en una adopción.
    const data = { op: 'enroll', intent: 'join', dpub: device.publickey, token: qr.token || qr.sn, sn: qr.sn, commit, label, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })

    const enrolled = new Promise((resolve, reject) => {
      const off = client.on('message', (_from, p) => {
        if (!p || typeof p !== 'object') return
        if (p.type === MSG.ENROLL_CHALLENGE) {
          const show = onCode || (({ deviceId, code }) => console.log(`[vault-service] device ${deviceId} · approve it on the vault:  dotrino-vault approve ${code}`))
          show({ deviceId, code })
        } else if (p.type === MSG.ENROLLED) { cleanup(); resolve(p) } else if (p.type === MSG.ERROR) { cleanup(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { cleanup(); reject(new Error('timeout waiting for approval on the vault')) }, approveTimeoutMs)
      const cleanup = () => { off(); clearTimeout(t) }
    })
    client.sendByPubkey(qr.iss, { type: MSG.ENROLL, data, signature })
    const res = await enrolled

    // Validación estricta (igual que un dispositivo): cert de la maestra VISTA,
    // para ESTA llave, y el código echado debe ser el nuestro (anti vault falso).
    if (res.code !== code) throw new Error('the vault echoed a code other than the one shown (possible malicious relay)')
    const v = await verifyDelegation({ cert: res.cert, expectedSub: device.publickey, expectedScope: secretsScope(ns) })
    if (!v.ok) throw new Error('invalid cert: ' + v.reason)
    if (res.cert.iss !== qr.iss) throw new Error('cert signed by a master other than the one in the QR')

    // Reemplazo, no acumulación: el archivo se sobrescribe entero y la identidad
    // anterior deja de existir en este agente.
    writeServiceIdentity(dir, { v: 1, ns, iss: qr.iss, proxy: qr.proxy, device, cert: res.cert, enrolledAt: Date.now() })
    return { device, cert: res.cert, iss: qr.iss, replaced }
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
    const res = await pending
    if (res.type === MSG.ERROR) throw new Error(res.error)

    // Autenticidad: el cuerpo viene firmado por la MAESTRA pineada.
    const body = res.body
    if (!body || body.op !== 'secrets.result' || body.ns !== ns) throw new Error('malformed secrets reply')
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) throw new Error('stale secrets reply')
    const ok = await verifyDeviceSig({ publickey: masterPubkey, data: body, signature: res.signature })
    if (!ok) throw new Error('invalid master signature on the secrets reply')

    const payload = await openSealed({ privateKey: eph.privateKey, enc: body.enc })
    if (!payload || typeof payload.secrets !== 'object') throw new Error('malformed secrets envelope')
    return payload.secrets
  } finally { client.close() }
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

  const handleMessage = async (payload) => {
    if (payload?.type === MSG.REVOKED) return handleRevocation(payload)
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
export async function waitForSecrets ({ dir, ns, proxyUrl, masterPubkey, device, cert, retryMs = 5000, maxRetryMs = 60000, onRetry } = {}) {
  let delay = retryMs
  for (;;) {
    try {
      return await fetchSecrets({ dir, ns, proxyUrl, masterPubkey, device, cert })
    } catch (e) {
      // Lo NO transitorio no se arregla reintentando: falta de enrolamiento,
      // cert revocado/vencido o scope equivocado exigen re-emparejar → se corta.
      if (/not enrolled|invalid ns|unauthorized: (revoked|expired|scope|cn|untrusted-issuer|cert-device-mismatch)/.test(e.message)) throw e
      try { onRetry?.(e, delay) } catch (_) {}
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(maxRetryMs, Math.round(delay * 1.6))
    }
  }
}
