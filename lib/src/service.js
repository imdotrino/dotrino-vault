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
    throw new Error('este entorno no tiene WebSocket global: usa Node ≥22')
  }
}


/**
 * La respuesta al `hello` va firmada y con el `sn` DENTRO de lo firmado. Comprobarlo
 * ata la respuesta a ESTA sesión: no vale la de otro emparejamiento ni la de otra
 * bóveda. Ojo con lo que NO prueba: cualquiera puede firmar con una llave suya, así
 * que esto no dice que sea TU bóveda — eso lo dice el código de 6 dígitos, que solo
 * aprende la bóveda donde tú lo tecleas.
 */
async function verificarHola (p, sn) {
  const b = p?.body
  if (!b?.iss || b.sn !== sn) throw new Error('la bóveda contestó a otro emparejamiento')
  if (!(await verifyDeviceSig({ publickey: b.iss, data: b, signature: p.signature }))) {
    throw new Error('la respuesta de la bóveda no está bien firmada')
  }
  // El modo también viene aquí, y aquí viene FIRMADO por la bóveda. Se comprueba
  // de nuevo aunque ya se haya mirado el del QR: en la forma corta el QR es un
  // código que pasó por manos ajenas, y esta es la primera vez que la bóveda
  // dice de su puño y letra qué se propone hacer.
  rechazarAdopcion(b.m)
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
function rechazarAdopcion (modo) {
  if (modo !== 'adopt') return
  throw new Error(
    'esta invitación se abrió para ADOPTAR la cuenta del aparato, y un agente no transfiere su identidad: ' +
    'la suya se la cede el vault. Abre el emparejamiento sin `--adopt` (`dotrino-vault pair --service <ns>`).'
  )
}

/**
 * Canjea la cita del QR y devuelve la instancia a la que apunta.
 *
 * Una cita se quema al usarse y caduca en minutos, así que un error acá casi
 * siempre significa lo mismo para quien lo lee: el código ya se usó o venció, y
 * hay que pedir otro en la bóveda. Se dice así, no con el error crudo.
 */
async function resolverCita (client, code) {
  if (!code) throw new Error('la invitación no trae código de emparejamiento')
  if (typeof client.redeemPairingCode !== 'function') {
    throw new Error('el proxio no soporta códigos de emparejamiento (actualizá @dotrino/proxy-client)')
  }
  const r = await client.redeemPairingCode(code)
  if (!r?.ok || !r.instance) {
    throw new Error(`ese código no sirve: ${r?.error || 'no válido'}. Pedí uno nuevo en la bóveda.`)
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
    timer = setTimeout(() => reject(new Error('timeout conectando al proxy')), connectTimeoutMs)
  })
  try {
    await Promise.race([client.connect(), timeout])
  } catch (e) {
    try { client.close() } catch (_) {}
    // El 'error' de transporte del cliente puede llegar como un Event sin
    // `message` → sin esto el operador ve una línea de error vacía.
    const why = e?.message || e?.type || 'error de transporte'
    throw new Error(`no se pudo conectar al proxy ${proxyUrl}: ${why}`)
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
    const t = setTimeout(() => { cleanup(); reject(new Error('timeout esperando respuesta del vault')) }, timeoutMs)
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
    if (!o) throw new Error('eso no parece una invitación del vault (pega la salida de `dotrino-vault pair --service <ns>`)')
    qr = o
  }
  if (!qr?.sn || !(qr.iss || qr.conn)) throw new Error('qr inválido: falta la bóveda o el nonce')
  rechazarAdopcion(qr.m)
  if (!isValidSecretsNs(ns)) throw new Error('ns inválido (usa [a-z0-9-]{1,32}, p.ej. "proxy")')
  if (!dir) throw new Error('falta dir (dónde persistir la identidad del servicio)')
  label = label || 'servicio:' + ns

  // La identidad que va a quedar descartada. Se avisa antes de tocar nada: para
  // el proxy, por ejemplo, esta llave es además su identidad de red, así que
  // reemplazarla le cambia el id de nodo y sus peers dejan de reconocerlo hasta
  // que se re-pineen a mano.
  const anterior = readServiceIdentity(dir)
  let replaced = null
  if (anterior?.device?.publickey) {
    replaced = {
      ns: anterior.ns,
      enrolledAt: anterior.enrolledAt,
      deviceId: (await pubkeyId(anterior.device.publickey)).slice(0, 8).toUpperCase()
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
    const destino = await resolverCita(client, qr.conn)
    const hola = await new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (p?.type === MSG.HELLO_OK) { fin(); verificarHola(p, qr.sn).then(resolve, reject) }
        else if (p?.type === MSG.ERROR) { fin(); reject(new Error(p.error)) }
      })
      const t = setTimeout(() => { fin(); reject(new Error('la bóveda no contestó: ese código pudo caducar')) }, 15000)
      const fin = () => { off(); clearTimeout(t) }
      try { client.send(destino, { type: MSG.HELLO, sn: qr.sn }) } catch (e) { fin(); reject(e) }
    })
    qr = { ...qr, iss: hola.iss, proxy: hola.proxy || qr.proxy }
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
 * @param {(info:{ns:string, ts:number})=>void} opts.onChange
 * @param {(info:{nonce:string})=>void} [opts.onRevoked]  Cert revocado: apagar YA.
 * @param {number} [opts.graceMs=30000]      No obedecer avisos durante los primeros N ms.
 * @param {number} [opts.minIntervalMs=60000] Mínimo entre dos avisos obedecidos.
 * @param {number} [opts.jitterMs=5000]      Espera aleatoria antes de avisar.
 * @param {(m:string)=>void} [opts.log]
 * @returns {Promise<{stop:()=>void}>}
 */
export async function watchSecretsChanges ({
  dir, ns, onChange, onRevoked, graceMs = 30000, minIntervalMs = 60000, jitterMs = 5000, log = () => {}
} = {}) {
  const saved = dir ? readServiceIdentity(dir) : null
  ns = ns || saved?.ns
  if (!saved?.device || !saved?.cert || !saved?.iss || !saved?.proxy) {
    throw new Error('servicio sin enrolar: no hay a quién escuchar')
  }
  const master = saved.iss
  const nacido = Date.now()
  let ultimoTs = 0
  let ultimoObedecido = 0
  const enVuelo = new Set()   // avisos cuya firma se está comprobando ahora mismo
  let parado = false
  let client = null
  let reintento = null

  /**
   * REVOCACIÓN = interruptor de emergencia. Hasta ahora revocar un cert no le
   * quitaba nada a un servicio YA CORRIENDO: seguía operando con los secretos en
   * memoria hasta que alguien se acordara de reiniciarlo (el README decía lo
   * contrario). Teniendo la conexión abierta, el aviso llega y el agente se apaga
   * en el acto — y no vuelve, porque al arrancar `fetchSecrets` recibe
   * «no autorizado: revoked», que no se arregla reintentando.
   *
   * Sin gracia, sin piso y sin jitter, al revés que un cambio de configuración:
   * apagar algo comprometido es justo lo que no debe esperar su turno.
   */
  const atenderRevocacion = async (payload) => {
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

  const atender = async (payload) => {
    if (payload?.type === MSG.REVOKED) return atenderRevocacion(payload)
    if (payload?.type !== MSG.SECRETS_CHANGED) return
    const body = payload.body
    if (!body || body.op !== 'secrets.changed' || body.ns !== ns) return
    if (typeof body.ts !== 'number' || Math.abs(Date.now() - body.ts) > FRESH_WINDOW_MS) {
      return log('[vault] aviso de cambio con fecha fuera de ventana: ignorado')
    }
    if (body.ts <= ultimoTs) return log('[vault] aviso de cambio repetido: ignorado')
    // Dos copias del MISMO aviso pueden llegar a la vez, y comprobar la firma es
    // asíncrono: sin esta marca las dos pasarían el corte de `ultimoTs` antes de
    // que ninguna lo actualizara, y el agente se reiniciaría por partida doble.
    // La marca se pone antes del `await` y el `ultimoTs` DESPUÉS de verificar, para
    // que un aviso falso con fecha lejana no pueda dejar fuera a los de verdad.
    if (enVuelo.has(body.ts)) return
    enVuelo.add(body.ts)
    let valida = false
    try {
      valida = await verifyDeviceSig({ publickey: master, data: body, signature: payload.signature })
    } finally { enVuelo.delete(body.ts) }
    if (!valida) return log('[vault] change notice BADLY SIGNED: ignored (not from your vault)')
    if (body.ts <= ultimoTs) return
    ultimoTs = body.ts

    const ahora = Date.now()
    if (ahora - nacido < graceMs) {
      return log('[vault] change notice right after start: ignored (avoids the restart loop)')
    }
    if (ahora - ultimoObedecido < minIntervalMs) {
      return log('[vault] aviso de cambio demasiado seguido del anterior: ignorado')
    }
    ultimoObedecido = ahora

    const espera = Math.floor(Math.random() * jitterMs)
    log(`[vault] the vault reports config for "${ns}" changed (in ${espera} ms)`)
    setTimeout(() => { if (!parado) { try { onChange?.({ ns, ts: body.ts }) } catch (e) { log('[vault] ' + e.message) } } }, espera)
  }

  const conectar = async () => {
    if (parado) return
    try {
      client = await freshClient(saved.proxy)
      await identifyAsService(client, saved.device)
      client.on('message', (_from, p) => { atender(p).catch(() => {}) })
      // Reconectar solo: si se cae el proxio, el agente deja de ser avisable, y
      // eso es exactamente el momento en que uno querría enterarse de una rotación.
      client.on('disconnected', () => { if (!parado) reintento = setTimeout(conectar, 5000) })
      log('[vault] listening for config changes')
    } catch (e) {
      if (!parado) reintento = setTimeout(conectar, 5000)
    }
  }
  await conectar()

  return {
    stop () {
      parado = true
      clearTimeout(reintento)
      try { client?.close() } catch (_) {}
    }
  }
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
      if (/sin enrolar|ns inválido|no autorizado: (revoked|expired|scope|cn|untrusted-issuer|cert-device-mismatch)/.test(e.message)) throw e
      try { onRetry?.(e, delay) } catch (_) {}
      await new Promise((r) => setTimeout(r, delay))
      delay = Math.min(maxRetryMs, Math.round(delay * 1.6))
    }
  }
}
