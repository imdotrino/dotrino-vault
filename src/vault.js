/**
 * dotrino-vault — núcleo del certificador personal (daemon headless).
 *
 * Custodia la clave MAESTRA del usuario (vía `@dotrino/identity`) y la expone como
 * CA propia. EMPAREJAMIENTO ENDURECIDO (ver docs/pairing-protocol.md): el token de
 * 5 min ya NO es autoridad suficiente — para obtener un cert el dispositivo debe
 * (1) PROBAR posesión de su llave D firmando el ENROLL, y (2) el dueño debe APROBAR
 * en el PC tras comparar un SAS (código de 6 dígitos) entre las dos pantallas. La
 * maestra solo firma el cert DESPUÉS de esa aprobación humana.
 *
 * Toda la cripto es de `@dotrino/identity`. Este módulo solo orquesta.
 */
import fs from 'node:fs'
import path from 'node:path'
import { Identity } from '@dotrino/identity/node'
import { verifyChain, pubkeyId, verifyDeviceSig } from '@dotrino/identity/capabilities'
import * as Acta from '@dotrino/identity/acta'
import { createEnrollDesk, deviceIdOf, DEVICE_TTL_MS } from '../lib/src/enroll.js'
import { createAdminDesk } from '../lib/src/admin.js'
import { shouldNotifyRevoked } from '../lib/src/revocation.js'
import { createTransport, masterPubkeyOf } from './transport.js'
import { openStore } from './store.js'
import { openThreadStore, STORE_READ_METHODS, PROFILE_EDIT_METHODS } from './threadStore.js'
import { openSecretsStore, assertVar } from './secretsStore.js'
import { makeSealer } from './sealer.js'
import { seal } from '../lib/src/sealed.js'
import { dataDir, ensureDir } from './paths.js'
import { atRestFor, machineKey, migrateFile } from './atrest.js'
import { MSG, SCOPE, secretsScope, isValidSecretsNs } from './protocol.js'

/**
 * Abre UN perfil del vault (una maestra, un dir, una conexión al proxy). El
 * daemon multi-perfil (`manager.js`) levanta uno de estos por perfil.
 *
 * @param {Object} [opts]
 * @param {string} [opts.dir]        Dir de datos de ESTE perfil.
 * @param {() => boolean} [opts.isLocked]  Candado del perfil (contraseña opcional).
 *   Solo bloquea EDITAR el perfil (`profileSet`): firmar/leer y el resto del store
 *   siguen sirviendo a los dispositivos enrolados aunque esté bloqueado.
 */
export async function startVault ({ dir = dataDir(), proxyUrl, log = console.log, onEnrollChallenge, isLocked = () => false, forAdoption = false, onAdopted } = {}) {
  ensureDir(dir)
  // CIFRADO EN REPOSO ligado a esta máquina: ningún archivo del dir queda en claro, así
  // que copiarlos a otro equipo no sirve de nada. La identidad se migra AQUÍ (verificando
  // antes de reemplazar); el resto —`vault.json`, `threads.json`, `secrets.json`— lo hace
  // su propio store al abrirse. No protege contra quien ya tiene ESTA
  // máquina (puede leer el mismo material); es subir el listón, no una imposibilidad.
  // La migración verifica antes de reemplazar: si algo falla, el original queda intacto.
  try {
    const r = migrateFile(path.join(dir, 'identity.json'), machineKey(dir))
    if (r === 'migrado') log('[vault] identity encrypted at rest (bound to this machine)')
  } catch (e) { log('[vault] could not encrypt the identity at rest:', e.message) }
  const identity = await Identity.connect({ dir, atRest: atRestFor(dir) })
  if (!identity.me?.publickey) await identity.setMyNickname('')
  // CAMINO A: este perfil nació para adoptar la cuenta de un aparato. La identidad se crea
  // igual (su llave es la que entrará como miembro), pero se marca para que `joinProfile`
  // acepte cambiar su acta recién nacida por la que traiga el dispositivo. Sin la marca,
  // adoptar sería pisar una cuenta con datos y se rechaza — que es lo correcto por defecto.
  if (forAdoption) {
    try { await identity.prepareForAdoption() } catch (e) { log('[vault] could not prepare the profile for adoption:', e.message) }
  }

  const store = openStore(dir)
  const threads = openThreadStore(dir)
  const secrets = openSecretsStore(dir, { sealer: makeSealer(), defaultKey: () => new Uint8Array(machineKey(dir)) })
  const master = await masterPubkeyOf(identity)
  const fp = (await pubkeyId(master)).slice(0, 16)

  const { client } = await createTransport({ identity, dir, url: proxyUrl })

  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set(revoked.map((r) => r.nonce))
  }

  const reply = (to, obj) => {
    try { client.send(to, obj) } catch (e) { log('[vault] could not reply:', e.message) }
  }

  // FRESCURA anti-replay: toda petición firmada debe traer `data.ts` dentro de una
  // ventana de ±5 min (mismo criterio que el identify del proxy). Sin esto, un
  // relay malicioso podía REPRODUCIR mensajes firmados viejos (re-pedir firmas,
  // abrir renovaciones…) durante toda la vida del cert.
  // AUDITORÍA: bitácora de actividad de seguridad (activity.log, JSONL) — qué
  // dispositivo firmó/renovó/enroló y qué se rechazó. `dotrino-vault activity`
  // la muestra. Sin contenido de payloads (privacidad): solo op, dispositivo, hora.
  const activityFile = path.join(dir, 'activity.log')
  const audit = (op, info = {}) => {
    try {
      fs.appendFileSync(activityFile, JSON.stringify({ ts: Date.now(), op, ...info }) + '\n')
      // rotación simple: si pasa de ~1 MB, conservar la última mitad
      const st = fs.statSync(activityFile)
      if (st.size > 1024 * 1024) {
        const lines = fs.readFileSync(activityFile, 'utf8').split('\n')
        fs.writeFileSync(activityFile, lines.slice(Math.floor(lines.length / 2)).join('\n'))
      }
    } catch (_) {}
  }

  const FRESH_WINDOW_MS = 5 * 60 * 1000
  const isFresh = (d) => typeof d?.ts === 'number' && Math.abs(Date.now() - d.ts) <= FRESH_WINDOW_MS
  const staleReply = (from) => reply(from, { type: MSG.ERROR, error: 'stale request: ts outside the ±5 min window (possible replay, or the device clock is off)' })

  // --- ENROLL / aprobación / revocación: núcleo COMPARTIDO (lib/src/enroll.js) ---
  // El mismo módulo lo usan «este dispositivo es bóveda» (@dotrino/vault) y la copia
  // vendorizada del iframe de identidad: un solo sitio donde vive el flujo, y por lo
  // tanto un solo sitio donde se comprueba el código antes de firmar el cert.
  const desk = createEnrollDesk({
    identity,
    iss: master,
    proxy: client.url,
    send: (to, obj) => reply(to, obj),
    sendByPubkey: (pub, obj) => client.sendByPubkey(pub, obj),
    audit,
    log,
    // Camino A: lo que esta bóveda le manda al aparato para entrar en SU acta. La llave de
    // cifrado es lo que le permite leer el contenido de la cuenta que va a custodiar; sin
    // ella entraría mandando una cuenta que no puede abrir.
    encPub: identity.me?.encryptionPubkey || null,
    vaultLabel: 'bóveda',
    // Lo único que lleva el QR corto: una CITA del proxio, que es un código de 6
    // caracteres de un solo uso y con minutos de vida. Antes iba la dirección de
    // la conexión, que eran 4 caracteres; hoy esa dirección es una instancia de
    // 24 (para poder rutearla entre proxios) y no cabe cómoda en un QR ni
    // conviene dejarla impresa en algo que circula. Se pide una por
    // emparejamiento: si el proxio es viejo y no las conoce, se cae solo a la
    // invitación larga, que sigue funcionando.
    connToken: async () => {
      try { return (await client.requestPairingCode())?.code || null }
      catch (_) { return null }
    },
    onAdopted: (info) => { try { onAdopted?.(info) } catch (_) {} },
    // Se va el aparato, se van SUS variables. Guardarlas sería configuración de una llave
    // que ya no entra, y volvería a la vida sola el día que se enrole otro aparato con esa
    // misma llave. Va aquí porque a quitar se entra por dos puertas (el PC y la consola
    // remota) y las dos pasan por `desk.revokeDevice`.
    onDeviceRemoved: (sub) => {
      try {
        const n = secrets.forgetDevice(sub)
        if (n) log(`[vault] dropped ${n} variable(s) of the removed device`)
      } catch (e) { log('[vault] could not drop the device variables:', e.message) }
    },
    defaultScope: [SCOPE.READ],
    onChallenge ({ deviceId, scope }) {
      log(`\n[vault] Un dispositivo quiere conectarse:`)
      log(`        deviceId: ${deviceId}`)
      log(`        Ingresa el código que MUESTRA el dispositivo:`)
      log(`          dotrino-vault approve <código>    (o rechaza: dotrino-vault reject ${deviceId})\n`)
      try { onEnrollChallenge?.({ deviceId, scope }) } catch (_) {}
    }
  })

  // --- handleSign / handleGet: idénticos (verifyChain de la cadena D←maestra) ---
  async function handleSign (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'sign', reason: 'stale' }); return staleReply(from) }
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.SIGN, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'sign')
    const toSign = p.data?.payload
    if (toSign == null) return reply(from, { type: MSG.ERROR, error: 'data.payload required' })
    const { signature, publickey } = await identity.signData(toSign)
    audit('sign', { device: await deviceIdOf(chk.device) })
    reply(from, { type: MSG.SIGNED, signature, publickey, device: chk.device })
  }

  async function handleGet (from, p) {
    if (!isFresh(p.data)) return staleReply(from)
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.READ, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'get')
    const id = p.data?.id || 'root'
    reply(from, { type: MSG.DATA, id, node: store.getNode(id) })
  }

  // Store de hilos+aperturas (Fase 3): escrituras requieren vault:store; lecturas
  // aceptan vault:store o vault:read. Cada op va firmada por D + cert (cadena D←maestra).
  async function handleStore (from, p) {
    const d = p.data
    // `Object.hasOwn` y no `threads.methods[d.method]`: con la comprobación laxa,
    // `method: 'toString'` (o cualquier miembro heredado de Object) pasaba el filtro y
    // se llamaba como si fuera del store.
    if (!d || typeof d.method !== 'string' || !Object.hasOwn(threads.methods, d.method)) {
      return reply(from, { type: MSG.ERROR, error: 'store: invalid method' })
    }
    if (!isFresh(d)) return staleReply(from)
    // CANDADO del perfil (contraseña opcional): solo frena EDITAR el perfil. Un
    // dispositivo enrolado puede seguir firmando, leyendo y guardando contenido;
    // lo que no puede es reescribir quién sos mientras el perfil está bloqueado.
    if (PROFILE_EDIT_METHODS.has(d.method) && isLocked()) {
      audit('rejected', { what: 'store', method: d.method, reason: 'locked' })
      return reply(from, { type: MSG.ERROR, error: 'profile locked: unlock it on the vault machine (dotrino-vault unlock) to edit it' })
    }
    const revoked = await revocationSet()
    let chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.STORE, trustedIssuer: master, revoked })
    if (!chk.ok && STORE_READ_METHODS.has(d.method)) {
      chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.READ, trustedIssuer: master, revoked })
    }
    if (!chk.ok) return denyChain(from, chk, p, 'store')
    try {
      // CIFRADO de punta a punta con la clave de contenido del perfil: el proxy transporta
      // pero no ve nada de lo que el usuario guarda. Si el dispositivo mandó `enc`, se abre
      // aquí con la clave de la bóveda (que también es miembro) y la respuesta vuelve igual.
      let args = d.args || {}
      let cek = null
      if (d.enc) {
        cek = await identity.contentKey?.().catch(() => null)
        if (!cek) return reply(from, { type: MSG.ERROR, error: 'store: this vault does not hold the profile content key' })
        args = JSON.parse(await identity.openContent(d.enc))
      }
      const result = await threads.methods[d.method](args)
      // Que un aparato ESCRIBA en tu bóveda queda anotado. Antes solo se auditaba el
      // rechazo, así que la bitácora contaba quién entró pero no qué hizo después.
      // Solo la operación y el aparato: nunca el contenido (`activity` es un registro
      // de seguridad, no una copia de lo que guardas).
      if (!STORE_READ_METHODS.has(d.method)) {
        audit('store', { device: await deviceIdOf(chk.device), method: d.method })
      }
      if (cek) {
        const enc = await identity.sealContent(JSON.stringify(result ?? null))
        return reply(from, { type: MSG.STORE_RESULT, method: d.method, result: { __enc: enc } })
      }
      reply(from, { type: MSG.STORE_RESULT, method: d.method, result })
    } catch (e) { reply(from, { type: MSG.ERROR, error: e.message }) }
  }

  // Lista (solo lectura) de dispositivos enrolados, para un panel en el navegador.
  // Cualquier cert válido tuyo puede verla; REVOCAR sigue siendo solo desde el PC.
  /**
   * Un aparato REVOCADO que vuelve a aparecer: se le reemite el `vault.revoked` FIRMADO
   * para que se entere y se auto-borre.
   *
   * Un «unauthorized: revoked» suelto no basta y no debe bastar: no va firmado, así que
   * el dispositivo tiene prohibido borrar nada con él (si no, cualquiera destruiría datos
   * ajenos con un mensaje). Lo único que puede borrar es un aviso firmado por la maestra
   * — y hasta ahora el daemon no lo reemitía nunca. Si el aparato estaba apagado cuando lo
   * quitaste, no se enteraba jamás: seguía enseñando el perfil como si nada.
   */
  async function notifyIfRevoked (pubkey, nonce = null, certIss = null, reason = 'revoked') {
    if (typeof pubkey !== 'string') return
    try {
      const record = (await identity.profileActa?.().catch(() => null))?.acta || null
      // Sin acta (bóveda anterior al acta) hay que mirar las delegaciones, que es lo único
      // que queda. OJO con dónde se buscan: desde identity 0.42 `issued` es «lo que HOY
      // sirve para entrar», así que los retirados NO están ahí — viven en `revokedCerts`.
      let knownRevoked = false
      let fallbackNonce = null
      if (!record) {
        const delegations = await identity.listDelegations()
        const revoked = await revocationSet()
        const candidates = [...(delegations.revokedCerts || []), ...(delegations.issued || [])]
        const theirs = candidates.filter((x) => x.sub === pubkey && (x.revokedAt || revoked.has(x.nonce)))
        knownRevoked = theirs.length > 0
        fallbackNonce = theirs[0]?.nonce || null
      }
      if (!shouldNotifyRevoked({ reason, pubkey, master, certIss, members: record?.members || null, knownRevoked })) return
      // El aviso nombra el certificado que el aparato ACABA de presentar: es el que tiene
      // en la mano, y es contra ese contra el que comprueba antes de borrarse.
      await desk.emitRevoke(pubkey, nonce || fallbackNonce)
      audit('revoke.notified', { device: await deviceIdOf(pubkey).catch(() => null), reason })
    } catch (e) { log('[vault] could not re-emit the revocation:', e.message) }
  }

  /**
   * Rechaza una petición y, si el aparato ya no es del perfil, SE LO DICE con el aviso
   * firmado — sea cual sea la operación que estuviera intentando.
   *
   * Un dispositivo que fue tuyo tiene que poder llegar hasta aquí precisamente para que se
   * le pueda mandar a paseo: es el único mensaje que le borra la cuenta, porque es el único
   * que va firmado por la maestra (un «unauthorized» suelto no borra nada y no debe: sería
   * destruir datos ajenos con un mensaje, el wipe-DoS de `docs/pairing-protocol.md §2.3`).
   *
   * Antes esto solo pasaba en `devices` —la pantalla de dispositivos— y solo si el papel
   * estaba REVOCADO. Un aparato quitado que estuviera guardando notas nunca preguntaba por
   * ahí, y uno al que simplemente se le venció el certificado no entraba en el caso: los
   * dos se quedaban enseñando la cuenta indefinidamente.
   */
  async function denyChain (from, chk, p, what) {
    await notifyIfRevoked(p.data?.publickey, p.cert?.nonce || null, p.cert?.iss || null, chk.reason)
    if (what) audit('rejected', { what, reason: chk.reason })
    return reply(from, { type: MSG.ERROR, error: 'unauthorized: ' + chk.reason })
  }

  /**
   * «¿SIGO SIENDO DE ESTA CASA?» — la única pregunta que se atiende SIN certificado.
   *
   * Existe por el aparato que se quedó sin papel: no puede firmar, ni leer, ni renovar, y
   * —esto es lo grave— tampoco tenía forma de enterarse de que lo echaron, porque todo lo
   * demás exige el certificado que ya no tiene. Se quedaba enseñando para siempre una
   * cuenta que ya no era suya. Va firmada con la llave del propio aparato, que es
   * exactamente lo que el acta nombra, así que decir quién pregunta no necesita más.
   *
   * La respuesta es sí o no, y nada más: al que sigue dentro no se le manda el acta —no la
   * pidió, y contarle el perfil entero a quien no trae papel es dar de más—. Al que ya no
   * está se le manda el aviso FIRMADO de expulsión, que es lo único que le borra la cuenta.
   * Que un desconocido pregunte no cuesta nada: lo que se le puede contestar es un aviso a
   * nombre de SU propia llave, que no le sirve contra nadie más (`verifyRevoke` exige que
   * el aviso nombre al aparato que lo recibe).
   */
  async function handleCheck (from, p) {
    if (!isFresh(p?.data)) return staleReply(from)
    const pub = p.data.publickey
    if (typeof pub !== 'string') return reply(from, { type: MSG.ERROR, error: 'unauthorized: shape' })
    if (!(await verifyDeviceSig({ publickey: pub, data: p.data, signature: p.signature }))) {
      return reply(from, { type: MSG.ERROR, error: 'unauthorized: bad-signature' })
    }
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    const inside = (record?.members || []).some((m) => m?.pub === pub)
    audit('check', { device: await deviceIdOf(pub).catch(() => null), in: inside })
    if (inside) return reply(from, { type: MSG.CHECKED, in: true })
    await notifyIfRevoked(pub, null, null, 'revoked')
    reply(from, { type: MSG.CHECKED, in: false })
  }

  async function handleDevices (from, p) {
    if (!isFresh(p.data)) return staleReply(from)
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, trustedIssuer: master, revoked: await revocationSet() })
    if (!chk.ok) return denyChain(from, chk, p, null)
    const { issued, revoked } = await identity.listDelegations()
    // El acta viaja con la lista: así cada dispositivo se entera de los cambios de
    // política (quién manda, quién puede qué) sin un canal aparte.
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    // Si el dispositivo estuvo apagado y viene con un `seq` viejo, se le manda la CADENA
    // que falta (ventana de retención, §1.3) para que compruebe el encadenamiento en vez
    // de tragarse un salto a ciegas. Si se salió de la ventana, llega vacía y toca
    // re-emparejar — que es justo lo que debe pasar.
    // El `.catch()` de antes NO protegía de nada: si `actaHistory` no existe, el
    // TypeError es SÍNCRONO y salta antes de que haya promesa que encadenar. Pasó: el
    // método vivía en el núcleo pero no en el envoltorio de Node, así que esta línea
    // tiraba toda la respuesta y ningún navegador ya emparejado —que manda `sinceSeq`
    // siempre— volvía a sincronizar su acta. Un try/catch de verdad, y opcional.
    let chain = null
    if (typeof p.data?.sinceSeq === 'number') {
      try { chain = (await identity.actaHistory?.({ sinceSeq: p.data.sinceSeq }))?.chain || null }
      catch (e) { log('[vault] could not build the record chain:', e.message) }
    }
    // `sub` (pubkey completa) va incluida: es la DIRECCIÓN de cada dispositivo en el
    // proxy → permite a las apps AUTODESCUBRIR tus máquinas (p. ej. la terminal
    // lista tus agentes sin pegar nada). Solo la ve quien presenta un cert tuyo válido.
    const devices = await Promise.all(issued.map(async (x) => ({
      deviceId: x.sub ? await deviceIdOf(x.sub) : null, sub: x.sub || null, label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
    })))
    reply(from, { type: MSG.DEVICES_RESULT, devices, revoked, acta: record, chain })
  }

  // RENOVACIÓN automática: un dispositivo con cert VIGENTE y no revocado pide un
  // cert fresco (misma sub-clave y scope) sin QR ni aprobación — sigue siendo el
  // mismo dispositivo enrolado, solo extiende la ventana. Un cert vencido o
  // revocado NO puede renovarse (ahí sí toca re-emparejar con aprobación).
  const RENEW_TTL_MS = 30 * 24 * 60 * 60 * 1000
  async function handleRenew (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'renew', reason: 'stale' }); return staleReply(from) }
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, trustedIssuer: master, revoked: await revocationSet() })
    if (!chk.ok) return denyChain(from, chk, p, 'renew')
    // Reusar el label del cert original (si sigue registrado en delegations).
    const { issued } = await identity.listDelegations()
    const prev = (issued || []).find((x) => x.nonce === p.cert.nonce)
    // EL SCOPE SALE DEL ACTA, no del cert viejo. El acta es la política (lo que el dueño
    // decidió con `caps`); el cert es su reflejo, y solo dura 30 días para poder cambiar.
    // Copiar `p.cert.scope` congelaba la política en el momento del emparejamiento: dar
    // `administra` no llegaba nunca al cert (la consola remota no podía funcionar) y
    // QUITARLO tampoco surtía efecto hasta que el cert caducara, hasta un mes después.
    // Si el miembro ya no está en el acta, no se renueva nada: lo echaron.
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    let scope = p.cert.scope
    if (record) {
      scope = Acta.memberScopes(record, p.cert.sub)
      if (!scope.length) {
        audit('rejected', { what: 'renew', device: await deviceIdOf(p.cert.sub), reason: 'not-a-member' })
        return reply(from, { type: MSG.ERROR, error: 'unauthorized: the record no longer lists this device' })
      }
    }
    const { cert } = await identity.signDelegation(p.cert.sub, scope, { ttlMs: RENEW_TTL_MS, label: prev?.label || '' })
    audit('renew', { device: await deviceIdOf(p.cert.sub), label: prev?.label || '', scope })
    log(`[vault] cert renewed for ${await deviceIdOf(p.cert.sub)} (30 days)`)
    reply(from, { type: MSG.RENEWED, cert })
  }

  // SECRETOS de servicios: un servicio enrolado (cert `vault:secrets:<ns>`)
  // pide el bundle de su namespace — el del SCOPE (que comparten todos los
  // aparatos que sirven ese ns) con el SUYO PROPIO encima (`secretsStore.js`).
  // Lo suyo se indexa por la llave que firma esta misma petición, así que no hay
  // manera de pedir lo de otro aparato. La respuesta va SELLADA a la llave ECDH
  // efímera `ek` que vino en el sobre firmado (el proxy transporta pero no
  // puede leer los valores) y el cuerpo va FIRMADO por la maestra (el
  // servicio verifica contra su iss pineada — un relay no puede inyectar
  // secretos falsos). Replay inerte: cada petición usa una ek nueva.
  //   data: { op:'secrets', ns, ek, publickey, ts }
  async function handleSecrets (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'secrets', reason: 'stale' }); return staleReply(from) }
    const ns = p.data?.ns
    if (!isValidSecretsNs(ns)) return reply(from, { type: MSG.ERROR, error: 'secrets: invalid namespace' })
    if (typeof p.data?.ek !== 'string') return reply(from, { type: MSG.ERROR, error: 'secrets: missing ek (requester ephemeral key)' })
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: secretsScope(ns), trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'secrets')
    // FRONTERA DEL CN (acta): además del scope del cert, el acta tiene que decir que este
    // miembro es el servicio `ns`. Así el límite no depende solo de qué cert se emitió: la
    // llave del proxy no ve nada que no sea del proxy, y está escrito donde se puede comprobar.
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (record && !Acta.memberCanReadSecrets(record, chk.device, ns)) {
      audit('rejected', { what: 'secrets', ns, reason: 'cn' })
      return reply(from, { type: MSG.ERROR, error: `unauthorized: cn — the record does not recognise this member as the "${ns}" service` })
    }
    let enc
    try {
      // Mientras el archivo siga en v3 el cable NO cambia: se mandan los valores como
      // siempre. Solo tras la migración viajan sobres, y entonces quien los abre es el
      // agente con su llave. Así el despliegue del daemon se deshace con un reinicio,
      // porque hasta el primer desbloqueo no ha cambiado nada de lo que ve nadie.
      const b = secrets.bundleFor(ns, chk.device)
      const payload = b.legacy
        ? { secrets: Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v])) }
        : { sealed: b }
      enc = await seal({ ek: p.data.ek, payload })
    } catch (e) {
      return reply(from, { type: MSG.ERROR, error: 'secrets: invalid ek' })
    }
    const body = { op: 'secrets.result', ns, enc, ts: Date.now() }
    const { signature } = await identity.signData(body)
    audit('secrets', { device: await deviceIdOf(chk.device), ns })
    reply(from, { type: MSG.SECRETS_RESULT, body, signature })
  }

  client.on('message', async (from, payload) => {
    if (!payload || typeof payload !== 'object') return
    try {
      if (payload.type === MSG.HELLO) return desk.handleHello(from, payload)
      if (payload.type === MSG.ENROLL) return await desk.handleEnroll(from, payload)
      if (payload.type === MSG.ACTA_SEALED) return await desk.handleActaSealed(from, payload)
      if (payload.type === MSG.SIGN) return await handleSign(from, payload)
      if (payload.type === MSG.GET) return await handleGet(from, payload)
      if (payload.type === MSG.STORE) return await handleStore(from, payload)
      if (payload.type === MSG.CHECK) return await handleCheck(from, payload)
      if (payload.type === MSG.DEVICES) return await handleDevices(from, payload)
      if (payload.type === MSG.RENEW) return await handleRenew(from, payload)
      if (payload.type === MSG.SECRETS) return await handleSecrets(from, payload)
      if (payload.type === MSG.ADMIN) return await handleAdmin(from, payload)
      if (payload.type === MSG.RENOUNCE) return await handleRenounce(from, payload)
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: e.message })
    }
  })

  log(`[vault] listo · id ${fp} · ${store.getTree().children.length} nodos`)

  // ----- API local (CLI/UI de control) -----
  // Emparejar / aprobar / rechazar / revocar viven en el núcleo compartido (`desk`).

  // ----- AVISO DE CAMBIO a los agentes del ns -----
  //
  // Guardar un secreto no sirve de nada si quien lo usa no se entera. La bóveda
  // avisa (sin mandar valores: solo «el ns cambió») y el agente decide — el
  // estándar es que SALGA y lo levante su supervisor, para leer todo fresco y,
  // sobre todo, para que el valor viejo deje de existir en su memoria.
  //
  // AGRUPADO a propósito: cargar cinco valores seguidos con `secret set` son cinco
  // escrituras, pero un solo cambio de configuración. Sin esta ventana serían cinco
  // reinicios en cadena, y el agente se pasaría la carga entera reiniciándose.
  // La variable de entorno va en inglés (CONVENCIONES §8.1); nadie la tenía puesta.
  const NOTICE_GROUP_MS = Number(process.env.DOTRINO_VAULT_NOTICE_MS) || 3000
  const pendingNotices = new Map()   // clave (ns | 'dev:'+pub) → timer

  async function notifyNsChange (ns) {
    let targets = []
    try {
      const { issued } = await identity.listDelegations()
      const revokedNonces = await revocationSet()
      const scope = secretsScope(ns)
      // Los agentes de ESE ns y nadie más: el aviso dice qué namespace cambió, así
      // que mandárselo a otro sería filtrarle que existe.
      //
      // Y UNO POR LLAVE, no uno por delegación: renovar el cert emite una
      // delegación nueva para la MISMA sub-clave, así que un agente que lleve
      // tiempo enrolado aparece varias veces y recibiría el aviso repetido.
      const seen = new Set()
      targets = (issued || []).filter((x) => {
        if (!x.sub || revokedNonces.has(x.nonce) || !(x.scope || []).includes(scope)) return false
        if (seen.has(x.sub)) return false
        seen.add(x.sub)
        return true
      })
    } catch (e) { return log('[vault] could not list who to notify:', e.message) }
    if (!targets.length) return

    const body = { op: 'secrets.changed', ns, ts: Date.now() }
    const { signature } = await identity.signData(body)
    for (const d of targets) {
      try { client.sendByPubkey(d.sub, { type: MSG.SECRETS_CHANGED, body, signature }) } catch (_) {}
    }
    audit('secrets.changed', { ns, notified: targets.length })
    log(`[vault] config for "${ns}" changed: notified ${targets.length} agent(s)`)
  }

  /**
   * Cambió una variable de UN aparato: el aviso va solo a ese aparato. El mensaje dice
   * qué NAMESPACE cambió (es lo que el agente sabe leer), así que hace falta su `cn`; un
   * miembro sin `cn` no es un servicio y no lee variables, de modo que no hay a quién
   * avisar y no se manda nada.
   */
  async function notifyDeviceChange (pub) {
    let cn = null
    try {
      const record = (await identity.profileActa?.().catch(() => null))?.acta
      cn = (record?.members || []).find((m) => m.pub === pub)?.cn || null
    } catch (e) { return log('[vault] could not look up who to notify:', e.message) }
    if (!cn) return
    const body = { op: 'secrets.changed', ns: cn, ts: Date.now() }
    const { signature } = await identity.signData(body)
    try { client.sendByPubkey(pub, { type: MSG.SECRETS_CHANGED, body, signature }) } catch (_) {}
    const device = await deviceIdOf(pub).catch(() => null)
    audit('secrets.changed', { ns: cn, device, notified: 1 })
    log(`[vault] config for device ${device} ("${cn}") changed: notified it`)
  }

  /**
   * Un cambio de configuración, un aviso: escrituras seguidas se agrupan en la misma
   * ventana. La CLAVE distingue los dos cajones (`<ns>` y `dev:<pub>`) para que tocar
   * lo de un aparato no cancele el aviso pendiente de todo su namespace.
   */
  function scheduleNotice (ns) { schedule(ns, () => notifyNsChange(ns)) }
  function scheduleDeviceNotice (pub) { schedule('dev:' + pub, () => notifyDeviceChange(pub)) }

  function schedule (key, fn) {
    clearTimeout(pendingNotices.get(key))
    const t = setTimeout(() => {
      pendingNotices.delete(key)
      fn().catch((e) => log('[vault] change notice failed:', e.message))
    }, NOTICE_GROUP_MS)
    t.unref?.()
    pendingNotices.set(key, t)
  }

  // --- CONSOLA REMOTA (docs/consola-remota.md) ---------------------------------
  // Un dispositivo con cert `vault:admin` puede ADMITIR y EXPULSAR miembros sin venir
  // al PC. No puede cambiar permisos, traspasar el mando, conceder `admin` ni tocar los
  // secretos: esas operaciones no existen como mensaje, a propósito. Así un aparato con
  // `admin` robado hace daño acotado y reversible (se le revoca) en vez de poder dejar
  // al dueño fuera de su propia cuenta, que no tiene vuelta atrás.
  /** Últimas entradas de la bitácora (JSONL), de la más reciente hacia atrás. */
  function readActivity (limit = 100) {
    try {
      return fs.readFileSync(activityFile, 'utf8').split('\n').filter(Boolean).slice(-limit)
        .map((l) => { try { return JSON.parse(l) } catch (_) { return null } }).filter(Boolean).reverse()
    } catch (_) { return [] }
  }

  /**
   * Avisa a TODOS los miembros de que el perfil cambió, firmado por la maestra. Sin
   * esto, administrar a distancia sería invisible para el resto de los dispositivos —
   * y esa visibilidad es lo que hace DETECTABLE a un admin comprometido. Va por
   * `sendByPubkey`, así que al que está apagado le llega cuando encienda (cola 24 h).
   */
  async function notifyMembers (ev, info = {}) {
    try {
      const body = { ev, ...info, ts: Date.now() }
      const { signature } = await identity.signData(body)
      const { issued } = await identity.listDelegations()
      // UNO POR LLAVE, no uno por delegación: renovar emite una delegación nueva para la
      // MISMA sub-clave, así que un aparato que lleve tiempo enrolado aparece varias veces
      // y recibía el mismo aviso repetido —una vez por renovación acumulada—. Mismo
      // cuidado que en `notifyNsChange`.
      const seen = new Set()
      for (const d of issued || []) {
        if (!d.sub || seen.has(d.sub)) continue
        seen.add(d.sub)
        try { client.sendByPubkey(d.sub, { type: MSG.ADMIN_EVENT, body, signature }) } catch (_) {}
      }
    } catch (e) { log('[vault] could not notify members of the change:', e.message) }
  }

  /**
   * MOSTRADOR DE VARIABLES para la consola remota (`lib/src/admin.js` enruta; la política
   * y la cripto viven aquí, que es donde están la clave y el disco).
   *
   * Dos reglas, y son toda la frontera:
   *
   *   1. **El valor de una PRIVADA no sale de esta máquina.** Ni para un aparato tuyo con
   *      `admin`. Lo que viaja de una privada es su nombre y que es privada — con eso se
   *      le puede poner un valor nuevo a ciegas, que es lo que hace falta para rotarla.
   *   2. **Lo que sale, sale CIFRADO** con la clave de contenido del perfil: el proxy
   *      transporta el sobre y no ve nada. Igual que el contenido del usuario (`store`).
   */
  const varsDesk = {
    async list () {
      // `listSecrets`/`listDeviceSecrets` ya traen el valor de las públicas y solo de esas:
      // la frontera se decide en un sitio, y lo mismo ve el dueño en su terminal que aquí.
      // Se sella la lista ENTERA, no solo los valores: el proxy tampoco tiene por qué
      // aprender cómo se llaman tus variables ni qué servicios corres.
      return {
        enc: await identity.sealContent(JSON.stringify({
          ns: listSecrets(), dev: await listDeviceSecrets()
        }))
      }
    },
    async set ({ ns, pub, key, enc, public: isPublic }) {
      const payload = JSON.parse(await identity.openContent(enc))
      const value = payload?.value
      if (typeof value !== 'string' || !value) throw new Error('var.set: the sealed envelope must carry a non-empty value')
      if (ns) await setSecret(ns, key, value, isPublic)
      else await setDeviceSecret(pub, key, value, isPublic)
      return { ok: true, key }
    },
    /**
     * VARIAS DE UNA VEZ, y por eso existe: cada guardado suelto hace que la bóveda avise
     * al servicio de que su configuración cambió, y el servicio SALE para releerla entera
     * (`watchEnv`). Guardadas de una en una, quien administra a distancia reiniciaba el
     * servicio una vez por variable, y las primeras veces arrancaba con la configuración a
     * medio poner. Juntas: un guardado, un aviso, un reinicio.
     *
     * Los NOMBRES también viajan dentro del sobre —no solo los valores—: el proxy
     * transporta y no tiene por qué aprender cómo se llama la configuración de un servicio.
     */
    async setMany ({ ns, pub, enc, public: isPublic }) {
      const payload = JSON.parse(await identity.openContent(enc))
      const items = payload?.items
      if (!Array.isArray(items) || !items.length) throw new Error('var.setMany: the sealed envelope must carry the variables')
      // Borrar no se delega (`docs/consola-remota.md` §2): un aparato robado no puede
      // dejar sin configuración a un servicio. Así que aquí solo entran valores nuevos.
      /** @type {Array<{op:'set', key:string, value:string, public?:boolean}>} */
      const list = items.map((it) => ({
        op: /** @type {'set'} */ ('set'),
        key: it?.key,
        value: it?.value,
        ...(typeof it?.public === 'boolean' ? { public: it.public } : (isPublic === undefined ? {} : { public: isPublic }))
      }))
      const keys = ns ? applySecrets(ns, list) : await applyDeviceSecrets(pub, list)
      return { ok: true, keys }
    }
  }

  const admin = createAdminDesk({
    desk,
    deviceIdOf,
    ttlMs: DEVICE_TTL_MS,
    audit,
    notify: notifyMembers,
    readActivity,
    vars: varsDesk,
    // CERT ∩ ACTA, igual que los secretos con su CN. El cert dice qué se emitió; el acta,
    // qué decidió el dueño AHORA. Sin el segundo, `caps <ID> -administra` no surtía efecto
    // hasta que el cert caducara: quitarle la administración a un aparato que ya no es de
    // fiar exigía revocarlo entero. Con el cruce, deja de administrar en el acto.
    verify: async ({ data, signature, cert }) => {
      const chk = await verifyChain({
        data, signature, cert,
        expectedScope: SCOPE.ADMIN, trustedIssuer: master, revoked: await revocationSet()
      })
      // Quitarse a UNO MISMO desde la consola remota entra por aquí: la segunda petición
      // que mande el aparato ya llega con el certificado retirado. Que se entere con el
      // aviso firmado, en vez de con un error suelto que no puede borrar nada.
      if (!chk.ok) {
        await notifyIfRevoked(data?.publickey, cert?.nonce || null, cert?.iss || null, chk.reason)
        return chk
      }
      const record = (await identity.profileActa?.().catch(() => null))?.acta
      if (record && !Acta.memberCan(record, chk.device, 'admin')) return { ok: false, reason: 'acta' }
      return chk
    }
  })

  /**
   * RENUNCIA: un miembro se quita capacidades a sí mismo y la bóveda la SELLA en el acta.
   *
   * NO se pide certificado, y es a propósito: el registro va firmado por el propio miembro
   * y solo puede QUITAR, así que honrarlo no puede hacer daño — y exigir un cert válido
   * dejaría fuera justo el caso que la justifica (un aparato que ya no es de fiar, o cuyo
   * cert caducó). Sin esto la renuncia se quedaba en el dispositivo: la bóveda seguía
   * teniendo escrito que podía firmar y le seguía aceptando peticiones.
   */
  async function handleRenounce (from, p) {
    const record = p?.data?.record || p?.record
    if (!record || typeof record !== 'object') return reply(from, { type: MSG.ERROR, error: 'renounce: record required' })
    if (!(await Acta.verifyRenounce(record).catch(() => false))) {
      audit('rejected', { what: 'renounce', reason: 'signature' })
      return reply(from, { type: MSG.ERROR, error: 'renounce: the signature is not the member own' })
    }
    try {
      const r = await identity.absorbRenounce(record)
      const device = await deviceIdOf(record.member).catch(() => null)
      audit('renounce', { device, caps: record.caps })
      log(`[vault] ${device} renounced: ${(record.caps || []).join(', ')}`)
      await notifyMembers('renounce', { deviceId: device, caps: record.caps })
      reply(from, { type: MSG.RENOUNCE_RESULT, ok: true, seq: r?.seq ?? null })
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: 'renounce: ' + e.message })
    }
  }

  async function handleAdmin (from, p) {
    // La frescura se comprueba aquí (es del transporte, igual que en el resto de
    // handlers); el resto de la regla vive en el módulo puro.
    if (!isFresh(p.data)) return staleReply(from)
    const r = await admin.handle(p.data, { signature: p.signature, cert: p.cert })
    if (!r.ok) return reply(from, { type: MSG.ERROR, error: r.error })
    reply(from, { type: MSG.ADMIN_RESULT, op: p.data.op, result: r.result })
  }

  // API local de secretos (CLI/UI del dueño; audita cada cambio). `isPublic` es opcional:
  // sin decir nada, la variable conserva su visibilidad (y una nueva nace privada).
  /**
   * La llave con la que se abre la copia maestra.
   *
   * Con contraseña, la deriva quien llama y llega aquí por operación. **Sin
   * contraseña se cae a la llave de la máquina**, que es exactamente la protección
   * que había antes de todo esto: el disco sigue cifrado, pero su material vive en
   * ese mismo disco, así que una copia del disco lo abre.
   *
   * Es un default deliberado —un perfil sin contraseña tiene que seguir funcionando—
   * pero NO es equivalente, y por eso la consola lo dice en voz alta (§2.3 del
   * diseño). Prometer una protección que no está puesta es peor que no tenerla.
   */
  const adminKeyOr = (adminKey) => adminKey || new Uint8Array(machineKey(dir))

  // `adminKey` es la llave derivada de la contraseña del perfil, y va POR OPERACIÓN: se
  // usa para sellar y se suelta. Solo hace falta para escribir una privada — servir,
  // listar y borrar no la piden (ver `secretsStore.js`).
  /**
   * Los miembros que deben poder abrir un cajón: los SERVICIOS de ese namespace
   * (miembros del acta con ese `cn`). La bóveda NO entra en la lista — envolverle la
   * CEK a ella misma sería devolverle la capacidad de leerlo todo, que es justo lo
   * que este diseño quita.
   */
  async function nsMembers (ns) {
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    return (record?.members || []).filter((m) => m.cn === ns)
  }

  /**
   * Sellar no basta: hay que REPARTIR la llave. Tras cada escritura se envuelve la CEK
   * del cajón a sus miembros actuales — si no, el servicio recibe sobres que no puede
   * abrir y se queda reintentando para siempre, sin decir por qué.
   *
   * No avisa de cambio a nadie: el texto cifrado de los valores no se mueve, y avisar
   * reiniciaría a todos los nodos del ns para nada.
   */
  async function spreadKey (owner, members, adminKey) {
    if (secrets.isLegacy()) return null
    const r = await secrets.rewrap(owner, members, adminKey)
    if (r?.sinLlave?.length) {
      log(`[vault] ${owner}: ${r.sinLlave.length} member(s) without an encryption key - they will NOT be able to read their variables`)
      audit('secret.nokey', { owner, count: r.sinLlave.length })
    }
    return r
  }

  async function setSecret (ns, key, value, isPublic, adminKey) {
    await secrets.set(ns, key, value, isPublic, adminKey)
    await spreadKey(`ns:${ns}`, await nsMembers(ns), adminKey)
    audit('secret.set', { ns, key }); scheduleNotice(ns)
  }
  async function deleteSecret (ns, key) { const ok = await secrets.delete(ns, key); if (ok) { audit('secret.rm', { ns, key }); scheduleNotice(ns) } return ok }

  /**
   * CARGAR CONFIGURACIÓN ES UNA TRANSACCIÓN: muchas variables, UN aviso.
   *
   * De una en una, cada `set` es un cambio de configuración para la bóveda, y el agente
   * obedece el primero —sale, lo levanta el supervisor, lee lo que hubiera en ese
   * instante— mientras el dueño sigue tecleando. El resultado es un servicio corriendo
   * con media configuración, y encima con el arranque a medio hacer. La ventana de
   * agrupado (`NOTICE_GROUP_MS`) tapa el caso de un script, no el de una persona
   * escribiendo con quince segundos entre variable y variable.
   *
   * Así que la carga en grupo llega hasta aquí entera: se valida TODO primero, se
   * escribe en un solo guardado y sale UN aviso al final. Las visibilidades no entran:
   * no cambian lo que el servicio lee y por eso nunca avisaron.
   *
   * @param {string} ns
   * @param {Array<{op:'set'|'rm', key:string, value?:string, public?:boolean}>} items
   * @returns {string[]} las claves que efectivamente cambiaron (un `rm` de lo que no
   *   estaba no cambia nada, y no tiene por qué reiniciar a nadie).
   */
  async function applySecrets (ns, items, adminKey) {
    const list = assertItems(items)
    const changed = []
    await secrets.batch(async () => {
      for (const it of list) {
        if (it.op === 'rm') {
          if (await secrets.delete(ns, it.key)) { audit('secret.rm', { ns, key: it.key }); changed.push(it.key) }
        } else {
          await secrets.set(ns, it.key, it.value, it.public, adminKey)
          audit('secret.set', { ns, key: it.key })
          changed.push(it.key)
        }
      }
    })
    if (changed.length) {
      await spreadKey(`ns:${ns}`, await nsMembers(ns), adminKey)
      scheduleNotice(ns)
    }
    return changed
  }

  /** Lo mismo para el cajón de UN aparato (el aviso va solo a él). */
  async function applyDeviceSecrets (pub, items, adminKey) {
    const list = assertItems(items)
    const m = await requireService(pub)
    const changed = []
    await secrets.batch(async () => {
      for (const it of list) {
        if (it.op === 'rm') {
          if (await secrets.deleteDevice(pub, it.key)) changed.push(it.key)
        } else {
          await secrets.setDevice(pub, it.key, it.value, it.public, adminKey)
          changed.push(it.key)
        }
      }
    })
    if (changed.length) {
      await spreadKey(`dev:${pub}`, [m].filter(Boolean), adminKey)
      const device = await deviceIdOf(pub).catch(() => null)
      for (const it of list) {
        if (!changed.includes(it.key)) continue
        audit(it.op === 'rm' ? 'secret.rm' : 'secret.set', { device, ns: m?.cn || null, key: it.key, scope: 'device' })
      }
      scheduleDeviceNotice(pub)
    }
    return changed
  }

  /**
   * Todo o nada: si una variable del grupo no vale, no se escribe NINGUNA. Media
   * configuración cargada es peor que ninguna — el servicio arranca con ella.
   */
  function assertItems (items) {
    if (!Array.isArray(items) || !items.length) throw new Error('batch: no items')
    for (const it of items) {
      if (!it || (it.op !== 'set' && it.op !== 'rm')) throw new Error('batch: each item must be a set or an rm')
      if (it.op === 'rm') { if (!it.key) throw new Error('batch: rm needs a key') } else assertVar(it.key, it.value)
    }
    return items
  }
  /**
   * Los nombres, y el VALOR de las públicas. Pública quiere decir «este valor puede salir
   * de esta máquina»: taparlo justo aquí —en la máquina donde vive, delante de su dueño—
   * era lo único que la marca no significaba. La consola remota ya las enseña.
   */
  function listSecrets () {
    const out = {}
    for (const [ns, keys] of Object.entries(secrets.list())) {
      const values = secrets.publicOf(ns)
      out[ns] = keys.map((k) => (k.public ? { ...k, value: values[k.key] } : k))
    }
    return out
  }
  /** Cambiar SOLO quién puede ver el valor (no toca el valor ni avisa: el servicio lee lo mismo). */
  async function setSecretVisibility (ns, key, isPublic, adminKey) {
    const ok = await secrets.setVisibility(ns, key, isPublic, adminKey)
    if (ok) audit('secret.visibility', { ns, key, public: !!isPublic })
    return ok
  }

  /**
   * El bundle de un ns ABIERTO, para diagnosticar y para las pruebas. No lo usa el
   * camino de servir —ahí los sobres salen cerrados y los abre el agente—, y por eso
   * este sí pide poder abrir la copia maestra.
   */
  async function openSecrets (ns, devicePub = null, adminKey) {
    return secrets.openBundle(ns, devicePub, adminKey)
  }

  /** El miembro del acta con esa llave, o `null` (también si la bóveda todavía no tiene acta). */
  async function memberOf (pub) {
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record) return null
    return (record.members || []).find((m) => m.pub === pub) || null
  }

  /**
   * Variables de UN aparato. Se exige que sea un SERVICIO del acta (miembro con `cn`) porque
   * es el único que las lee: guardárselas a un teléfono sería configuración muerta, escrita
   * donde nadie la va a buscar el día que no funcione. Si la bóveda es anterior al acta no
   * hay contra qué comprobarlo y se acepta.
   */
  async function requireService (pub) {
    const m = await memberOf(pub)
    if (!m) {
      const record = (await identity.profileActa?.().catch(() => null))?.acta
      if (record) throw new Error('device: it is not a member of this profile')
      return null
    }
    if (!m.cn) throw new Error('device: it is not a service (only services read variables); pair it with `pair --service <ns>`')
    return m
  }

  async function setDeviceSecret (pub, key, value, isPublic, adminKey) {
    const m = await requireService(pub)
    await secrets.setDevice(pub, key, value, isPublic, adminKey)
    await spreadKey(`dev:${pub}`, [await memberOf(pub)].filter(Boolean), adminKey)
    audit('secret.set', { device: await deviceIdOf(pub).catch(() => null), ns: m?.cn || null, key, scope: 'device' })
    scheduleDeviceNotice(pub)
  }

  async function deleteDeviceSecret (pub, key) {
    const m = await memberOf(pub)
    const ok = await secrets.deleteDevice(pub, key)
    if (ok) {
      audit('secret.rm', { device: await deviceIdOf(pub).catch(() => null), ns: m?.cn || null, key, scope: 'device' })
      scheduleDeviceNotice(pub)
    }
    return ok
  }

  async function setDeviceSecretVisibility (pub, key, isPublic, adminKey) {
    const ok = await secrets.setDeviceVisibility(pub, key, isPublic, adminKey)
    if (ok) audit('secret.visibility', { device: await deviceIdOf(pub).catch(() => null), key, public: !!isPublic, scope: 'device' })
    return ok
  }

  /**
   * Las variables por aparato —nombres, y el valor de las PÚBLICAS, igual que `listSecrets`—
   * con quién es cada aparato pegado: una llave suelta no se puede administrar. `orphan`
   * marca las que quedaron de una llave que ya no está en el acta.
   */
  async function listDeviceSecrets () {
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    const members = record?.members || []
    const out = []
    for (const [pub, keys] of Object.entries(secrets.listDevices())) {
      const m = members.find((x) => x.pub === pub) || null
      const values = secrets.publicOfDevice(pub)
      out.push({
        pub,
        id: m?.id || await deviceIdOf(pub).catch(() => null),
        label: m?.label || '',
        cn: m?.cn || null,
        keys: keys.map((k) => (k.public ? { ...k, value: values[k.key] } : k)),
        orphan: !!members.length && !m
      })
    }
    return out
  }

  return {
    identity, client, store, threads, secrets, master, fingerprint: fp,
    startPairing: desk.startPairing,
    stopPairing: desk.stopPairing,
    listPending: desk.listPending,
    // Aprobar desde el PC avisa igual que aprobar a distancia: el resto de tus
    // dispositivos se entera de que entró alguien, venga de donde venga.
    approveDevice: async (code, adminKey) => {
      const r = await desk.approve(code)
      // Un servicio que ENTRA a un namespace que ya tiene variables necesita su
      // envoltura de la CEK, o recibirá sobres que no puede abrir y se quedará
      // reintentando en silencio. Se reparte aquí, que es por donde pasan las dos
      // puertas de aprobar (el PC y la consola remota), y no en `enroll.js`, que es
      // el archivo vendorizado en el iframe de identidad.
      const m = r?.cert?.sub ? await memberOf(r.cert.sub) : null
      if (m?.cn) await spreadKey(`ns:${m.cn}`, await nsMembers(m.cn), adminKey).catch((e) => log('[vault] could not hand the key to the new service:', e.message))
      await notifyMembers('enrolled', { deviceId: r?.deviceId || null, by: 'pc' })
      return r
    },
    rejectDevice: (deviceId) => desk.reject(deviceId),
    // El mostrador que atiende a la consola remota. Se expone para poder probar la
    // frontera de verdad (que el valor de una privada no salga ni dentro del sobre).
    vars: varsDesk,
    setSecret, deleteSecret, listSecrets, setSecretVisibility, openSecrets,
    setDeviceSecret, deleteDeviceSecret, listDeviceSecrets, setDeviceSecretVisibility,
    applySecrets, applyDeviceSecrets,
    listDevices: () => identity.listDelegations(),
    // Acta del perfil (quién es del perfil y qué puede cada uno): lo que muestran
    // `dotrino-vault members` y la consola de vault.dotrino.com.
    profileMembers: () => identity.profileMembers(),
    // ¿Es ESTA bóveda la que sella el acta? Lo usa el freno de borrado (D12).
    isMaster: () => identity.isMaster(),
    setCaps: async (pub, caps) => {
      const r = await identity.setCaps(pub, caps)
      audit('caps', { device: await deviceIdOf(pub).catch(() => null), caps })
      await notifyMembers('caps', { deviceId: await deviceIdOf(pub).catch(() => null), caps })
      return r
    },
    // Renombrar un dispositivo: es un nombre para el humano (no toca permisos ni llaves),
    // pero pasa por el acta y se avisa, para que el cambio no sea invisible en el resto.
    setLabel: async (pub, label) => {
      const r = await identity.setLabel(pub, label)
      const device = await deviceIdOf(pub).catch(() => null)
      audit('label', { device, label: r?.label ?? label })
      await notifyMembers('label', { deviceId: device, label: r?.label ?? label })
      return r
    },
    // QUITAR EL DISPOSITIVO. Se identifica por su llave (`sub`), no por un `nonce`: un
    // aparato puede tener varios certificados y retirar uno no lo echaba de la bóveda.
    // Se sigue aceptando `{ nonce }` para no romper una consola vieja en vuelo.
    revokeDevice: async (target) => {
      const sub = typeof target === 'object' && target ? target.sub : null
      if (!sub) {
        const nonce = typeof target === 'string' ? target : target?.nonce
        const r = await desk.revoke(nonce)
        await notifyMembers('revoked', { certNonce: nonce, by: 'pc' })
        return r
      }
      const r = await desk.revokeDevice(sub)
      audit('revoke-device', { device: await deviceIdOf(sub).catch(() => null), certs: r?.nonces?.length ?? null })
      await notifyMembers('revoked', { deviceId: await deviceIdOf(sub).catch(() => null), by: 'pc' })
      return r
    },
    close () {
      for (const t of pendingNotices.values()) clearTimeout(t)
      pendingNotices.clear()
      try { client.close() } catch (_) {} identity.destroy()
    }
  }
}
