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
import { verifyChain, pubkeyId } from '@dotrino/identity/capabilities'
import * as Acta from '@dotrino/identity/acta'
import { createEnrollDesk, deviceIdOf, DEVICE_TTL_MS } from '../lib/src/enroll.js'
import { createAdminDesk } from '../lib/src/admin.js'
import { createTransport, masterPubkeyOf } from './transport.js'
import { openStore } from './store.js'
import { openThreadStore, STORE_READ_METHODS, PROFILE_EDIT_METHODS } from './threadStore.js'
import { openSecretsStore } from './secretsStore.js'
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
    if (r === 'migrado') log('[vault] identidad cifrada en reposo (ligada a esta máquina)')
  } catch (e) { log('[vault] no se pudo cifrar la identidad en reposo:', e.message) }
  const identity = await Identity.connect({ dir, atRest: atRestFor(dir) })
  if (!identity.me?.publickey) await identity.setMyNickname('')
  // CAMINO A: este perfil nació para adoptar la cuenta de un aparato. La identidad se crea
  // igual (su llave es la que entrará como miembro), pero se marca para que `joinProfile`
  // acepte cambiar su acta recién nacida por la que traiga el dispositivo. Sin la marca,
  // adoptar sería pisar una cuenta con datos y se rechaza — que es lo correcto por defecto.
  if (forAdoption) {
    try { await identity.prepareForAdoption() } catch (e) { log('[vault] no se pudo preparar el perfil para adoptar:', e.message) }
  }

  const store = openStore(dir)
  const threads = openThreadStore(dir)
  const secrets = openSecretsStore(dir)
  const master = await masterPubkeyOf(identity)
  const fp = (await pubkeyId(master)).slice(0, 16)

  const { client } = await createTransport({ identity, dir, url: proxyUrl })

  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set(revoked.map((r) => r.nonce))
  }

  const reply = (to, obj) => {
    try { client.send(to, obj) } catch (e) { log('[vault] no se pudo responder:', e.message) }
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
  const staleReply = (from) => reply(from, { type: MSG.ERROR, error: 'petición vencida: ts fuera de la ventana ±5 min (posible replay, o el reloj del dispositivo está desfasado)' })

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
    if (!chk.ok) { audit('rejected', { what: 'sign', reason: chk.reason }); return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason }) }
    const toSign = p.data?.payload
    if (toSign == null) return reply(from, { type: MSG.ERROR, error: 'data.payload requerido' })
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
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const id = p.data?.id || 'root'
    reply(from, { type: MSG.DATA, id, node: store.getNode(id) })
  }

  // Store de hilos+aperturas (Fase 3): escrituras requieren vault:store; lecturas
  // aceptan vault:store o vault:read. Cada op va firmada por D + cert (cadena D←maestra).
  async function handleStore (from, p) {
    const d = p.data
    if (!d || typeof d.method !== 'string' || !threads.methods[d.method]) {
      return reply(from, { type: MSG.ERROR, error: 'store: método inválido' })
    }
    if (!isFresh(d)) return staleReply(from)
    // CANDADO del perfil (contraseña opcional): solo frena EDITAR el perfil. Un
    // dispositivo enrolado puede seguir firmando, leyendo y guardando contenido;
    // lo que no puede es reescribir quién sos mientras el perfil está bloqueado.
    if (PROFILE_EDIT_METHODS.has(d.method) && isLocked()) {
      audit('rejected', { what: 'store', method: d.method, reason: 'locked' })
      return reply(from, { type: MSG.ERROR, error: 'perfil bloqueado: desbloquéalo en el PC del vault (dotrino-vault unlock) para editarlo' })
    }
    const revoked = await revocationSet()
    let chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.STORE, trustedIssuer: master, revoked })
    if (!chk.ok && STORE_READ_METHODS.has(d.method)) {
      chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.READ, trustedIssuer: master, revoked })
    }
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    try {
      // CIFRADO de punta a punta con la clave de contenido del perfil: el proxy transporta
      // pero no ve nada de lo que el usuario guarda. Si el dispositivo mandó `enc`, se abre
      // aquí con la clave de la bóveda (que también es miembro) y la respuesta vuelve igual.
      let args = d.args || {}
      let cek = null
      if (d.enc) {
        cek = await identity.contentKey?.().catch(() => null)
        if (!cek) return reply(from, { type: MSG.ERROR, error: 'store: esta bóveda no tiene la clave de contenido del perfil' })
        args = JSON.parse(await identity.openContent(d.enc))
      }
      const result = await threads.methods[d.method](args)
      if (cek) {
        const enc = await identity.sealContent(JSON.stringify(result ?? null))
        return reply(from, { type: MSG.STORE_RESULT, method: d.method, result: { __enc: enc } })
      }
      reply(from, { type: MSG.STORE_RESULT, method: d.method, result })
    } catch (e) { reply(from, { type: MSG.ERROR, error: e.message }) }
  }

  // Lista (solo lectura) de dispositivos enrolados, para un panel en el navegador.
  // Cualquier cert válido tuyo puede verla; REVOCAR sigue siendo solo desde el PC.
  async function handleDevices (from, p) {
    if (!isFresh(p.data)) return staleReply(from)
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, trustedIssuer: master, revoked: await revocationSet() })
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const { issued, revoked } = await identity.listDelegations()
    // El acta viaja con la lista: así cada dispositivo se entera de los cambios de
    // política (quién manda, quién puede qué) sin un canal aparte.
    const acta = (await identity.profileActa?.().catch(() => null))?.acta || null
    // Si el dispositivo estuvo apagado y viene con un `seq` viejo, se le manda la CADENA
    // que falta (ventana de retención, §1.3) para que compruebe el encadenamiento en vez
    // de tragarse un salto a ciegas. Si se salió de la ventana, llega vacía y toca
    // re-emparejar — que es justo lo que debe pasar.
    const chain = typeof p.data?.sinceSeq === 'number'
      ? (await identity.actaHistory({ sinceSeq: p.data.sinceSeq }).catch(() => null))?.chain || null
      : null
    // `sub` (pubkey completa) va incluida: es la DIRECCIÓN de cada dispositivo en el
    // proxy → permite a las apps AUTODESCUBRIR tus máquinas (p. ej. la terminal
    // lista tus agentes sin pegar nada). Solo la ve quien presenta un cert tuyo válido.
    const devices = await Promise.all(issued.map(async (x) => ({
      deviceId: x.sub ? await deviceIdOf(x.sub) : null, sub: x.sub || null, label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
    })))
    reply(from, { type: MSG.DEVICES_RESULT, devices, revoked, acta, chain })
  }

  // RENOVACIÓN automática: un dispositivo con cert VIGENTE y no revocado pide un
  // cert fresco (misma sub-clave y scope) sin QR ni aprobación — sigue siendo el
  // mismo dispositivo enrolado, solo extiende la ventana. Un cert vencido o
  // revocado NO puede renovarse (ahí sí toca re-emparejar con aprobación).
  const RENEW_TTL_MS = 30 * 24 * 60 * 60 * 1000
  async function handleRenew (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'renew', reason: 'stale' }); return staleReply(from) }
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, trustedIssuer: master, revoked: await revocationSet() })
    if (!chk.ok) { audit('rejected', { what: 'renew', reason: chk.reason }); return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason }) }
    // Reusar el label del cert original (si sigue registrado en delegations).
    const { issued } = await identity.listDelegations()
    const prev = (issued || []).find((x) => x.nonce === p.cert.nonce)
    const { cert } = await identity.signDelegation(p.cert.sub, p.cert.scope, { ttlMs: RENEW_TTL_MS, label: prev?.label || '' })
    audit('renew', { device: await deviceIdOf(p.cert.sub), label: prev?.label || '' })
    log(`[vault] cert renovado para ${await deviceIdOf(p.cert.sub)} (30 días)`)
    reply(from, { type: MSG.RENEWED, cert })
  }

  // SECRETOS de servicios: un servicio enrolado (cert `vault:secrets:<ns>`)
  // pide el bundle de su namespace. La respuesta va SELLADA a la llave ECDH
  // efímera `ek` que vino en el sobre firmado (el proxy transporta pero no
  // puede leer los valores) y el cuerpo va FIRMADO por la maestra (el
  // servicio verifica contra su iss pineada — un relay no puede inyectar
  // secretos falsos). Replay inerte: cada petición usa una ek nueva.
  //   data: { op:'secrets', ns, ek, publickey, ts }
  async function handleSecrets (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'secrets', reason: 'stale' }); return staleReply(from) }
    const ns = p.data?.ns
    if (!isValidSecretsNs(ns)) return reply(from, { type: MSG.ERROR, error: 'secrets: namespace inválido' })
    if (typeof p.data?.ek !== 'string') return reply(from, { type: MSG.ERROR, error: 'secrets: falta ek (llave efímera del solicitante)' })
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: secretsScope(ns), trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) { audit('rejected', { what: 'secrets', ns, reason: chk.reason }); return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason }) }
    // FRONTERA DEL CN (acta): además del scope del cert, el acta tiene que decir que este
    // miembro es el servicio `ns`. Así el límite no depende solo de qué cert se emitió: la
    // llave del proxy no ve nada que no sea del proxy, y está escrito donde se puede comprobar.
    const acta = (await identity.profileActa?.().catch(() => null))?.acta
    if (acta && !Acta.memberCanReadSecrets(acta, chk.device, ns)) {
      audit('rejected', { what: 'secrets', ns, reason: 'cn' })
      return reply(from, { type: MSG.ERROR, error: `no autorizado: cn — el acta no reconoce a este miembro como el servicio «${ns}»` })
    }
    let enc
    try {
      enc = await seal({ ek: p.data.ek, payload: { secrets: secrets.get(ns) } })
    } catch (e) {
      return reply(from, { type: MSG.ERROR, error: 'secrets: ek inválida' })
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
      if (payload.type === MSG.DEVICES) return await handleDevices(from, payload)
      if (payload.type === MSG.RENEW) return await handleRenew(from, payload)
      if (payload.type === MSG.SECRETS) return await handleSecrets(from, payload)
      if (payload.type === MSG.ADMIN) return await handleAdmin(from, payload)
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
  const AVISO_AGRUPA_MS = Number(process.env.DOTRINO_VAULT_AVISO_MS) || 3000
  const avisosPendientes = new Map()   // ns → timer

  async function avisarCambio (ns) {
    let destinos = []
    try {
      const { issued } = await identity.listDelegations()
      const revocados = await revocationSet()
      const scope = secretsScope(ns)
      // Los agentes de ESE ns y nadie más: el aviso dice qué namespace cambió, así
      // que mandárselo a otro sería filtrarle que existe.
      //
      // Y UNO POR LLAVE, no uno por delegación: renovar el cert emite una
      // delegación nueva para la MISMA sub-clave, así que un agente que lleve
      // tiempo enrolado aparece varias veces y recibiría el aviso repetido.
      const vistas = new Set()
      destinos = (issued || []).filter((x) => {
        if (!x.sub || revocados.has(x.nonce) || !(x.scope || []).includes(scope)) return false
        if (vistas.has(x.sub)) return false
        vistas.add(x.sub)
        return true
      })
    } catch (e) { return log('[vault] no se pudo listar a quién avisar:', e.message) }
    if (!destinos.length) return

    const body = { op: 'secrets.changed', ns, ts: Date.now() }
    const { signature } = await identity.signData(body)
    for (const d of destinos) {
      try { client.sendByPubkey(d.sub, { type: MSG.SECRETS_CHANGED, body, signature }) } catch (_) {}
    }
    audit('secrets.changed', { ns, avisados: destinos.length })
    log(`[vault] configuración de «${ns}» cambió: avisados ${destinos.length} agente(s)`)
  }

  function programarAviso (ns) {
    clearTimeout(avisosPendientes.get(ns))
    const t = setTimeout(() => {
      avisosPendientes.delete(ns)
      avisarCambio(ns).catch((e) => log('[vault] aviso de cambio falló:', e.message))
    }, AVISO_AGRUPA_MS)
    t.unref?.()
    avisosPendientes.set(ns, t)
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
      for (const d of issued || []) {
        if (!d.sub) continue
        try { client.sendByPubkey(d.sub, { type: MSG.ADMIN_EVENT, body, signature }) } catch (_) {}
      }
    } catch (e) { log('[vault] could not notify members of the change:', e.message) }
  }

  const admin = createAdminDesk({
    desk,
    deviceIdOf,
    ttlMs: DEVICE_TTL_MS,
    audit,
    notify: notifyMembers,
    readActivity,
    verify: async ({ data, signature, cert }) => verifyChain({
      data, signature, cert,
      expectedScope: SCOPE.ADMIN, trustedIssuer: master, revoked: await revocationSet()
    })
  })

  async function handleAdmin (from, p) {
    // La frescura se comprueba aquí (es del transporte, igual que en el resto de
    // handlers); el resto de la regla vive en el módulo puro.
    if (!isFresh(p.data)) return staleReply(from)
    const r = await admin.handle(p.data, { signature: p.signature, cert: p.cert })
    if (!r.ok) return reply(from, { type: MSG.ERROR, error: r.error })
    reply(from, { type: MSG.ADMIN_RESULT, op: p.data.op, result: r.result })
  }

  // API local de secretos (solo CLI/UI del dueño; audita cada cambio).
  function setSecret (ns, key, value) { secrets.set(ns, key, value); audit('secret.set', { ns, key }); programarAviso(ns) }
  function deleteSecret (ns, key) { const ok = secrets.delete(ns, key); if (ok) { audit('secret.rm', { ns, key }); programarAviso(ns) } return ok }
  function listSecrets () { return secrets.list() }

  return {
    identity, client, store, threads, secrets, master, fingerprint: fp,
    startPairing: desk.startPairing,
    stopPairing: desk.stopPairing,
    listPending: desk.listPending,
    // Aprobar desde el PC avisa igual que aprobar a distancia: el resto de tus
    // dispositivos se entera de que entró alguien, venga de donde venga.
    approveDevice: async (code) => {
      const r = await desk.approve(code)
      await notifyMembers('enrolled', { deviceId: r?.deviceId || null, by: 'pc' })
      return r
    },
    rejectDevice: (deviceId) => desk.reject(deviceId),
    setSecret, deleteSecret, listSecrets,
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
    revokeDevice: async (nonce) => {
      const r = await desk.revoke(nonce)
      await notifyMembers('revoked', { certNonce: nonce, by: 'pc' })
      return r
    },
    close () {
      for (const t of avisosPendientes.values()) clearTimeout(t)
      avisosPendientes.clear()
      try { client.close() } catch (_) {} identity.destroy()
    }
  }
}
