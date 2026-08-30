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
// `PENDING_TTL_MS` se usa abajo, al esperar la firma del aprobador: sin importarlo, esa
// espera reventaba con un ReferenceError y la aprobación del mostrador de contraseñas no
// llegaba a existir. Solo se veía por ese camino —el único que lo usa—, y no había prueba
// que lo recorriera hasta que la hubo (dotrino-test, smoke:demonio, 2026-08-30).
import { createApprovals, PENDING_TTL_MS } from './approvals.js'
import { makeSealer } from './sealer.js'
import { openSealKeys } from './sealKey.js'
import { seal } from '../lib/src/sealed.js'
import { dataDir, ensureDir } from './paths.js'
import { atRestFor, kekFor, migrateFile } from './atrest.js'
import { MSG, SCOPE, secretsScope, isValidSecretsNs } from './protocol.js'

/**
 * Tope de una respuesta de la bóveda por el transporte. El proxio (`PROXY_MAX_FRAME_BYTES`)
 * corta el frame a 1 MB, y el sobre del proxio (destinatarios, tipos) va por encima de esto:
 * se deja margen en vez de apurar el límite.
 */
const MAX_REPLY_BYTES = 768 * 1024

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
export async function startVault ({ dir = dataDir(), proxyUrl, log = console.log, onEnrollChallenge, isLocked = () => false, hasPassword = () => true, deriveAdminKey = null, forAdoption = false, onAdopted } = {}) {
  ensureDir(dir)
  // CIFRADO EN REPOSO ligado a esta máquina: ningún archivo del dir queda en claro, así
  // que copiarlos a otro equipo no sirve de nada. La identidad se migra AQUÍ (verificando
  // antes de reemplazar); el resto —`vault.json`, `threads.json`, `secrets.json`— lo hace
  // su propio store al abrirse. No protege contra quien ya tiene ESTA
  // máquina (puede leer el mismo material); es subir el listón, no una imposibilidad.
  // La migración verifica antes de reemplazar: si algo falla, el original queda intacto.
  try {
    const r = migrateFile(path.join(dir, 'identity.json'), kekFor(dir))
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

  // LA LLAVE DE SELLADO (§8.8/§8.9): con ella se FIRMAN los sobres de los secretos. No
  // abre nada, así que se usa sin la frase; su autoridad se la da el acta, que la nombra
  // y que sella únicamente la maestra. Se estrena una por acta: aquí está el proveedor.
  const sealKeys = openSealKeys(dir)
  identity.setSealKeyProvider?.(() => sealKeys.mint())

  const store = openStore(dir)
  const threads = openThreadStore(dir)
  const approvals = createApprovals()

  /**
   * Pedidos de aprobación que NO son de un cajón de secretos: quien espera es una
   * promesa dentro del vault (la bóveda de contraseñas), no un aparato aguardando un
   * sobre sellado. `id` del pedido → `resolve(boolean)`.
   *
   * Aparte a propósito: `approvals` es un módulo puro y no tiene por qué saber que hay
   * dos clases de espera.
   */
  const waiters = new Map()
  // APARATOS QUE PIDEN APROBACIÓN: una lista de llaves en `approval.json` (cifrado en reposo
  // como todo el dir). Es decisión de esta bóveda, no del acta: es ella la que entrega.
  const approvalFile = path.join(dir, 'approval.json')
  const approvalAtRest = atRestFor(dir)
  const readSupervised = () => { try { const d = JSON.parse(approvalAtRest.decrypt(fs.readFileSync(approvalFile, 'utf8'))); return Array.isArray(d?.members) ? d.members : [] } catch (_) { return [] } }
  const needsApproval = (pub) => readSupervised().includes(pub)
  async function setApproval (pub, on) {
    const cur = new Set(readSupervised())
    if (on) cur.add(pub); else cur.delete(pub)
    fs.writeFileSync(approvalFile, approvalAtRest.encrypt(JSON.stringify({ v: 1, members: [...cur] })), { mode: 0o600 })
    audit('approval', { device: await deviceIdOf(pub).catch(() => null), on: !!on })
    return { approval: !!on }
  }
  // LA BÓVEDA DE CONTRASEÑAS: entradas y su llave, en el dir del perfil y cifradas en
  // reposo como todo lo demás. QUIÉN PUEDE PEDIR LO DICE EL ACTA (capacidad
  // `passwords`), como cualquier otro permiso: aquí no hay una segunda lista de
  // aparatos. Tenerla obligaba a acordarse de dos sitios al quitar un aparato, y era
  // además un emparejamiento paralelo al del ecosistema.
  const passwordsFile = path.join(dir, 'passwords.json')
  const passwordsAtRest = atRestFor(dir)
  const readPasswordsFile = () => {
    try { return JSON.parse(passwordsAtRest.decrypt(fs.readFileSync(passwordsFile, 'utf8'))) } catch (_) { return null }
  }
  const writePasswordsFile = (d) => {
    fs.writeFileSync(passwordsFile, passwordsAtRest.encrypt(JSON.stringify(d)), { mode: 0o600 })
  }

  /** El almacén que espera `@dotrino/passmanager`. Todo en un archivo, cifrado en reposo. */
  const passwordsStore = {
    async get (k) { return readPasswordsFile()?.data?.[k] },
    async set (k, v) {
      const d = readPasswordsFile() || { v: 1, data: {} }
      d.data = { ...(d.data || {}), [k]: v }
      writePasswordsFile(d)
    },
  }

  /** Los aparatos que el acta autoriza a pedir credenciales (`caps <ID> +contraseñas`). */
  const passwordDevices = () => (actaCache?.members || []).filter((m) => Acta.memberCan(actaCache, m.pub, 'passwords'))

  /**
   * El acta vigente, en caché.
   *
   * `isAllowed`/`encPubOf` del responder son SÍNCRONOS (se llaman por cada mensaje que
   * entra, y leer el acta ahí sería un await por mensaje), así que se refresca aparte.
   * Se relee cada pocos segundos: revocar un aparato tarda eso en cortarle el acceso,
   * no un reinicio.
   */
  let actaCache = null
  const refreshActa = async () => {
    try { actaCache = (await identity.profileActa?.().catch(() => null))?.acta || null } catch (_) {}
    return actaCache
  }

  /**
   * La llave de la bóveda de contraseñas. Nace con el primer uso y vive cifrada en
   * reposo, como la identidad: aquí no hace falta envolverla a cada aparato porque
   * ningún aparato abre la bóveda — piden de a una y el vault responde.
   */
  async function passwordsKey () {
    const d = readPasswordsFile()
    if (d?.cek) {
      const raw = Uint8Array.from(Buffer.from(d.cek, 'base64'))
      return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
    }
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key))
    writePasswordsFile({ ...(d || { v: 1, data: {} }), cek: Buffer.from(raw).toString('base64') })
    return key
  }

  const approvalsSweeper = setInterval(() => { for (const g of approvals.sweep()) audit('secrets.expired', { id: g.id, ns: g.ns, device: g.deviceId }) }, 30 * 1000); approvalsSweeper.unref?.()
  const secrets = openSecretsStore(dir, {
    sealer: makeSealer(),
    // A QUIÉN se le envuelve la llave de cada cajón: los servicios de ese namespace (o el
    // propio aparato, si el cajón es suyo) MÁS los aparatos que administran. Sale del
    // acta, y por eso lo pone el vault: el store no conoce el acta.
    recipients: (owner) => recipientsOf(owner),
    // La FIRMA del sobre: dice que salió de esta bóveda y con qué acta (§8.8).
    signer: (body) => signSeal(body),
    defaultKey: () => new Uint8Array(kekFor(dir))
  })
  // SIN CONTRASEÑA NO HAY SECRETO. Escribir no la pide (sellar solo necesita públicas,
  // §8.1), pero la copia de recuperación —la que deja al dueño VER sus valores— se cierra
  // con ella. Sin contraseña se cae a la llave de la máquina, que es la protección de
  // siempre, pero su material vive en este mismo disco: una copia del disco lo abre.
  // Se dice en voz alta: prometer una protección que no está puesta es peor que no
  // tenerla (docs/secretos-sellados.md §2.3).
  try {
    if (!hasPassword()) {
      log('[vault] this profile has NO password: private variables are sealed with a key derived from this machine,')
      log('[vault] so a copy of this disk opens them. Set one with `dotrino-vault profile password`.')
    }
  } catch (_) {}

  const master = await masterPubkeyOf(identity)
  const fp = (await pubkeyId(master)).slice(0, 16)

  /**
   * El acta tiene que nombrar una llave de sellado QUE SEA NUESTRA. Si no nombra ninguna
   * (un acta de antes de esto) o nombra una cuya privada no tenemos (el disco se
   * restauró, o el acta la selló otro master), se estrena: firmar sobres es de esta
   * máquina y no puede quedar a medias.
   *
   * Solo lo intenta el master —es el único que sella actas— y no bloquea el arranque: sin
   * llave los sobres salen sin firma, que es lo que ya pasaba antes de §8.8.
   */
  try {
    const info = await identity.profileActa?.()
    const acta = info?.acta
    if (info?.isMaster && acta && (!acta.sealPub || !sealKeys.has(acta.sealPub))) {
      const r = await identity.rotateSealKey()
      // Sin `%s`: este `log` va con un prefijo por delante, así que el formato no es lo
      // primero y `console.log` no lo sustituye (salía «record #%s 2»).
      log(`[vault] new sealing key in record #${r.seq}`)
    }
  } catch (e) { log('[vault] could not set up the sealing key:', e.message) }

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
      // Su cajón propio se va entero y eso es inmediato y completo (estaba sellado solo
      // a él). Lo que comparte —la CEK de su namespace— hay que ROTARLO, porque quitarle
      // la envoltura no basta: si guardó la CEK sigue abriendo todo lo cifrado con ella.
      //
      // Pero rotar exige la contraseña, y quitar un aparato es el interruptor de
      // emergencia: el gesto que se hace desde el teléfono cuando se perdió una máquina.
      // Un interruptor que pide una frase que quizá no tienes a mano no es un
      // interruptor. Así que se INTENTA, y si no se puede queda anotado y a la vista.
      markRotationDue(sub).catch((e) => log('[vault] could not rotate after the removal:', e.message))
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
    reply(from, fitChain({ type: MSG.DEVICES_RESULT, devices, revoked, acta: record, chain }))
  }

  /**
   * NADA DE FRAMES QUE NO CABEN. El proxio corta a 1 MB y cierra la conexión con un 1009:
   * la respuesta no llega, la bóveda reconecta y no queda ni una línea de log de su lado.
   * Así estuvo muda tres días para todo el ecosistema (2026-08-24) mientras el bot social
   * repetía «no tienes ningún node de contenido enrolado».
   *
   * La cadena de actas es lo único que puede crecer sin techo aquí —cada acta es un
   * snapshot completo de los miembros—, así que se recorta por el FINAL: el tramo que sale
   * sigue siendo contiguo desde el `seq` del que pregunta, que es lo que necesita para
   * encadenar, y en la siguiente pregunta seguirá desde donde llegó.
   */
  function fitChain (msg) {
    const size = (m) => JSON.stringify(m).length
    if (size(msg) <= MAX_REPLY_BYTES) return msg
    const full = msg.chain?.length || 0
    while (msg.chain?.length && size(msg) > MAX_REPLY_BYTES) msg.chain = msg.chain.slice(0, -1)
    if (!msg.chain?.length) msg.chain = null
    const left = msg.chain?.length || 0
    log(`[vault] record chain trimmed to fit the transport: ${left}/${full} link(s), ${size(msg)} bytes`)
    if (size(msg) > MAX_REPLY_BYTES) log(`[vault] ⚠ the reply STILL does not fit (${size(msg)} bytes): the proxy will drop it`)
    return msg
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
  /**
   * Un servicio que se enroló antes de que existieran las llaves de cifrado registra la
   * suya. Es la alternativa a re-enrolarlo: re-enrolar le cambia la pubkey, y su cajón
   * de variables va indexado por ella — se quedaría sin configuración sin decirlo.
   */
  async function handleEncKey (from, p) {
    const ns = p.data?.ns
    if (!isValidSecretsNs(ns)) return reply(from, { type: MSG.ERROR, error: 'enckey: invalid namespace' })
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: secretsScope(ns), trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'enckey')
    try {
      await identity.setMemberEncPub({ pub: chk.device, encPub: p.data.encPub })
      audit('enckey', { device: await deviceIdOf(chk.device).catch(() => null), ns })
      log(`[vault] ${ns}: encryption key registered for ${await deviceIdOf(chk.device).catch(() => '????-????')}`)
      // Ya puede recibir sobres: se le envuelve la llave de su cajón en el acto, o
      // seguiría sin poder abrir nada hasta la siguiente escritura.
      await spreadKey(`ns:${ns}`, await nsMembers(ns)).catch((e) => log('[vault] could not hand it the key:', e.message))
      const body = { op: 'secrets.result', ns, enc: null, ok: true, ts: Date.now() }
      const { signature } = await identity.signData(body)
      reply(from, { type: MSG.SECRETS_RESULT, body, signature })
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: 'enckey: ' + e.message })
    }
  }

  async function handleSecrets (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'secrets', reason: 'stale' }); return staleReply(from) }
    // REGISTRAR LA LLAVE DE CIFRADO de un servicio ya enrolado. Va por aquí, y no por
    // un mensaje nuevo, para no tocar `protocol.js` — que está vendorizado en el iframe
    // de identidad y obligaría a re-vendorizar.
    //
    // No exige la contraseña del perfil, y el argumento importa: registrar una llave no
    // da acceso a nada por sí solo. Quien firma esta petición ya tiene la llave de firma
    // del servicio y su cert, o sea que ya lee ese namespace. No hay escalada.
    if (p.data?.op === 'enckey') return handleEncKey(from, p)
    if (['approvals', 'approve', 'deny'].includes(p.data?.op)) return handleApproval(from, p)
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
    // APROBACIÓN: si este APARATO está marcado (`dotrino-vault approval <ID> on`), liberarle
    // claves privadas exige el visto bueno de un aparato con `approve` — en CADA petición,
    // que para un servicio bien hecho es una por arranque: pide al (re)iniciar, se queda las
    // claves en memoria y no vuelve a pedir. El pedido se apunta, se avisa a quien aprueba y se
    // contesta «pendiente»; la respuesta de verdad sale cuando el teléfono firme
    // (`handleApproval`), sellada a la misma `ek`.
    if (needsApproval(chk.device)) {
      const deviceId = await deviceIdOf(chk.device).catch(() => null)
      const label = (record?.members || []).find((m) => m.pub === chk.device)?.label || ''
      const pend = approvals.request({ ns, device: chk.device, deviceId, label, ek: p.data.ek })
      audit('secrets.pending', { device: deviceId, ns, id: pend.id })
      log(`[vault] ${ns}: ${deviceId || '????-????'} is waiting for approval (${pend.id})`)
      const body = { op: 'secrets.pending', ns, id: pend.id, exp: pend.exp, ts: Date.now() }
      const { signature } = await identity.signData(body)
      reply(from, { type: MSG.SECRETS_RESULT, body, signature })
      await notifyApprovers(pend, record)
      return
    }
    let res
    try { res = await resultFor(ns, chk.device, p.data.ek, record) } catch (e) {
      return reply(from, { type: MSG.ERROR, error: 'secrets: invalid ek' })
    }
    audit('secrets', { device: await deviceIdOf(chk.device), ns })
    reply(from, { type: MSG.SECRETS_RESULT, ...res })
  }

  /** El bundle de `ns` para `devicePub`, sellado a su `ek` y firmado por la maestra. */
  async function resultFor (ns, devicePub, ek, record) {
    // Mientras el archivo siga en v3 el cable NO cambia: se mandan los valores como
    // siempre. Solo tras la migración viajan sobres, y entonces quien los abre es el
    // agente con su llave. Así el despliegue del daemon se deshace con un reinicio,
    // porque hasta el primer desbloqueo no ha cambiado nada de lo que ve nadie.
    const b = secrets.bundleFor(ns, devicePub)
    // EL ACTA VIAJA CON EL BUNDLE (§8.8): es lo que le permite al agente comprobar que
    // los sobres los selló esta bóveda, y con qué llave —la que el acta nombra para el
    // `seq` con el que se firmaron—. No es un dato secreto: el acta es pública dentro
    // del perfil y el agente ya es miembro. Sin ella podría abrir igual, pero no sabría
    // de dónde salió lo que abre.
    const payload = b.legacy
      ? { secrets: Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v])) }
      : { sealed: b, acta: record || null }
    const enc = await seal({ ek, payload })
    const body = { op: 'secrets.result', ns, enc, ts: Date.now() }
    const { signature } = await identity.signData(body)
    return { body, signature }
  }

  /**
   * PEDIDOS DE APROBACIÓN (aparatos marcados con `approval on`). Entran por `vault.secrets` con
   * `op: approvals | approve | deny`, firmados por un aparato con `vault:approve` — que,
   * como `admin`, no se empareja: se concede a mano (`caps <ID> +aprueba`). El acta tiene
   * que decirlo también, para que quitar el permiso surta efecto en el acto.
   */
  async function handleApproval (from, p) {
    const op = p.data?.op
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.APPROVE, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'approval')
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (record && !Acta.memberCan(record, chk.device, 'approve')) {
      audit('rejected', { what: 'approval', reason: 'acta' })
      return reply(from, { type: MSG.ERROR, error: 'unauthorized: acta — this member does not approve' })
    }
    const by = await deviceIdOf(chk.device).catch(() => null)
    const answer = async (body) => {
      body = { ...body, ts: Date.now() }
      const { signature } = await identity.signData(body)
      reply(from, { type: MSG.SECRETS_RESULT, body, signature })
    }
    if (op === 'approvals') return answer({ op: 'approvals', items: approvals.list() })
    const id = typeof p.data?.id === 'string' ? p.data.id : ''
    const pend = approvals.take(id)
    if (!pend) return reply(from, { type: MSG.ERROR, error: 'approval: unknown or expired request' })
    // PEDIDOS QUE NO SON DE UN CAJÓN (hoy: la bóveda de contraseñas). Se resuelve ANTES
    // de tocar `resultFor`, que asume un cajón y una `ek`: aquí no hay nada que sellar,
    // solo una promesa esperando un sí o un no.
    if (waiters.has(id)) {
      const resolver = waiters.get(id)
      waiters.delete(id)
      const ok = op === 'approve'
      audit(ok ? 'passwords.approved' : 'passwords.denied', { device: pend.deviceId, id, by })
      log(`[vault] passwords: request of ${pend.deviceId} ${ok ? 'approved' : 'DENIED'} by ${by}`)
      resolver(ok)
      return answer({ op: `${op}.result`, id, ok: true })
    }
    if (op === 'deny') {
      audit('secrets.denied', { device: pend.deviceId, ns: pend.ns, id, by })
      log(`[vault] ${pend.ns}: request of ${pend.deviceId} DENIED by ${by}`)
      try { client.sendByPubkey(pend.device, { type: MSG.ERROR, error: `unauthorized: denied — the "${pend.ns}" request was denied from ${by}` }) } catch (_) {}
      return answer({ op: 'deny.result', id, ok: true })
    }
    if (op !== 'approve') return reply(from, { type: MSG.ERROR, error: 'approval: unknown op' })
    let res
    try { res = await resultFor(pend.ns, pend.device, pend.ek, record) } catch (e) {
      return reply(from, { type: MSG.ERROR, error: 'approval: could not seal the reply: ' + e.message })
    }
    audit('secrets.approved', { device: pend.deviceId, ns: pend.ns, id, by })
    log(`[vault] ${pend.ns}: request of ${pend.deviceId} approved by ${by}`)
    // Va por `sendByPubkey`: si el que pedía ya no está conectado, lo recoge al volver.
    try { client.sendByPubkey(pend.device, { type: MSG.SECRETS_RESULT, ...res }) } catch (_) {}
    return answer({ op: 'approve.result', id, ok: true })
  }

  /** Aviso a los aparatos que aprueban (cola del proxio → push nativo si están apagados). */
  async function notifyApprovers (pend, record) {
    try {
      const body = { ev: 'approval', id: pend.id, ns: pend.ns, deviceId: pend.deviceId, label: pend.label, exp: pend.exp, ts: Date.now() }
      const { signature } = await identity.signData(body)
      const who = (record?.members || []).filter((m) => Acta.memberCan(record, m.pub, 'approve')).map((m) => m.pub)
      if (!who.length) log(`[vault] ${pend.ns}: nobody can approve (grant it with: dotrino-vault caps <ID> +aprueba)`)
      for (const pub of who) { try { client.sendByPubkey(pub, { type: MSG.ADMIN_EVENT, body, signature }) } catch (_) {} }
    } catch (e) { log('[vault] could not notify approvers:', e.message) }
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
      if (payload.type === MSG.REWRAP_OK) return await handleRewrapOk(payload)
      if (payload.type === MSG.ADMIN) return await handleAdmin(from, payload)
      if (payload.type === MSG.RENOUNCE) return await handleRenounce(from, payload)
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: e.message })
    }
  })

  // ----- LA BÓVEDA DE CONTRASEÑAS -----
  //
  // Se monta al final y envuelto: es una pieza opcional y un fallo suyo no puede tumbar
  // la CA. Solo se levanta cuando el acta autoriza a alguien — sin eso no hay a quién
  // responder, y crear la llave por si acaso sería crear un secreto que nadie pidió.
  //
  // Y se levanta EN CUANTO pasa, no en el siguiente arranque: conceder el permiso ya es
  // un acto explícito del dueño, y pedirle además que reinicie la bóveda es de las cosas
  // que se olvidan y luego parecen un fallo del gestor.
  let passwords = null
  /**
   * EL SELLADO del gestor: la misma cripto de los sobres del ecosistema
   * (`@dotrino/identity/content`), atada a la llave de cifrado de esta bóveda.
   *
   * Va aquí y no en el cliente del transporte porque el cliente del vault es UNO y lo
   * comparte todo: el protocolo de la CA viaja en claro a propósito (un enrolamiento es
   * público hasta que hay cert). Lo que se sella es lo del gestor, y por eso `isSealed`
   * mira su marca y no otra.
   *
   * Sin esto la bóveda RECIBÍA los sobres y los tiraba —el cliente no tenía con qué
   * abrirlos— y el aparato se quedaba esperando sin que nada lo dijera.
   */
  const passwordSealing = {
    async seal (msg, peerEncPub) {
      if (!peerEncPub) throw Object.assign(new Error('no encryption key'), { code: 'unsealed' })
      return {
        app: 'passmanager',
        // Destinatarios como OBJETOS y no como llaves sueltas: `encrypt` expande cada
        // uno a todos los aparatos de esa persona, y una cadena a secas se le cae por
        // el `continue` sin envolver nada — el sobre salía vacío y sin error.
        sealed: await identity.encrypt([{ encryptionPubkey: peerEncPub }], JSON.stringify(msg)),
        from: await identity.getEncryptionPubkey()
      }
    },
    // `decrypt` devuelve `{ plaintext }`, no la cadena.
    async open (env) { return JSON.parse((await identity.decrypt(env.from, null, env.sealed)).plaintext) },
    isSealed: (m) => !!m && m.app === 'passmanager' && !!m.sealed
  }
  const startPasswordDesk = async () => {
    if (passwords || !passwordDevices().length) return
    const { createPasswordDesk } = await import('./passwords.js')
    client.updateConfig({ sealing: passwordSealing })
    passwords = createPasswordDesk({
      client,
      store: passwordsStore,
      cek: await passwordsKey(),
      // UNA sola condición, y es del ACTA: el aparato tiene la capacidad `passwords`.
      // Quitársela —o quitar el aparato— le corta esto en la siguiente pasada, sin
      // que haya una segunda lista que acordarse de tocar.
      isAllowed: (pub) => !!actaCache && Acta.memberCan(actaCache, pub, 'passwords'),
      encPubOf: (pub) => (actaCache?.members || []).find((m) => m.pub === pub)?.encPub || null,
      needsApproval: (pub) => needsApproval(pub),
      // El teléfono: se apunta el pedido, se le avisa y esta promesa espera su firma.
      // Es el mismo camino que ya recorren los cajones de secretos.
      approve: async ({ pubkey, op }) => {
        const deviceId = await deviceIdOf(pubkey).catch(() => null)
        const label = (actaCache?.members || []).find((m) => m.pub === pubkey)?.label || ''
        const pend = approvals.request({ ns: 'passwords', device: pubkey, deviceId, label, ek: '' })
        audit('passwords.pending', { device: deviceId, id: pend.id, op })
        log(`[vault] passwords: ${deviceId || '????-????'} is waiting for approval (${pend.id})`)
        const espera = new Promise((resolve) => {
          waiters.set(pend.id, resolve)
          // Si nadie contesta, vence solo: la promesa no se queda colgada para siempre
          // y el aparato recibe un no en vez de esperar sin fin.
          const t = setTimeout(() => {
            if (waiters.delete(pend.id)) {
              audit('passwords.expired', { device: deviceId, id: pend.id })
              resolve(false)
            }
          }, PENDING_TTL_MS)
          t.unref?.()
        })
        await notifyApprovers(pend, actaCache)
        return espera
      },
      audit,
      log,
    }).start()
    log('[vault] passwords: serving %d device(s)', passwordDevices().length)
  }
  try {
    // El acta ANTES de mirarla: es ella la que dice si hay a quién responder, y sin
    // refrescarla primero el mostrador no se levantaba nunca en un arranque en frío.
    await refreshActa()
    const actaSweeper = setInterval(() => {
      refreshActa().then(startPasswordDesk).catch(() => {})
    }, 5000)
    actaSweeper.unref?.()
    if (passwordDevices().length) await startPasswordDesk()
    // Ni código de enlace ni pegar nada: un gestor entra como cualquier otro aparato.
    else log('[vault] passwords: no device may ask yet · pair one with `dotrino-vault pair --scope contrasenas`')
  } catch (e) {
    log('[vault] passwords: no se pudo levantar (%s); el resto sigue igual', e.message)
  }

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
  /**
   * La llave de administración a partir de lo que venga en el sobre de la consola
   * remota. `undefined` si no trae contraseña — entonces el store cae a la de la
   * máquina, que es lo correcto para un perfil que no tiene ninguna.
   *
   * La contraseña no se guarda: se deriva, se usa y se suelta con el sobre.
   */
  /**
   * La llave derivada de la contraseña, si el sobre la traía. Desde §8 solo la piden las
   * operaciones que LEEN (ver un valor, cambiar su visibilidad): escribir no.
   */
  async function adminKeyFrom (payload) {
    const pwd = payload?.password
    if (typeof pwd !== 'string' || !pwd) return undefined
    if (typeof deriveAdminKey !== 'function') return undefined
    return deriveAdminKey(pwd)
  }

  const varsDesk = {
    async list () {
      // `listSecrets`/`listDeviceSecrets` ya traen el valor de las públicas y solo de esas:
      // la frontera se decide en un sitio, y lo mismo ve el dueño en su terminal que aquí.
      // Se sella la lista ENTERA, no solo los valores: el proxy tampoco tiene por qué
      // aprender cómo se llaman tus variables ni qué servicios corres.
      return {
        enc: await identity.sealContent(JSON.stringify({
          ns: listSecrets(), dev: await listDeviceSecrets(),
          // Aparatos que están en el acta pero no pueden abrir lo suyo: hay que
          // enseñarlo donde se administra, no solo en el log del servicio.
          incomplete: await incompleteMembers(),
          // Lo que quedó a deber un sellado: quien administra a distancia tiene que
          // poder verlo, porque es exactamente lo que él puede saldar (escribiendo una
          // variable con la contraseña) y la bóveda no.
          pending: await secretDebts(),
          // Y si el perfil NO tiene contraseña, decirlo: sus privadas se abren con la
          // llave de la máquina de la bóveda, cuyo material vive en ese mismo disco.
          // El comentario de aquí decía «la consola lo dice en voz alta» y la consola
          // no decía nada — el mismo error que el comentario mentiroso de `atrest.js`.
          hasPassword: (() => { try { return !!hasPassword() } catch (_) { return true } })()
        }))
      }
    },
    async set ({ ns, pub, key, enc, public: isPublic, by: who = null }) {
      const payload = JSON.parse(await identity.openContent(enc))
      const value = payload?.value
      if (typeof value !== 'string' || !value) throw new Error('var.set: the sealed envelope must carry a non-empty value')
      // NO PIDE LA CONTRASEÑA (§8.1): sellar solo necesita las públicas de quien va a
      // leer. Lo que se guarda es quién lo escribió, para que el histórico lo diga.
      if (ns) await setSecret(ns, key, value, isPublic, { by: who })
      else await setDeviceSecret(pub, key, value, isPublic, { by: who })
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
    async setMany ({ ns, pub, enc, public: isPublic, by: who = null }) {
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
      // NO PIDE LA CONTRASEÑA (§8.1). Y sí, `applySecrets` va con `await` — sin él la
      // escritura quedaba al aire y la respuesta salía antes de guardar nada.
      const keys = ns ? await applySecrets(ns, list, { by: who }) : await applyDeviceSecrets(pub, list, { by: who })
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
  const adminKeyOr = (adminKey) => adminKey || new Uint8Array(kekFor(dir))

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
   * Los APARATOS QUE ADMINISTRAN: miembros sin CN (no son servicios) con llave de
   * cifrado. Son los que pueden VER y REVERTIR desde la consola sin teclear la frase en
   * ningún sitio, que es todo el punto del §8.2 — la capacidad de leer se muda de una
   * frase que se escribe en cualquier parte a una llave que no sale del aparato.
   *
   * La bóveda NO entra en la lista, ni aquí ni en `nsMembers`: envolverle la llave a
   * ella misma sería devolverle la capacidad de leerlo todo, que es justo lo que este
   * diseño quita. Hay un test que lo afirma.
   */
  async function adminDevices () {
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    return (record?.members || []).filter((m) => !m.cn && m.encPub && m.pub !== master)
  }

  /**
   * Los destinatarios de un cajón. Y la regla que decide quién NO entra, que es la que
   * importa (decidida por el dueño el 2026-08-22):
   *
   * **UN CAJÓN CON DUEÑO NO SE ENVUELVE PARA QUIEN ADMINISTRA.** Si el acta dice que
   * hay un servicio que consume ese `ns`, sus variables son suyas y de nadie más: el
   * token de R2 o las llaves de TURN no se pueden abrir desde un navegador, ni aunque
   * alguien se lleve tu portátil con la sesión puesta.
   *
   * Dos cosas que hacen que esto se sostenga:
   *
   *  · **No es una negativa, es que no existe.** Se podría haber dejado el envoltorio y
   *    que la bóveda se negara a entregarlo, pero entonces la protección sería una
   *    política: el envoltorio seguiría en el disco, y quien tuviera el disco más la
   *    llave de un aparato que administra lo abriría sin preguntarle a nadie. Lo que no
   *    se crea no se puede saltar.
   *  · **El criterio es ESTRUCTURAL, no de tiempo de ejecución.** Se mira el acta —qué
   *    dice la maestra que existe—, no quién está encendido. «Hay un servicio activo»
   *    se puede forzar esperando a que ese servicio esté caído.
   *
   * Y sigue habiendo quien pueda repartir: el propio SERVICIO re-envuelve para un
   * miembro nuevo de su cajón (ya tiene la CEK, así que no gana nada), y la frase
   * abre la envoltura de recuperación, que `wrapAll` añade siempre.
   */
  /**
   * Llega la envoltura que hizo un servicio. Se comprueba QUIÉN la firma —tiene que ser
   * el aparato al que se le pidió, no cualquiera que pase por el proxy— y se reparte a
   * quien esté esperándola. Guardarla es cosa de `delegateRewrap`, que es quien sabe
   * qué pidió; aquí solo se valida el remitente.
   */
  async function handleRewrapOk (payload) {
    const d = payload?.data
    if (!d || d.op !== 'rewrap.ok' || !d.wrap) return
    const signer = payload?.cert?.sub
    if (!signer) return
    if (!(await verifyDeviceSig({ publickey: signer, data: d, signature: payload.signature }))) {
      return log('[vault] a handed key arrived BADLY SIGNED: ignored')
    }
    // Y que quien firma sea de ese cajón: si no, no tenía por qué poder abrir esa llave.
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    const m = (record?.members || []).find((x) => x.pub === signer)
    const ns = d.owner?.startsWith('ns:') ? d.owner.slice(3) : null
    if (!m || (ns && m.cn !== ns)) return log('[vault] a handed key arrived from someone outside that drawer: ignored')
    for (const fn of [...rewrapWaiters]) { try { fn(d) } catch (_) {} }
  }

  /** Suscriptores de `vault.rewrap.ok` (la envoltura que devuelve un servicio). */
  const rewrapWaiters = new Set()
  const onRewrapOk = (fn) => { rewrapWaiters.add(fn); return () => rewrapWaiters.delete(fn) }

  async function recipientsOf (owner) {
    if (owner.startsWith('ns:')) {
      const owned = await nsMembers(owner.slice(3))
      // Sin dueño (un cajón personal, o uno cuyo servicio ya no está) sí entra quien
      // administra: si no, no quedaría nadie que pudiera abrirlo sin la frase.
      return owned.length ? owned : await adminDevices()
    }
    const pub = owner.slice(owner.indexOf(':') + 1)
    const m = await memberOf(pub)
    // El cajón propio de un aparato de SERVICIO es tan suyo como el de su ns.
    if (m?.cn) return [m]
    return [...(m ? [m] : []), ...await adminDevices()]
  }

  /**
   * Firma un sobre con la LLAVE DE SELLADO que nombra el acta (§8.8). Devuelve el `seq`
   * del acta junto a la firma: es lo que le dice a quien verifica con qué llave
   * comprobarla, porque esa llave rota con el acta (§8.9).
   *
   * Si no hay llave —o no es nuestra— el sobre sale SIN firma. Guardar la configuración
   * es más importante que poder demostrar después de dónde salió.
   */
  async function signSeal (body) {
    try {
      const acta = (await identity.profileActa?.().catch(() => null))?.acta
      if (!acta?.sealPub) return null
      const sig = await sealKeys.sign(acta.sealPub, body)
      return sig ? { seq: acta.seq, sig } : null
    } catch (_) { return null }
  }

  /**
   * Sellar no basta: hay que REPARTIR la llave. Tras cada escritura se envuelve la CEK
   * del cajón a sus miembros actuales — si no, el servicio recibe sobres que no puede
   * abrir y se queda reintentando para siempre, sin decir por qué.
   *
   * No avisa de cambio a nadie: el texto cifrado de los valores no se mueve, y avisar
   * reiniciaría a todos los nodos del ns para nada.
   */
  /**
   * Se fue un miembro de un namespace: su CEK deja de ser de fiar. Se intenta rotar en
   * el acto y, si no se puede (perfil sin desbloquear), el cajón queda MARCADO — la
   * consola y el CLI lo enseñan, y la siguiente escritura desbloqueada lo salda.
   *
   * Una deuda que no se ve es una deuda que no se paga, y aquí la deuda es que alguien
   * que ya no está podría abrir lo que se escriba mañana.
   */
  async function markRotationDue (sub) {
    const m = await memberOf(sub)
    const ns = m?.cn
    if (!ns) return
    try {
      const r = await secrets.rotate(`ns:${ns}`, await nsMembers(ns))
      if (r?.rotated != null) {
        log(`[vault] ns:${ns}: key rotated after removing a member (${r.rotated} variable(s) re-encrypted)`)
        audit('secret.rotate', { ns, keys: r.rotated })
        scheduleNotice(ns)
        return
      }
    } catch (e) {
      store.setSetting(`rotate-due:${ns}`, String(Date.now()))
      log(`[vault] ns:${ns}: PENDING ROTATION - a member left and its key could not be rotated (${e.message})`)
      audit('secret.rotate-due', { ns, reason: e.message })
    }
  }

  /**
   * Lo que este perfil debe volver a sellar, para que las listas puedan DECIRLO. Son dos
   * deudas distintas y las dos acaban igual —los miembros no leen sus variables— así que
   * salen juntas:
   *
   * - `rotate`: se fue un miembro y no se pudo rotar la llave del namespace.
   * - `rewrap`: entró uno (o registró su llave de cifrado) y no se le pudo envolver.
   *
   * Ambas se saldan solas en la siguiente escritura con contraseña. Mientras tanto,
   * enseñarlas es la diferencia entre un servicio mal configurado y uno mal configurado
   * que además nadie ve.
   */
  /**
   * Los aparatos INCOMPLETOS: los que están en el acta pero no pueden abrir alguna de
   * las variables que les tocan (§8.7). Pasa siempre que entra uno nuevo — envolverle su
   * llave exige abrir la CEK, y eso pide la frase, que por el camino del enrolamiento no
   * hay quien la teclee.
   *
   * Que no puedan leer es CORRECTO y no se relaja. Lo que se arregla aquí es que se
   * vea: hasta ahora un servicio recién enrolado aparecía en la lista como cualquier
   * otro y arrancaba sin configuración, repitiendo un error en su propio log que nadie
   * mira. Con esto, la consola y la TUI pueden decir exactamente qué falta y qué hacer
   * (`dotrino-vault secret settle`, que sí pide la frase).
   *
   * @returns {Promise<Array<{ pub: string, cn: string|null, owners: Record<string, string[]> }>>}
   */
  async function incompleteMembers () {
    if (secrets.isLegacy?.()) return []
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    const out = []
    for (const m of record?.members || []) {
      if (!m.encPub || m.pub === master) continue
      const owners = {}
      // Un servicio lee su cajón de ns y el suyo propio; un aparato que administra
      // puede DESTAPAR cualquiera, así que se le miran todos: sin envoltura, el botón
      // «Ver» de la consola le fallaría sin explicar por qué.
      // Un aparato que administra NO debe tener envoltura de los cajones con dueño
      // (`recipientsOf`), así que no se le cuenta como falta: lo que ahí falta es a
      // propósito y ponerlo en la lista sería pedir que se «arregle» lo correcto.
      const ownedNs = new Set((record?.members || []).filter((x) => x.cn).map((x) => x.cn))
      const drawers = m.cn
        ? [`ns:${m.cn}`, `dev:${m.pub}`]
        : [...Object.keys(secrets.list()).filter((ns) => !ownedNs.has(ns)).map((ns) => `ns:${ns}`), `dev:${m.pub}`]
      for (const owner of drawers) {
        const missing = secrets.missingFor(owner, m.pub)
        if (missing.length) owners[owner] = missing
      }
      if (Object.keys(owners).length) out.push({ pub: m.pub, cn: m.cn || null, owners })
    }
    return out
  }

  /**
   * Lo que quedó a deber una ROTACIÓN: un aparato salió conociendo la llave vigente y
   * no se pudo rotar en ese momento. Eso sí es una nota, porque es un hecho pasado que el
   * estado de hoy no enseña (quitarle la envoltura no le quita lo que ya supo).
   */
  function rotationsDue () {
    const out = {}
    for (const [k, v] of Object.entries(store.listSettings?.() || {})) {
      // La salida va SIEMPRE por owner (`ns:proxy`), aunque el ajuste guarde solo el
      // nombre del namespace: una sola forma para quien lo lee.
      if (k.startsWith('rotate-due:')) out['ns:' + k.slice('rotate-due:'.length)] = { kind: 'rotate', at: Number(v) || 0 }
    }
    return out
  }

  /**
   * TODO lo que está a deber, por cajón: las rotaciones anotadas y, CALCULADO, cada
   * envoltura que falta. La falta de una envoltura no se anota nunca: se mira. Una nota
   * se desincroniza en cuanto alguien salda la deuda por un camino que no pasa por donde
   * se anotó (pasó dos veces: el reparto por el hermano y el rehacer al abrir), y
   * entonces la consola avisa de algo que ya no existe. Lo que se calcula no miente.
   * @returns {Promise<Record<string, { kind: 'rotate'|'rewrap', at?: number, members?: { pub: string, keys: string[] }[] }>>}
   */
  async function secretDebts () {
    const out = rotationsDue()
    for (const m of await incompleteMembers()) {
      for (const [owner, keys] of Object.entries(m.owners)) {
        if (out[owner]?.kind === 'rotate') continue
        out[owner] = out[owner] || { kind: 'rewrap', members: [] }
        out[owner].members.push({ pub: m.pub, keys })
      }
    }
    return out
  }

  async function spreadKey (owner, members, adminKey) {
    if (secrets.isLegacy()) return null
    // Si este cajón quedó a deber una rotación (se fue alguien y no se pudo rotar),
    // se salda AHORA, que es cuando hay con qué. Rotar incluye re-envolver, así que
    // sustituye al reparto en vez de sumarse.
    const ns = owner.startsWith('ns:') ? owner.slice(3) : null
    if (ns && store.getSetting(`rotate-due:${ns}`)) {
      const rot = await secrets.rotate(owner, members, adminKey)
      store.setSetting(`rotate-due:${ns}`, undefined)
      log(`[vault] ns:${ns}: pending rotation settled (${rot?.rotated ?? 0} variable(s) re-encrypted)`)
      audit('secret.rotate', { ns, keys: rot?.rotated ?? 0, pending: true })
      return rot
    }
    try {
      const r = await secrets.rewrap(owner, members, adminKey)
      if (r?.sinLlave?.length) {
        log(`[vault] ${owner}: ${r.sinLlave.length} member(s) without an encryption key - they will NOT be able to read their variables`)
        audit('secret.nokey', { owner, count: r.sinLlave.length })
      }
      return r
    } catch (e) {
      // SIN la contraseña no hay forma de envolverle su llave, y esto pasa por caminos
      // donde no hay a quién pedírsela: un servicio que acaba de registrar su llave de
      // cifrado llega por el proxio, no por una consola. Antes se perdía en un `.catch`
      // del que llamaba y el servicio se quedaba sin variables SIN QUE NADIE SE ENTERARA
      // — el modo de fallo que más caro sale aquí. Se dice y se audita; la deuda no se
      // anota: se CALCULA (`secretDebts`), así no hay nota que se quede vieja cuando la
      // salde un hermano o el abrir la bóveda.
      log(`[vault] ${owner}: could not hand out its key (${e.message}); its members will not read their variables until a sibling hands it out or the vault is opened`)
      audit('secret.rewrap-due', { owner, reason: e.message })
      throw e
    }
  }

  /**
   * Escribir NO pide la frase (§8.1): el sobre se sella con las públicas de quien lo va
   * a leer. `by` es el aparato que lo escribió, y va al histórico.
   */
  async function setSecret (ns, key, value, isPublic, { by = null } = {}) {
    await secrets.set(ns, key, value, isPublic, { by })
    await settleDebts(`ns:${ns}`, () => nsMembers(ns))
    audit('secret.set', { ns, key }); scheduleNotice(ns)
  }

  /**
   * SALDAR LAS DEUDAS DEL PERFIL, con la frase en la mano. Es lo que hay que llamar tras
   * desbloquear: heredarle a un aparato nuevo lo que ya estaba guardado, y rotar de
   * verdad el cajón del que salió alguien. Las dos cosas exigen ABRIR, y abrir es lo
   * único que la frase guarda (§8.3).
   *
   * No lanza: devuelve qué pasó con cada cajón, porque una deuda que no se puede saldar
   * tiene que seguir viéndose en la lista en vez de tumbar la operación entera.
   */
  /**
   * PIDE AL SERVICIO QUE REPARTA la llave de su cajón a un miembro nuevo (§8.11).
   *
   * Es la única forma de completar a un aparato sin la frase y sin que nadie guarde
   * llaves de más: la bóveda no puede abrir la CEK, pero el servicio que la consume la
   * tiene abierta, y re-envolverla no le da ningún poder que no tuviera.
   *
   * La bóveda manda su propia envoltura de esa generación —la del servicio, que él ya
   * podía abrir— junto al ACTA firmada. El servicio saca de ahí la pública del
   * destinatario y contesta con la envoltura nueva, que se guarda con `putWrap`, que
   * solo AÑADE. Si el servicio no está encendido, la deuda se queda a la vista.
   *
   * @returns {Promise<{ done: number, asked: number }>}
   */
  async function delegateRewrap (owner, targetPub, { timeoutMs = 15000 } = {}) {
    const ns = owner.startsWith('ns:') ? owner.slice(3) : null
    if (!ns) return { done: 0, asked: 0 }
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record) return { done: 0, asked: 0 }
    // Quien puede repartir: un miembro de ESE cajón que no sea el propio destinatario.
    const helpers = (record.members || []).filter((m) => m.cn === ns && m.pub !== targetPub && m.encPub)
    const pending = secrets.wrapsToShare(owner, targetPub, helpers[0]?.pub || '')
    if (!helpers.length || !pending.length) return { done: 0, asked: 0 }

    let done = 0
    for (const gen of pending) {
      const body = { op: 'rewrap', owner, gen: gen.gen, wrap: gen.mine, target: targetPub, acta: record, ts: Date.now() }
      const { signature } = await identity.signData(body)
      const answer = new Promise((resolve) => {
        const off = onRewrapOk((d) => {
          if (d.owner !== owner || d.gen !== gen.gen || d.target !== targetPub) return
          off(); resolve(d.wrap)
        })
        setTimeout(() => { off(); resolve(null) }, timeoutMs).unref?.()
      })
      try { client.sendByPubkey(helpers[0].pub, { type: MSG.REWRAP, body, signature }) } catch (e) {
        log(`[vault] ${owner}: could not ask for the key to be handed out (${e.message})`)
        continue
      }
      const wrap = await answer
      if (!wrap) continue
      try { secrets.putWrap(owner, gen.gen, targetPub, wrap); done++ } catch (e) {
        log(`[vault] ${owner}: the handed key was refused (${e.message})`)
      }
    }
    if (done) {
      audit('secret.delegated', { owner, target: await deviceIdOf(targetPub).catch(() => null), gens: done })
      log(`[vault] ${owner}: ${done} key(s) handed out by its own service`)
    }
    return { done, asked: pending.length }
  }

  async function resealAll (adminKey = null) {
    const out = { drawers: 0, wrapped: 0, dropped: 0, sinLlave: [] }
    for (const owner of secrets.owners?.() || []) {
      const before = new Set(secrets.recipientsIn(owner))
      const members = await recipientsOf(owner)
      try {
        const r = await secrets.rewrap(owner, members, adminKey, { exact: true })
        const after = new Set(secrets.recipientsIn(owner))
        out.drawers++
        out.wrapped += r?.wrapped || 0
        out.dropped += [...before].filter((p) => !after.has(p)).length
        for (const p of r?.sinLlave || []) out.sinLlave.push(p)
      } catch (e) {
        log(`[vault] ${owner}: could not reseal (${e.message})`)
      }
    }
    if (out.dropped) audit('secret.reseal', { drawers: out.drawers, dropped: out.dropped })
    return out
  }

  async function settleSecretDebts (adminKey = null) {
    const out = {}
    // Las deudas ANOTADAS más las que se ven MIRANDO: un aparato puede quedarse sin
    // envoltura sin que nadie llegara a anotar nada (basta con que el apunte se pierda
    // por un camino que no pase por `spreadKey`), y entonces `settle` contestaba «nada
    // pendiente» mientras el servicio repetía en su log que no podía leer. Se calcula,
    // que es barato y no depende de que alguien se acordara de apuntarlo.
    const debts = new Set(Object.keys(rotationsDue()))
    for (const m of await incompleteMembers()) for (const owner of Object.keys(m.owners)) debts.add(owner)

    for (const owner of debts) {
      const k = owner.slice(owner.indexOf(':') + 1)
      // Los destinatarios de un cajón no son solo quien lo consume: también quien lo
      // administra (`recipientsOf`). Envolver solo para los primeros dejaba a la consola
      // sin poder destapar lo que ella misma acababa de saldar.
      const members = await recipientsOf(owner)
      try { out[owner] = await spreadKey(owner, members, adminKey) } catch (e) {
        // Sin frase, el último recurso es pedírselo a quien sí puede: el propio servicio.
        let delegated = 0
        for (const m of await incompleteMembers()) {
          if (!m.owners[owner]) continue
          delegated += (await delegateRewrap(owner, m.pub).catch(() => ({ done: 0 }))).done
        }
        out[owner] = delegated ? { delegated } : { error: e.message }
      }
    }
    return out
  }

  /**
   * Si este cajón quedó a deber un re-envoltorio o una rotación, se intenta saldar ahora.
   * Sin frase solo se puede en un perfil que no tiene contraseña —ahí la copia de
   * recuperación se abre con la llave de la máquina—, y en uno que sí la tiene se queda
   * anotado, que es lo que las listas enseñan. No se propaga el error: la variable YA se
   * guardó, y el que escribe no tiene por qué enterarse de una deuda vieja.
   */
  async function settleDebts (owner, membersFn) {
    const ns = owner.startsWith('ns:') ? owner.slice(3) : null
    const owed = (ns && store.getSetting(`rotate-due:${ns}`)) ||
      (await incompleteMembers()).some((m) => m.owners[owner])
    if (!owed) return null
    try { return await spreadKey(owner, await membersFn(), null) } catch (_) { return null }
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
  async function applySecrets (ns, items, { by = null } = {}) {
    const list = assertItems(items)
    const changed = []
    await secrets.batch(async () => {
      for (const it of list) {
        if (it.op === 'rm') {
          if (await secrets.delete(ns, it.key)) { audit('secret.rm', { ns, key: it.key }); changed.push(it.key) }
        } else {
          await secrets.set(ns, it.key, it.value, it.public, { by })
          audit('secret.set', { ns, key: it.key })
          changed.push(it.key)
        }
      }
    })
    if (changed.length) {
      await settleDebts(`ns:${ns}`, () => nsMembers(ns))
      scheduleNotice(ns)
    }
    return changed
  }

  /** Lo mismo para el cajón de UN aparato (el aviso va solo a él). */
  async function applyDeviceSecrets (pub, items, { by = null } = {}) {
    const list = assertItems(items)
    const m = await requireService(pub)
    const changed = []
    await secrets.batch(async () => {
      for (const it of list) {
        if (it.op === 'rm') {
          if (await secrets.deleteDevice(pub, it.key)) changed.push(it.key)
        } else {
          await secrets.setDevice(pub, it.key, it.value, it.public, { by })
          changed.push(it.key)
        }
      }
    })
    if (changed.length) {
      await settleDebts(`dev:${pub}`, async () => [m].filter(Boolean))
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

  async function setDeviceSecret (pub, key, value, isPublic, { by = null } = {}) {
    const m = await requireService(pub)
    await secrets.setDevice(pub, key, value, isPublic, { by })
    await settleDebts(`dev:${pub}`, async () => [await memberOf(pub)].filter(Boolean))
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
    identity, client, store, threads, secrets, master, fingerprint: fp, dir,
    startPairing: desk.startPairing,
    stopPairing: desk.stopPairing,
    listPending: desk.listPending,
    // Cajones con aprobación por uso (`approvals.js`).
    // Aparatos que piden aprobación al recibir claves (`approvals.js`).
    needsApproval,
    setApproval,
    supervised: () => readSupervised(),
    // La bóveda de contraseñas (`passwords.js`). Aquí SÍ se lista: es donde está la
    // llave. Lo que no puede es listarla un aparato.
    passwordDevices,
    passwordsVault: () => passwords?.vault || null,
    listApprovals: () => approvals.list(),
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
      if (m?.cn) {
        await spreadKey(`ns:${m.cn}`, await nsMembers(m.cn), adminKey).catch(async (e) => {
          log('[vault] could not hand the key to the new service:', e.message)
          // Sin la frase la bóveda no puede envolvérsela… pero un HERMANO suyo sí: otro
          // servicio del mismo cajón ya tiene la llave abierta (§8.11). Si contesta, el
          // recién llegado arranca completo; si no hay ninguno encendido, la deuda queda
          // a la vista y se salda al abrir la bóveda.
          const r2 = await delegateRewrap(`ns:${m.cn}`, m.pub).catch(() => ({ done: 0 }))
          if (!r2.done) log(`[vault] ns:${m.cn}: nobody could hand it the key — it stays in debt until the vault is opened`)
        })
      }
      await notifyMembers('enrolled', { deviceId: r?.deviceId || null, by: 'pc' })
      return r
    },
    rejectDevice: (deviceId) => desk.reject(deviceId),
    // El mostrador que atiende a la consola remota. Se expone para poder probar la
    // frontera de verdad (que el valor de una privada no salga ni dentro del sobre).
    vars: varsDesk,
    setSecret, deleteSecret, listSecrets, setSecretVisibility, openSecrets,
    // Sella un `secrets.json` v3 entero. Es el punto de no retorno del despliegue y
    // por eso es una operación con nombre propio, no algo que ocurra de refilón al
    // desbloquear: deja `secrets.json.v3.bak` para poder volver.
    /**
     * Convierte el archivo de secretos al formato nuevo. `membersOf` es opcional y lo
     * normal es NO pasarlo: por defecto se usa la misma lista de destinatarios que
     * cualquier escritura —los servicios del cajón MÁS los aparatos que administran—.
     *
     * Pasarla a mano fue un error real: la conversión envolvía solo a los servicios, y
     * entonces la consola del dueño no podía ver nada de lo que ya había, aunque el
     * diseño dice que sí (§8.2). Lo de siempre: dos sitios decidiendo lo mismo.
     */
    resealAll,
    delegateRewrap,
    incompleteMembers,
    migrateSecrets: (membersOf, adminKey) => secrets.migrate(
      membersOf || ((owner) => recipientsOf(owner)), adminKey
    ),
    settleSecretDebts,
    revealSecret: (owner, key, adminKey) => secrets.reveal(owner, key, adminKey),
    secretHistory: (owner, key) => secrets.history(owner, key),
    revealSecretHistory: (owner, key, ts, adminKey) => secrets.revealHistory(owner, key, ts, adminKey),
    revertSecret: (owner, key, ts, opts) => secrets.revert(owner, key, ts, opts),
    // Cambiar la contraseña del perfil obliga a volver a cerrar la copia maestra con
    // la llave nueva, o los secretos quedarían ilegibles. No toca los sobres.
    rekeySecrets: (oldKey, newKey) => secrets.rekeyRecovery(oldKey, newKey),
    setDeviceSecret, deleteDeviceSecret, listDeviceSecrets, setDeviceSecretVisibility,
    applySecrets, applyDeviceSecrets,
    listDevices: () => identity.listDelegations(),
    // Acta del perfil (quién es del perfil y qué puede cada uno): lo que muestran
    // `dotrino-vault members` y la consola de vault.dotrino.com.
    profileMembers: () => identity.profileMembers(),
    // Los namespaces que quedaron a deber una rotación (se fue un miembro y no se pudo
    // rotar su llave). Lo enseñan `secret list` y la consola: si no se ve, no se salda.
    rotationsDue,
    secretDebts,
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
      clearInterval(approvalsSweeper)
      for (const t of pendingNotices.values()) clearTimeout(t)
      pendingNotices.clear()
      try { client.close() } catch (_) {} identity.destroy()
    }
  }
}
