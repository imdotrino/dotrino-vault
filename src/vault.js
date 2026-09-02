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
import { createAdminDesk, authorBody } from '../lib/src/admin.js'
import { shouldNotifyRevoked } from '../lib/src/revocation.js'
import { createTransport, masterPubkeyOf } from './transport.js'
import { startSealersPublisher } from './sealers.js'
import { assertKeyOwnsDir } from './keyowner.js'
import { openStore } from './store.js'
import { openThreadStore, STORE_READ_METHODS, PROFILE_EDIT_METHODS } from './threadStore.js'
import { openSecretsStore, assertVar, RECOVERY as RECOVERY_WRAP } from './secretsStore.js'
// `PENDING_TTL_MS` se usa abajo, al esperar la firma del aprobador: sin importarlo, esa
// espera reventaba con un ReferenceError y la aprobación del mostrador de contraseñas no
// llegaba a existir. Solo se veía por ese camino —el único que lo usa—, y no había prueba
// que lo recorriera hasta que la hubo (dotrino-test, smoke:demonio, 2026-08-30).
import { createApprovals, PENDING_TTL_MS } from './approvals.js'
import { makeSealer } from './sealer.js'
import { openSealKeys } from './sealKey.js'
import { openCommKey, COMM_CN, COMM_CAPS } from './commKey.js'
import { seal } from '../lib/src/sealed.js'
import { dataDir, ensureDir } from './paths.js'
import { atRestFor, kekFor, migrateFile, encryptText, decryptText } from './atrest.js'
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
export async function startVault ({ dir = dataDir(), proxyUrl, log = console.log, onEnrollChallenge, isLocked = () => false, hasPassword = () => true, deriveAdminKey = null, openKey = null, forAdoption = false, onAdopted } = {}) {
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
  /**
   * EL CANDADO DE LA MAESTRA. La mitad privada se guarda sellada con la llave que sale de
   * la contraseña del perfil (`openKey`), no con la de la máquina: cerrada, la maestra no
   * está en memoria y no hay con qué sacarla del disco.
   *
   * `open` devuelve `null` con el perfil cerrado, y el pilar entonces carga la identidad
   * SIN con qué firmar — se sabe quién eres, no se puede hablar por ti. Un perfil sin
   * contraseña no tiene `openKey`: se queda como estaba, bajo la llave de máquina, y la
   * consola ya lo dice en voz alta.
   */
  const keyLock = {
    seal: async (texto) => { const k = openKey?.(); return k ? encryptText(texto, k) : null },
    open: async (blob) => { const k = openKey?.(); if (!k) return null; try { return decryptText(blob, k) } catch (_) { return null } }
  }
  const identity = await Identity.connect({ dir, atRest: atRestFor(dir), keyLock })
  // ESTE DIRECTORIO ES DE ESTA LLAVE. Es lo único que hay que proteger cuando varias
  // bóvedas viven en un mismo disco: cada una con el suyo, para que nunca se mezclen.
  assertKeyOwnsDir(dir, identity.me?.publickey || null)
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
  const commKey = openCommKey(dir)
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
  /**
   * ¿ESTE APARATO TIENE QUE PEDIR PERMISO PARA RECIBIR CLAVES PRIVADAS?
   *
   * Lo dice el ACTA, con el permiso `unattended`: quien lo tiene se las lleva solo; quien
   * no, espera a que un aparato con `approve` lo firme.
   *
   * Antes era al revés y vivía aquí: una lista local de «estos SÍ piden permiso», así que
   * un aparato nuevo nacía pudiendo llevarse las claves y nadie elegía eso — se elegía por
   * omisión. Ahora hay que conceder a propósito quién puede llevárselas solo, y **si falta
   * el dato se pide permiso**, que es lo que hay que hacer cuando no se sabe (dueño,
   * 2026-09-01).
   *
   * Y al estar en el acta lo respeta cualquier bóveda de la cuenta, se ve en la pantalla de
   * permisos como los demás, y se quita quitándolo — sin acordarse de un registro escondido
   * en una máquina.
   */
  function needsApproval (pub, record) {
    if (!record) return true          // sin acta no se decide que sí: se pide permiso
    return !Acta.memberCan(record, pub, 'unattended')
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
    recipients: (owner, opts) => recipientsOf(owner, opts),
    // La FIRMA del sobre: dice que salió de esta bóveda y con qué acta (§8.8).
    signer: (body) => signSeal(body),
    // CON QUÉ se cierra la copia de recuperación cuando quien llama no trajo la frase:
    // la llave del perfil si está ABIERTO, y si no la de la máquina. El orden importa —
    // un perfil CON contraseña no se abre con la llave de la máquina, así que sin lo
    // primero un aparato enrolado con la bóveda abierta se quedaba sin su cajón y solo
    // se enteraba al arrancar (dueño, 2026-08-31).
    defaultKey: () => openKey?.() || new Uint8Array(kekFor(dir))
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
    // CON EL PERFIL ABIERTO. Estrenar la llave de sellado SELLA EL ACTA, y una bóveda
    // cerrada no sella nada — la misma regla que el bloque de abajo. Cerrada se queda sin
    // llave y los sobres salen sin firma (lo que ya pasaba antes de §8.8), y se arregla sola
    // la primera vez que alguien abra el perfil.
    if (info?.isMaster && acta && !isLocked() && (!acta.sealPub || !sealKeys.has(acta.sealPub))) {
      const r = await identity.rotateSealKey()
      // Sin `%s`: este `log` va con un prefijo por delante, así que el formato no es lo
      // primero y `console.log` no lo sustituye (salía «record #%s 2»).
      log(`[vault] new sealing key in record #${r.seq}`)
    }
  } catch (e) { log('[vault] could not set up the sealing key:', e.message) }

  /**
   * LA LLAVE DE COMUNICACIÓN, dentro del acta.
   *
   * La maestra sella el acta y reenvuelve sobres; hablar por la red no es suyo. Esta es la
   * que se identifica ante el proxio, y su autoridad la dice el ACTA: entra como un miembro
   * más, con `cn: 'vault'`, así que el acta la trata como un servicio del perfil — puede
   * hablar por la bóveda, no firmar por la persona.
   *
   * Solo se puede meter con el perfil ABIERTO (admitir un miembro es sellar el acta, y eso
   * es de la maestra). Con el perfil cerrado no se toca nada: si ya está, se usa; y si no,
   * `identify` se repliega a la maestra y lo dice. Por eso una bóveda que se actualiza
   * tiene que abrirse UNA vez, y a partir de ahí ya puede vivir cerrada.
   */
  try {
    const info = await identity.profileActa?.()
    const acta = info?.acta
    // CON EL PERFIL ABIERTO, y `isLocked()` es la pregunta correcta — no `masterLocked`.
    //
    // Se coló así: en la PRIMERA arrancada tras actualizar, la maestra todavía está guardada
    // en claro (se sella al abrir el perfil), o sea que `masterLocked` es `false` aunque el
    // perfil esté cerrado. Con ese guardián, la bóveda de producción admitió su llave de
    // comunicación y SELLÓ UN ACTA NUEVA (#76 → #77) estando cerrada — justo lo que la regla
    // prohíbe, y encima rotando de paso la llave de sellado sin que nadie lo pidiera.
    if (acta && !isLocked() && !identity.masterLocked) {
      const pub = await commKey.ensure()
      const yaEsta = (acta.members || []).some((m) => m?.pub === pub)
      if (!yaEsta && info?.isMaster) {
        await identity.admitMember({ pub, label: 'esta bóveda', cn: COMM_CN, caps: [...COMM_CAPS] })
        log('[vault] this vault is now a member of its own record: it talks with its own key, not the master one')
      }
    }
  } catch (e) { log('[vault] could not put the communication key in the record:', e.message) }

  const { client } = await createTransport({ identity, dir, url: proxyUrl, commKey, log })

  // El registro público de cadenas de selladores: deposita, si hay a dónde, los eslabones
  // que le dicen a un tercero si esta cuenta sigue sellada por quien él cree. Ver
  // `sealers.js` — es una comodidad para quien lee, nunca una dependencia de la bóveda.
  startSealersPublisher({ identity, client, log })

  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set(revoked.map((r) => r.nonce))
  }

  /**
   * CONTESTAR SIN MATAR LA CONEXIÓN.
   *
   * El proxio corta los frames a 1 MB (`maxPayload`), y `ws` no «descarta» el que se pasa:
   * CIERRA EL SOCKET con un 1009. La bóveda se queda muda, sin un solo error en su log, y
   * desde fuera se ve igual que si estuviera apagada. Eso ya pasó y duró tres días.
   *
   * Así que una respuesta que no quepa no se manda: se sustituye por un error, que sí cabe.
   * Una bóveda que dice «no cabe» se arregla; una muda no se puede ni diagnosticar.
   */
  const reply = (to, obj) => {
    try {
      const bytes = Buffer.byteLength(JSON.stringify(obj))
      if (bytes > MAX_REPLY_BYTES) {
        log(`[vault] the reply to ${obj?.type} does not fit (${bytes} bytes > ${MAX_REPLY_BYTES}): sending an error instead of killing the connection`)
        audit('reply-too-big', { type: obj?.type || null, bytes })
        return client.send(to, { type: MSG.ERROR, error: `reply too big (${bytes} bytes): ask for less at a time` })
      }
      client.send(to, obj)
    } catch (e) { log('[vault] could not reply:', e.message) }
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

  /**
   * EL ACTA MANDA, EL PAPEL SOLO ACOMPAÑA. Se pregunta DESPUÉS de verificar la cadena y
   * ANTES de hacer nada, en todos los mostradores.
   *
   * El certificado dice a qué se comprometió esta bóveda cuando conectó el aparato; el
   * acta dice lo que puede HOY. Y no coinciden: `caps <ID> -lee` sella el acta pero no
   * reemite ni revoca el papel, que vive hasta 30 días. Sin esto, quitarle un permiso a un
   * aparato no se lo quitaba — seguía leyendo, guardando o firmando un mes más.
   *
   * Va por `memberCanScope` (el pilar) y no a mano en cada sitio: la regla es la misma en
   * las dos bóvedas y se comprobaba mal en las dos.
   *
   * @returns {boolean} `true` si puede seguir; si no, ya contestó el «no».
   */
  /**
   * CON QUÉ SE JUZGA UN PAPEL: el acta que tiene esta bóveda.
   *
   * Sustituye a `trustedIssuer: master`, que comparaba contra UNA llave fija y por eso el
   * multivault no podía existir — una segunda selladora sellaba el acta y luego sus papeles
   * los rechazaban los diez mostradores. Ahora se compara contra la lista que dice el acta.
   *
   * Sin acta se devuelven nulos a propósito: `verifyDelegation` responde `no-acta` y el
   * mostrador deniega. Es lo contrario de un repliegue — no hay con qué decidir, así que no
   * se decide que sí.
   */
  async function contextoActa () {
    const acta = (await identity.profileActa?.().catch(() => null))?.acta || null
    if (!acta) return { actaSeq: null, sealers: null }
    return { actaSeq: acta.seq, sealers: Acta.sealersOf(acta) }
  }

  async function actaAllows (from, chk, scope, what) {
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    // SIN ACTA NO SE ATIENDE. Esto era `if (!record || puede())`, o sea: sin acta, pasa. Un
    // repliegue no dice «por si falta el dato», dice «si falta el dato, di que sí» — y el
    // acta falta justo cuando algo se rompió (un archivo a medias, un `catch` que devolvió
    // null), que es cuando menos hay que fiarse. Toda cuenta tiene acta desde hace versiones.
    if (!record) {
      audit('rejected', { what, reason: 'sin-acta' })
      reply(from, { type: MSG.ERROR, error: 'unauthorized: this vault has no record to decide with' })
      return false
    }
    if (Acta.memberCanScope(record, chk.device, scope)) return true
    audit('rejected', { what, reason: 'acta' })
    reply(from, { type: MSG.ERROR, error: 'unauthorized: acta — this member no longer has that permission' })
    return false
  }

  // --- handleSign / handleGet: idénticos (verifyChain de la cadena D←maestra) ---
  async function handleSign (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'sign', reason: 'stale' }); return staleReply(from) }
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.SIGN, ...(await contextoActa()), revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'sign')

    // MANDA EL ACTA, NO EL PAPEL. Esto miraba solo el certificado, y era el único
    // mostrador que lo hacía —`approve` y los secretos ya preguntaban al acta—. El agujero
    // que dejaba: `caps <ID> -firma` quita `sign` del acta pero NO reemite ni revoca el
    // cert del aparato, que sigue diciendo `vault:sign` hasta 30 días. Entonces su
    // `signData` local veía que ya no puede y se lo PEDÍA a la bóveda… que decía que sí.
    // O sea que quitarle el permiso de firmar no se lo quitaba: lo cambiaba de firmar él
    // a que firmaras tú por él.
    if (!await actaAllows(from, chk, SCOPE.SIGN, 'sign')) return

    // Y CERRADA NO FIRMA NADA (dueño, 2026-08-31). La regla de antes —«el daemon sigue
    // firmando con el perfil bloqueado, para que un reinicio no deje las apps muertas»— es
    // ANTERIOR AL MODELO DE SOBRES y queda derogada: con los sobres la bóveda no necesita
    // firmar nada para servir. Lo que hace abierta es rehacer los sobres.
    //
    // Y las apps no se quedan muertas por esto: un aparato al que el acta le da `sign`
    // firma con SU llave y no pasa por aquí (ver `signData` en el pilar). Leer y guardar
    // tampoco pasan por aquí, y siguen funcionando con el candado echado.
    if (isLocked()) {
      audit('rejected', { what: 'sign', reason: 'locked' })
      return reply(from, { type: MSG.ERROR, error: 'vault locked: the master key does not sign while the vault is closed' })
    }
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
      expectedScope: SCOPE.READ, ...(await contextoActa()), revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'get')
    if (!await actaAllows(from, chk, SCOPE.READ, 'get')) return
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
    let chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.STORE, ...(await contextoActa()), revoked })
    if (!chk.ok && STORE_READ_METHODS.has(d.method)) {
      chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.READ, ...(await contextoActa()), revoked })
    }
    if (!chk.ok) return denyChain(from, chk, p, 'store')
    // El scope que valió es el que hay que preguntarle al acta: un método de lectura pudo
    // pasar con `read` en vez de `store`, y exigirle `store` al acta lo rechazaría a pesar
    // de tener permiso para lo que pidió.
    if (!await actaAllows(from, chk, chk.scope === SCOPE.READ ? SCOPE.READ : SCOPE.STORE, 'store')) return
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
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, ...(await contextoActa()), revoked: await revocationSet() })
    if (!chk.ok) return denyChain(from, chk, p, null)
    // DOS RESPUESTAS, PORQUE SON DOS PREGUNTAS DISTINTAS.
    //
    // Un SERVICIO pregunta aquí para enterarse de dos cosas suyas: si le revocaron el papel
    // y cuál es el acta vigente. Eso no es tu inventario y no puede exigir `lee` — se lo
    // exigí, y en producción dejó ciegos a los servicios (`rejected devices/acta` en la
    // bitácora del VPS, dos veces, antes de que lo viera).
    //
    // La LISTA DE APARATOS sí es el perfil —cómo se llama cada máquina y qué puede— y esa
    // sigue pidiendo `lee`. Antes no preguntaba nada, así que un aparato al que le quitaste
    // el permiso seguía viéndolo todo hasta que su papel caducara.
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    const puedeVerTodo = !!record && Acta.memberCanScope(record, chk.device, SCOPE.READ)
    const { issued, revoked } = await identity.listDelegations()
    if (!puedeVerTodo) {
      if (!record) {
        audit('rejected', { what: 'devices', reason: 'sin-acta' })
        return reply(from, { type: MSG.ERROR, error: 'unauthorized: this vault has no record to decide with' })
      }
      audit('devices', { device: await deviceIdOf(chk.device).catch(() => null), solo: 'revocaciones' })
      return reply(from, { type: MSG.DEVICES_RESULT, devices: [], revoked, acta: record })
    }
    // El acta viaja con la lista: así cada dispositivo se entera de los cambios de
    // política (quién manda, quién puede qué) sin un canal aparte.
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
    // Si tras podar la cadena SIGUE sin caber, no se avisa y se manda igual —eso mataba la
    // conexión—: se devuelve tal cual y `reply` lo sustituye por un error. El aviso de aquí
    // sobra porque el de `reply` dice lo mismo y además dice qué hizo.
    return msg
  }

  // RENOVACIÓN automática: un dispositivo con cert VIGENTE y no revocado pide un
  // cert fresco (misma sub-clave y scope) sin QR ni aprobación — sigue siendo el
  // mismo dispositivo enrolado, solo extiende la ventana. Un cert vencido o
  // revocado NO puede renovarse (ahí sí toca re-emparejar con aprobación).
  async function handleRenew (from, p) {
    if (!isFresh(p.data)) { audit('rejected', { what: 'renew', reason: 'stale' }); return staleReply(from) }
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, ...(await contextoActa()), revoked: await revocationSet() })
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
    // Sin acta no se renueva: caer al scope del papel viejo es reconceder a ciegas lo que
    // el acta ya no dice. Un repliegue así no protege de nada, tapa.
    if (!record) {
      audit('rejected', { what: 'renew', device: await deviceIdOf(p.cert.sub), reason: 'sin-acta' })
      return reply(from, { type: MSG.ERROR, error: 'unauthorized: this vault has no record to decide with' })
    }
    const scope = Acta.memberScopes(record, p.cert.sub)
    if (!scope.length) {
      audit('rejected', { what: 'renew', device: await deviceIdOf(p.cert.sub), reason: 'not-a-member' })
      return reply(from, { type: MSG.ERROR, error: 'unauthorized: the record no longer lists this device' })
    }
    // RENOVAR NO RETIRA EL PAPEL ANTERIOR (`supersede: false`), y esto costó dos servicios.
    //
    // Retirarlo al emitir parece limpio —un aparato, un papel— pero convierte cualquier
    // renovación que falle DESPUÉS de emitirse en una expulsión permanente: la máquina se
    // queda con el papel viejo, que acaba de quedar revocado, y ya no puede ni pedir otro.
    // Pasó dos veces en la migración del VPS (el registro de selladores y el bot social):
    // el papel nuevo salió, la respuesta no llegó a guardarse, y al reintentar la bóveda
    // contestaba `unauthorized: revoked`. Re-emparejar a mano, con TTY, por una renovación.
    //
    // Que convivan dos papeles del mismo aparato ya no es el problema que era: ninguno
    // vence, pero lo que pueden hacer lo decide el ACTA en cada mostrador, así que el
    // viejo no autoriza nada que el nuevo no autorice. Y quitar el aparato de verdad sigue
    // siendo `revokeDevice`, que los retira TODOS de una vez.
    const { cert } = await identity.signDelegation(p.cert.sub, scope, { label: prev?.label || '', supersede: false })
    audit('renew', { device: await deviceIdOf(p.cert.sub), label: prev?.label || '', scope, seq: cert.seq })
    log(`[vault] cert renewed for ${await deviceIdOf(p.cert.sub)} · record #${cert.seq}`)
    // El acta viaja con el papel: sin ella quien lo recibe no puede comprobar que lo firmó
    // una selladora del perfil, que es lo que sustituyó a «lo firmó la maestra».
    reply(from, { type: MSG.RENEWED, cert, acta: record })
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
      expectedScope: secretsScope(ns), ...(await contextoActa()), revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'enckey')
    // MISMA FRONTERA QUE SERVIR EL CAJÓN, y por la misma razón: esto no solo apunta una
    // llave pública, acto seguido le ENVUELVE la del cajón (`spreadKey`, más abajo). Aquí
    // solo se miraba el certificado, así que a un aparato al que el acta ya le había
    // quitado `secrets` se le entregaba la llave igual, hasta 30 días. Es el mismo fallo
    // que se cerró en `handleSign`, en otro mostrador.
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record || !Acta.memberCanReadSecrets(record, chk.device, ns)) {
      audit('rejected', { what: 'enckey', ns, reason: record ? 'cn' : 'sin-acta' })
      return reply(from, { type: MSG.ERROR, error: `unauthorized: cn — the record does not recognise this member as the "${ns}" service` })
    }
    try {
      await identity.setMemberEncPub({ pub: chk.device, encPub: p.data.encPub })
      audit('enckey', { device: await deviceIdOf(chk.device).catch(() => null), ns })
      log(`[vault] ${ns}: encryption key registered for ${await deviceIdOf(chk.device).catch(() => '????-????')}`)
      // Ya puede recibir sobres: se le envuelve la llave de sus cajones en el acto, o
      // seguiría sin poder abrir nada hasta la siguiente escritura.
      //
      // Va por `recipientsOf` —el único sitio que sabe quién debe tener envoltura de un
      // cajón—, que incluye a los SELLADORES. Con `nsMembers` se envolvía solo para los del
      // ns y los selladores se quedaban con lo viejo (dueño, 2026-09-01).
      //
      // Y su cajón PROPIO también: un aparato con variables suyas se quedaba sin poder
      // abrirlas, que es el mismo agujero por otra puerta.
      for (const owner of [`ns:${ns}`, `dev:${chk.device}`]) {
        await spreadKey(owner, (esPublica) => recipientsOf(owner, { public: esPublica }))
          .catch((e) => log(`[vault] ${owner}: could not hand it the key: ${e.message}`))
      }
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
      expectedScope: secretsScope(ns), ...(await contextoActa()), revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'secrets')
    // FRONTERA DEL CN (acta): además del scope del cert, el acta tiene que decir que este
    // miembro es el servicio `ns`. Así el límite no depende solo de qué cert se emitió: la
    // llave del proxy no ve nada que no sea del proxy, y está escrito donde se puede comprobar.
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record || !Acta.memberCanReadSecrets(record, chk.device, ns)) {
      audit('rejected', { what: 'secrets', ns, reason: record ? 'cn' : 'sin-acta' })
      return reply(from, { type: MSG.ERROR, error: `unauthorized: cn — the record does not recognise this member as the "${ns}" service` })
    }
    // APROBACIÓN: si este APARATO está marcado (`dotrino-vault approval <ID> on`), liberarle
    // claves privadas exige el visto bueno de un aparato con `approve` — en CADA petición,
    // que para un servicio bien hecho es una por arranque: pide al (re)iniciar, se queda las
    // claves en memoria y no vuelve a pedir. El pedido se apunta, se avisa a quien aprueba y se
    // contesta «pendiente»; la respuesta de verdad sale cuando el teléfono firme
    // (`handleApproval`), sellada a la misma `ek`.
    // SOLO PÚBLICAS: NO SE PIDE APROBACIÓN (dueño, 2026-09-01).
    //
    // La aprobación existe para soltar CLAVES PRIVADAS. Una variable pública está guardada
    // en claro —eso es lo que significa marcarla— y ya la ve cualquiera que administre, así
    // que hacer sonar el teléfono del dueño para entregarla es molestarlo por nada.
    //
    // Lo que NO se relaja: quien pide sigue teniendo que ser un miembro identificado, con su
    // papel y con el `cn` de este cajón (las dos comprobaciones de arriba). Y el filtro lo
    // hace la BÓVEDA (`bundleFor({ publicOnly })`), no el que pide: si mandáramos todo y el
    // cliente eligiera, pedir «solo públicas» sería la manera de saltarse la aprobación.
    const publicOnly = p.data?.publicOnly === true
    if (!publicOnly && needsApproval(chk.device, record)) {
      const deviceId = await deviceIdOf(chk.device).catch(() => null)
      const label = (record?.members || []).find((m) => m.pub === chk.device)?.label || ''
      const pend = approvals.request({ ns, device: chk.device, deviceId, label, ek: p.data.ek })
      audit('secrets.pending', { device: deviceId, ns, id: pend.id })
      log(`[vault] ${ns}: ${deviceId || '????-????'} is waiting for approval (${pend.id})`)
      const body = { op: 'secrets.pending', ns, id: pend.id, exp: pend.exp, ts: Date.now() }
      // El acta viaja también aquí: es con lo que el agente sabe qué llave podía firmar
      // esto. En `secrets.result` va dentro del sobre; en un «pendiente» no hay sobre.
      reply(from, { type: MSG.SECRETS_RESULT, body, seal: await sealOrFail(body), acta: record || null })
      await notifyApprovers(pend, record)
      return
    }
    let res
    try { res = await resultFor(ns, chk.device, p.data.ek, record, { publicOnly }) } catch (e) {
      return reply(from, { type: MSG.ERROR, error: 'secrets: invalid ek' })
    }
    audit('secrets', { device: await deviceIdOf(chk.device), ns, ...(publicOnly ? { publicOnly: true } : {}) })
    reply(from, { type: MSG.SECRETS_RESULT, ...res })
  }

  /** El bundle de `ns` para `devicePub`, sellado a su `ek` y firmado por la llave de sellado. */
  async function resultFor (ns, devicePub, ek, record, { publicOnly = false } = {}) {
    // Mientras el archivo siga en v3 el cable NO cambia: se mandan los valores como
    // siempre. Solo tras la migración viajan sobres, y entonces quien los abre es el
    // agente con su llave. Así el despliegue del daemon se deshace con un reinicio,
    // porque hasta el primer desbloqueo no ha cambiado nada de lo que ve nadie.
    const b = secrets.bundleFor(ns, devicePub, { publicOnly })
    // EL ACTA VIAJA CON EL BUNDLE (§8.8): es lo que le permite al agente comprobar que
    // los sobres los selló esta bóveda, y con qué llave —la que el acta nombra para el
    // `seq` con el que se firmaron—. No es un dato secreto: el acta es pública dentro
    // del perfil y el agente ya es miembro. Sin ella podría abrir igual, pero no sabría
    // de dónde salió lo que abre.
    // El acta va en LOS DOS caminos, también en el v3 heredado: ya no sirve solo para
    // decir de dónde salieron los sobres, sino para saber qué llave podía firmar esta
    // respuesta. Sin ella el agente no puede comprobar quién le contestó.
    const payload = b.legacy
      ? { secrets: Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v])), acta: record || null }
      : { sealed: b, acta: record || null }
    // LO QUE SE MANDA CON AGUJEROS, SE DICE. La bóveda sabe aquí mismo que este aparato no
    // tiene envoltura de tal variable —`missingFor` lo contesta—, y hasta hoy se callaba:
    // contestaba un bundle que el agente no podía abrir y el registro decía «aprobado»,
    // como si se hubiera servido. Desde fuera parecía que el pedido funcionaba y volvía a
    // aparecer una y otra vez. Falta la envoltura, y eso solo se arregla ABRIENDO la
    // bóveda; decirlo aquí es lo que convierte un bucle mudo en algo que se puede arreglar.
    if (!b.legacy && !publicOnly) {
      const faltan = [...secrets.missingFor(`ns:${ns}`, devicePub), ...secrets.missingFor(`dev:${devicePub}`, devicePub)]
      if (faltan.length) {
        const quien = await deviceIdOf(devicePub).catch(() => '????-????')
        audit('secrets.no-wrapping', { device: quien, ns, vars: faltan })
        log(`[vault] ${ns}: ${quien} has no wrapping for ${faltan.join(', ')} — open the vault (dotrino-vault unlock) so it hands it the key`)
      }
    }
    const enc = await seal({ ek, payload })
    const body = { op: 'secrets.result', ns, enc, ts: Date.now() }
    // LA MAESTRA NO FIRMA ESTO. Su trabajo es sellar el acta y reenvolver sobres; servir
    // no es suyo. Quien firma es la LLAVE DE SELLADO que el acta nombra (`sealPub`), la
    // misma que ya firma cada sobre — y por eso esto se puede servir con el perfil
    // bloqueado, y algún día desde una réplica que no tiene la maestra ni debe tenerla.
    return { body, seal: await sealOrFail(body) }
  }

  /**
   * Firma con la llave de sellado, o revienta. No hay repliegue a la maestra: si el acta
   * no nombra una llave de sellado que sea nuestra, esta bóveda no está en condiciones de
   * servir, y decirlo es mejor que servir firmado por quien no toca.
   */
  async function sealOrFail (body) {
    const s = await signSeal(body)
    if (!s) throw new Error('this vault has no sealing key named by the record: it cannot serve')
    return s
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
      expectedScope: SCOPE.APPROVE, ...(await contextoActa()), revoked: await revocationSet()
    })
    if (!chk.ok) return denyChain(from, chk, p, 'approval')
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record || !Acta.memberCan(record, chk.device, 'approve')) {
      audit('rejected', { what: 'approval', reason: record ? 'acta' : 'sin-acta' })
      return reply(from, { type: MSG.ERROR, error: 'unauthorized: acta — this member does not approve' })
    }
    const by = await deviceIdOf(chk.device).catch(() => null)
    const answer = async (body) => {
      body = { ...body, ts: Date.now() }
      reply(from, { type: MSG.SECRETS_RESULT, body, seal: await sealOrFail(body) })
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
      try { client.sendByPubkey(pend.device, { type: MSG.ERROR, error: `unauthorized: denied — the "${pend.ns}" request was denied from ${by}` }) }
      catch (e) { log(`[vault] ${pend.ns}: could not tell ${pend.deviceId} it was denied: ${e.message}`) }
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
    // EL FALLO NO SE TRAGA. Tragarlo era lo peor de este mostrador: la bóveda apuntaba
    // «aprobado», el que pedía no recibía nada, y no quedaba una sola línea que mirar —
    // así que el dueño aprobaba una y otra vez creyendo que el teléfono no llegaba.
    try { client.sendByPubkey(pend.device, { type: MSG.SECRETS_RESULT, ...res }) }
    catch (e) { log(`[vault] ${pend.ns}: approved, but the reply did not reach ${pend.deviceId}: ${e.message}`) }
    return answer({ op: 'approve.result', id, ok: true })
  }

  /**
   * Aviso a los aparatos que aprueban (cola del proxio → timbre nativo si están apagados).
   *
   * LA MAESTRA NO FIRMA ESTO, y es el fallo que dejaba el mecanismo entero inservible.
   * Avisar es SERVIR, y servir es trabajo de la llave de sellado —la maestra solo sella el
   * acta y reenvuelve los sobres al abrir (CLAUDE.md, «la maestra tiene DOS trabajos»)—.
   * Con `identity.signData` esto reventaba con «vault locked» en cada pedido, o sea SIEMPRE:
   * la bóveda vive cerrada, que es justamente para lo que sirve el candado. Y como reventaba
   * antes de mandar nada, el proxio no tenía a quién encolar y el teléfono NO TIMBRABA
   * NUNCA. El pedido solo se veía si al dueño se le ocurría abrir la app por su cuenta.
   *
   * El aviso no lleva nada que no esté ya en el pedido, y el timbre que sale de aquí sigue
   * sin contenido: quien lo recibe pregunta por la lista, no la lee del aviso.
   */
  async function notifyApprovers (pend, record) {
    try {
      const body = { ev: 'approval', id: pend.id, ns: pend.ns, deviceId: pend.deviceId, label: pend.label, exp: pend.exp, ts: Date.now() }
      const seal = await sealOrFail(body)
      const who = (record?.members || []).filter((m) => Acta.memberCan(record, m.pub, 'approve')).map((m) => m.pub)
      if (!who.length) log(`[vault] ${pend.ns}: nobody can approve (grant it with: dotrino-vault caps <ID> +aprueba)`)
      // EL FALLO NO SE TRAGA. Un aviso que no sale es un teléfono que no timbra, y eso
      // desde fuera se ve igual que «nadie ha aprobado todavía»: se espera para siempre
      // sin nada que mirar. Es el mismo cuidado que en `notifyMembers`.
      for (const pub of who) {
        try { client.sendByPubkey(pub, { type: MSG.ADMIN_EVENT, body, seal }) }
        catch (e) { log(`[vault] could not ring ${pub.slice(0, 24)}… about ${pend.ns}: ${e.message}`) }
      }
      log(`[vault] ${pend.ns}: rang ${who.length} approver(s) for ${pend.id}`)
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
      if (payload.type === MSG.ADMIN_EVENT) return await handleAdminEvent(payload)
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: e.message })
    }
  })

  /**
   * AVISO DE OTRA BÓVEDA de la misma cuenta (multivault). Trae el acta nueva y aquí se
   * ADOPTA, que es lo que hace que conceder un permiso surta efecto en la otra máquina en
   * vez de esperar a que renueve su cert.
   *
   * No se comprueba quién lo manda y no hace falta: `adoptActa` aplica §2.4.1 —firma,
   * encadenado, `seq` que no baja y desempate— así que un acta ajena o vieja se rechaza
   * sola. Fiarse del remitente sería la comprobación débil; fiarse del acta es la fuerte.
   */
  async function handleAdminEvent (payload) {
    const acta = payload?.acta
    if (!acta || typeof acta !== 'object') return
    try {
      const r = await identity.adoptActa?.(acta)
      if (r?.adopted) log(`[vault] adopted record #${acta.seq} announced by another vault (${r.reason})`)
      // Y el RECHAZO también se dice. Callarlo dejaría el peor fallo de todos: se concede
      // un permiso en una máquina, la otra no se entera, y no hay una sola línea que lo
      // explique — que es exactamente lo que costó encontrar esto.
      else log(`[vault] IGNORED the record #${acta.seq} announced by another vault: ${r?.reason || 'no reason given'}`)
    } catch (e) { log('[vault] could not adopt the announced record:', e.message) }
  }

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
      // EN VIVO, no del caché: conceder o quitar `unattended` tiene que surtir efecto en
      // el acto. Con el caché, la mesa de contraseñas seguía decidiendo con la foto del
      // último refresco — y en el sentido peligroso: un aparato al que le acabas de quitar
      // el permiso se seguía sirviendo solo.
      needsApproval: async (pub) => needsApproval(pub, await refreshActa()),
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
      // EL ACTA VIAJA CON EL AVISO. Sin esto, un miembro se enteraba de que «algo cambió»
      // pero no de QUÉ, y no veía el acta nueva hasta renovar su cert — hasta 30 días.
      // Para un aparato eso era lento; para OTRA BÓVEDA es fatal: se le concede `sella` y
      // no puede sellar, porque su copia del acta no lo dice todavía.
      // No es un dato secreto (es pública dentro del perfil y estos son sus miembros), y
      // quien la recibe la adopta por las reglas de §2.4.1, así que una vieja o ajena no
      // hace daño: se rechaza sola.
      const acta = (await identity.profileActa?.().catch(() => null))?.acta || null
      const { issued } = await identity.listDelegations()
      // A QUIÉN SE AVISA: a los MIEMBROS DEL ACTA, no solo a quien esta bóveda enroló.
      //
      // Esto avisaba únicamente por `issued` —las delegaciones que emitió esta bóveda—, y
      // eso deja fuera exactamente el caso del multivault: la segunda bóveda entró por
      // `join`, así que la delegación la emitió la PRIMERA. Cuando la segunda sellaba un
      // acta nueva (admitir un aparato con su permiso `sella`), su lista de emitidas no
      // tenía a la primera dentro y el cambio no llegaba a ninguna parte: las dos bóvedas
      // quedaban con actas distintas y la del dueño sin enterarse de nada.
      //
      // El acta es la lista de quién es del perfil: esa es la lista correcta. `issued` se
      // suma porque cubre a quien tiene cert y todavía no aparece ahí.
      const miembros = (await identity.profileMembers?.().catch(() => null))?.members || []
      const yo = identity.me?.publickey || null
      // UNO POR LLAVE, no uno por delegación: renovar emite una delegación nueva para la
      // MISMA sub-clave, así que un aparato que lleve tiempo enrolado aparece varias veces
      // y recibía el mismo aviso repetido —una vez por renovación acumulada—. Mismo
      // cuidado que en `notifyNsChange`.
      const seen = new Set()
      const avisar = (pub) => {
        if (!pub || pub === yo || seen.has(pub)) return
        seen.add(pub)
        // El fallo NO se traga. Que un aviso no salga es exactamente lo que deja a dos
        // bóvedas con actas distintas sin que nadie se entere, y encontrarlo sin una línea
        // de log cuesta días (la última vez, tres).
        try { client.sendByPubkey(pub, { type: MSG.ADMIN_EVENT, body, signature, acta }) }
        catch (e) { log(`[vault] could not notify ${pub.slice(0, 24)}… of "${ev}": ${e.message}`) }
      }
      for (const m of miembros) avisar(m.pub)
      for (const d of issued || []) avisar(d.sub)
      log(`[vault] notified ${seen.size} member(s) of "${ev}" (record #${acta?.seq ?? '?'})`)
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
    async list ({ caller = null } = {}) {
      // EL VAULT DECIDE QUÉ ENVÍA PARA LEER (dueño, 2026-09-02: «la consola debe tener todos
      // los sobres; la diferencia es si el vault se los envía para la lectura o no»).
      //
      // Tener la envoltura y recibir el sobre son dos cosas: quien administra tiene la
      // envoltura de cada PÚBLICA, y por eso aquí se le manda el sobre de esas y solo de
      // esas. Las privadas de un cajón con dueño no se mandan — y aunque se mandaran no
      // podría abrirlas, porque su envoltura no existe. Dos cerrojos para lo mismo, a
      // propósito: que uno falle no basta para leerlas.
      //
      // Se sella la lista ENTERA, no solo los valores: el proxy tampoco tiene por qué
      // aprender cómo se llaman tus variables ni qué servicios corres.
      return {
        enc: await identity.sealContent(JSON.stringify({
          ns: conSobres(listSecrets(), 'ns', caller), dev: conSobres(await listDeviceSecrets(), 'dev', caller),
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
    /**
     * PARA QUIÉN ENVOLVER. Lo contesta la bóveda porque la lista sale del ACTA
     * (`recipientsOf`), y tener dos sitios respondiendo a «quién puede abrir este cajón» es
     * exactamente cómo se acaba dejando fuera a alguien sin que nadie se entere.
     */
    async recipients ({ ns, pub, public: isPublic }) {
      // LA VISIBILIDAD CAMBIA LA LISTA: una pública se envuelve además para quien
      // administra, así que hay que decirlo al preguntar. Pedirla sin decirlo y luego
      // guardarla como pública produciría un sobre que la consola no puede abrir — y la
      // bóveda lo rechazaría, que es lo correcto pero desorienta.
      return secrets.recipientsFor(ns ? `ns:${ns}` : `dev:${pub}`, { public: !!isPublic })
    },
    /**
     * GUARDAR UNA VARIABLE **SIN VERLA** (dueño, 2026-09-01).
     *
     * «La bóveda cerrada no puede ver el valor; debe confiar en la firma del admin y en el
     * contenido de esos sobres, y es la razón por la que al abrir la bóveda rehace los
     * sobres: por si alguno tiene alguna incoherencia.»
     *
     * Antes esto abría el sobre para sacar el valor en claro y volvía a cerrarlo. Ese
     * rodeo era el ÚNICO motivo por el que la llave de cifrado del perfil tenía que estar
     * accesible con la bóveda cerrada — o sea, la razón por la que una copia del disco
     * abría todo lo dirigido al perfil.
     *
     * Ahora llega hecho: el valor cifrado con una CEK nueva y esa CEK envuelta para cada
     * destinatario. Aquí se comprueba lo que se puede comprobar SIN la llave: que las
     * envolturas cubren exactamente a quien dice el acta. Lo que no se puede comprobar
     * —que dentro haya lo que dice— lo corrige el repaso al abrir la bóveda.
     *
     * Una PÚBLICA sigue viajando en claro y por el camino de siempre: marcarla pública es
     * precisamente decir que no hay nada que ocultar.
     */
    async set ({ ns, pub, key, sealed, caller = null, public: isPublic, by: who = null }) {
      const owner = ns ? `ns:${ns}` : `dev:${pub}`
      if (sealed) {
        // PÚBLICA Y PRIVADA VAN IGUAL (dueño, 2026-09-02: «la única diferencia es si se
        // despachan o no, son políticas; dales el mismo tratamiento de seguridad»). La
        // marca solo decide si se entrega sin aprobación.
        await verificarAutor(owner, key, sealed, caller)
        await verificarDestinatarios(owner, sealed.wraps, !!isPublic)
        await secrets.putSealed(owner, key, sealed, { by: who, public: isPublic })
        audit('secret.set', { ns: ns || null, key, sealed: true }); scheduleNotice(ns)
        await settleDebts(owner)
        return { ok: true, key }
      }
      // NO HAY OTRO CAMINO (dueño, 2026-09-02: «no dejes caminos viejos ni fallbacks; no hay
      // que hacer retrocompatibilidad y es una regla del estado actual del proyecto, por eso
      // quedan luego backdoors»).
      //
      // Aquí estaba el `enc`: la consola sellaba el valor AL PERFIL y la bóveda lo ABRÍA
      // para volver a cerrarlo. Ese descifrado era el único motivo por el que la llave de
      // cifrado del perfil tenía que estar accesible con la bóveda cerrada — o sea, la
      // razón por la que una copia del disco abría todo lo dirigido al perfil. Dejarlo
      // «por si acaso» habría dejado el agujero entero abierto con otro nombre.
      throw Object.assign(
        new Error('var.set: the value must come already sealed (`sealed`); the old `enc` path is gone — build it with buildSealedVar()'),
        { code: 'needs-sealed' })
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
    async setMany ({ ns, pub, items, caller = null, by: who = null }) {
      // CADA VARIABLE VIENE EN SU PROPIO SOBRE, ya hecho. La bóveda no abre ninguno: solo
      // comprueba quién los firma y a quién envuelven, igual que en `set`. Aquí estaba el
      // `enc` que las traía todas juntas selladas AL PERFIL, y abrirlo era lo que obligaba
      // a tener la llave de cifrado accesible con la bóveda cerrada.
      if (!Array.isArray(items) || !items.length) throw new Error('var.setMany: no variables came')
      const owner = ns ? `ns:${ns}` : `dev:${pub}`
      const keys = []
      for (const it of items) {
        if (!it?.key || !it?.sealed) throw new Error('var.setMany: each variable needs its key and its sealed envelope')
        await verificarAutor(owner, it.key, it.sealed, caller)
        await verificarDestinatarios(owner, it.sealed.wraps, !!it.public)
      }
      // Se comprueban TODAS antes de escribir NINGUNA: media carga aplicada es una
      // configuración que nadie quiso, y el servicio se reinicia con ella.
      for (const it of items) {
        await secrets.putSealed(owner, it.key, it.sealed, { by: who, public: !!it.public })
        keys.push(it.key)
      }
      audit('secret.setMany', { ns: ns || null, keys }); scheduleNotice(ns)
      await settleDebts(owner)
      return { ok: true, keys }
    }
  }

  const admin = createAdminDesk({
    desk,
    deviceIdOf,
    audit,
    // El MISMO candado que frena firmar y editar el perfil: revocar reescribe el acta y
    // configurar toca los secretos, y ninguna de las dos se hace con la bóveda cerrada.
    isLocked,
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
        expectedScope: SCOPE.ADMIN, ...(await contextoActa()), revoked: await revocationSet()
      })
      // Quitarse a UNO MISMO desde la consola remota entra por aquí: la segunda petición
      // que mande el aparato ya llega con el certificado retirado. Que se entere con el
      // aviso firmado, en vez de con un error suelto que no puede borrar nada.
      if (!chk.ok) {
        await notifyIfRevoked(data?.publickey, cert?.nonce || null, cert?.iss || null, chk.reason)
        return chk
      }
      const record = (await identity.profileActa?.().catch(() => null))?.acta
      if (!record || !Acta.memberCan(record, chk.device, 'admin')) return { ok: false, reason: record ? 'acta' : 'sin-acta' }
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
    // El `code` viaja aparte del texto: el texto está en inglés y puede cambiar, el código
    // es lo que empareja quien llama (`vault-locked` ≠ «no autorizado»).
    if (!r.ok) return reply(from, { type: MSG.ERROR, error: r.error, ...(r.code ? { code: r.code } : {}) })
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

  /**
   * LAS OTRAS BÓVEDAS —los miembros con el permiso `sella`— entran en TODOS los cajones,
   * también en los que tienen dueño. Decidido por el dueño el 2026-08-30.
   *
   * Y no contradice la regla de agosto —«un cajón con dueño no se envuelve para quien
   * administra»—, porque un cosellador **no es quien administra**: es un master. Aquella
   * regla saca a los aparatos de consola (un navegador, un portátil con la sesión puesta),
   * cuyo compromiso es probable y cuya necesidad es comodidad. Una segunda bóveda existe
   * justamente para poder REGENERAR los sobres el día que la primera no esté, y regenerar
   * exige abrir: dejarla fuera la haría inútil para el único desastre que viene a cubrir.
   *
   * El precio, que se dice y no se esconde: a partir de aquí son DOS los discos cuya
   * captura abre ese cajón. Eso es exactamente lo que cuesta sobrevivir a perder uno.
   */
  async function cosealerMembers () {
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    if (!record) return []
    // Sin `encPub` no hay a dónde envolver: se queda en deuda y se ve como `sinLlave`,
    // igual que cualquier otro miembro incompleto.
    return (record.members || []).filter((m) =>
      m.pub !== master && m.encPub && Acta.memberCan(record, m.pub, 'sealer'))
  }

  /** Sin duplicar: un cosellador puede ser además el dueño del cajón. */
  /** Sin repetidos por llave: un aparato puede entrar por dos vías (dueño y admin). */
  const dedup = (miembros) => {
    const vistos = new Set()
    return miembros.filter((m) => m && !vistos.has(m.pub) && vistos.add(m.pub))
  }
  const conCoselladores = (base, co) => {
    const vistos = new Set(base.map((m) => m.pub))
    return [...base, ...co.filter((m) => !vistos.has(m.pub))]
  }

  async function recipientsOf (owner, { public: isPublic = false } = {}) {
    const co = await cosealerMembers()
    // UNA PÚBLICA SE ENVUELVE TAMBIÉN PARA QUIEN ADMINISTRA (dueño, 2026-09-02: «la consola
    // debe poder leer todas las variables… debe tener todos los sobres; la diferencia es si
    // el vault se los envía para la lectura o no» → «cambia la regla y di que se envuelven
    // las públicas»).
    //
    // Puede decidirse variable a variable porque cada escritura estrena su propia CEK: el
    // llavero guarda una generación por valor, no una por cajón.
    //
    // Y la PRIVADA de un cajón con dueño sigue sin envoltura para la consola, que es la
    // regla de agosto y su motivo no ha cambiado: el token de R2 no tiene por qué poder
    // abrirse desde un navegador. Lo que cambia es que «pública» ya sí quiere decir algo
    // para quien administra — puede leerla— además de que se despacha sin aprobación.
    const admins = isPublic ? await adminDevices() : []
    if (owner.startsWith('ns:')) {
      const owned = await nsMembers(owner.slice(3))
      // Sin dueño (un cajón personal, o uno cuyo servicio ya no está) entra quien administra
      // SIEMPRE: si no, no quedaría nadie que pudiera abrirlo sin la frase.
      const base = owned.length ? [...owned, ...admins] : await adminDevices()
      return conCoselladores(dedup(base), co)
    }
    const pub = owner.slice(owner.indexOf(':') + 1)
    const m = await memberOf(pub)
    // El cajón propio de un aparato de SERVICIO es tan suyo como el de su ns.
    if (m?.cn) return conCoselladores(dedup([m, ...admins]), co)
    return conCoselladores(dedup([...(m ? [m] : []), ...await adminDevices()]), co)
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
    await settleDebts(`ns:${ns}`)
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
  /**
   * PEDIRLE A UN HERMANO QUE ENVUELVA — Y QUE SE LO ENTREGUE A LA BÓVEDA (§8.11).
   *
   * Regla del dueño (2026-09-01): «un servicio reparte la llave AL VAULT para que este la
   * reparta después, pero no se la entrega directo; si lo hace sin pasar por el vault está
   * mal». Es lo que hace este camino, y conviene verlo en el orden de las líneas:
   *
   *   1. la BÓVEDA le pide el sobre al hermano (`sendByPubkey` → `REWRAP`);
   *   2. el hermano le contesta A ELLA, nunca al recién llegado;
   *   3. la BÓVEDA lo guarda (`putWrap`) y a partir de ahí lo sirve ella.
   *
   * El destinatario no habla con nadie, y la bóveda nunca ve la llave en claro: el sobre
   * llega ya cerrado a la pública del destinatario. Por eso esto funciona con el perfil
   * cerrado, que es justo cuando hace falta.
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

  /**
   * REHACER EL LLAVERO ENTERO. Se llama al ABRIR la bóveda, que es el único momento en que
   * se puede: envolver exige la llave del cajón, y esa solo se abre con la frase.
   *
   * Lo que falle aquí SALE en `failed`, y quien llame tiene que decirlo. Callarlo fue el
   * fallo: un cajón que no se pudo reenvolver deja a sus aparatos sin poder leer nada, y
   * desde fuera la bóveda parecía abierta y sana — «desbloqueado» a secas—. Se descubría
   * días después, por un servicio que pedía sus claves una y otra vez.
   */
  /**
   * QUE LOS SOBRES EXISTAN PARA TODOS, SIEMPRE — TAMBIÉN AL SELLAR EL ACTA.
   *
   * Regla del dueño (2026-09-01): «cuando se abre el vault, y siempre, debe asegurarse de
   * que todos los sobres para todos los dispositivos existan, antes y después de sellar un
   * acta; es la tarea de la llave maestra, no tiene otra».
   *
   * Y es literalmente su otro trabajo: la maestra firma el acta y regenera los sobres. Todo
   * cambio del acta cambia QUIÉN debe tener envoltura de qué —entra un aparato, se le da
   * `secrets`, se le quita, aparece un sellador nuevo—, así que sellar sin repasar los
   * sobres deja el llavero diciendo una cosa y el acta otra. Eso fue justo el agujero: un
   * servicio en el acta, con su permiso, y sin poder abrir nada.
   *
   * Con la bóveda ABIERTA se rehace de verdad. Cerrada no se puede —envolver exige la llave
   * del cajón— y entonces queda como DEUDA anotada, que es lo que salda el `unlock`. Lo que
   * no se hace es callarlo.
   */
  /**
   * QUE LOS SOBRES EXISTAN PARA TODOS, CADA VEZ QUE EL ACTA CAMBIA.
   *
   * Regla del dueño (2026-09-01): «cuando se abre el vault, y siempre, debe asegurarse de
   * que todos los sobres para todos los dispositivos existan, antes y después de sellar un
   * acta; es la tarea de la llave maestra, no tiene otra». Y es literalmente su otro
   * trabajo: firmar el acta y regenerar los sobres.
   *
   * SE REHACE ENTERO, no se salda lo que falta. Saldar añade lo que no está pero no MIRA lo
   * que sobra: la envoltura de alguien a quien ya se le quitó el permiso se quedaría ahí
   * para siempre y nadie se enteraría. `resealAll` con `exact` deja cada cajón envuelto para
   * exactamente quien dice el acta —crea lo que falta y RETIRA lo caduco—, que es la única
   * forma de poder afirmar que el llavero está al día. No toca la red: es reenvolver con
   * las públicas del acta, así que esperar aquí no cuelga de ningún aparato apagado.
   *
   * NO HAY CAMINO PARA «LA BÓVEDA ESTÁ CERRADA» (dueño, 2026-09-01: «es un absurdo, con
   * bóveda cerrada no puede cambiar el acta»). Sellar el acta necesita la maestra, y cerrada
   * la maestra no está en memoria — o sea que si se llegó hasta aquí, estaba abierta. Un
   * `if` para ese caso no sería prudencia: sería un repliegue que le pone cara de trámite
   * normal a una contradicción. Si aun así falta la llave, se dice como lo que es.
   */
  /**
   * ¿QUIÉN HIZO ESTE SOBRE? Tiene que decirlo, y tiene que ser un MIEMBRO DEL ACTA.
   *
   * Regla del dueño (2026-09-01): «los sobres deben traer información de quién los hizo,
   * deberían tener la firma para que no se cuelen sobres firmados por cualquiera; solo
   * puede haber sobres firmados por miembros del acta».
   *
   * La petición ya viene firmada y comprobada (`verifyChain` + el acta), así que un extraño
   * no llega hasta aquí. Esto es otra cosa y hace falta igual: la bóveda guarda unos bytes
   * que NO PUEDE LEER, y sin esta firma lo único que ataba esos bytes a un autor era el
   * momento de la llamada. Con ella, el registro guardado se explica solo — se puede
   * comprobar después, en frío, sin fiarse de ningún log.
   *
   * El autor tiene que ser QUIEN LLAMA. Aceptar un sobre firmado por otro sería admitir un
   * relevo: alguien con `admin` colando un sobre que fabricó un tercero, sin que ninguna de
   * las dos comprobaciones lo note.
   */
  async function verificarAutor (owner, key, sealed, caller) {
    const a = sealed?.author
    if (!a || typeof a.pub !== 'string' || typeof a.sig !== 'string' || typeof a.ts !== 'number') {
      throw new Error('var.set: the envelope must say WHO made it (`author: { pub, sig, ts }`)')
    }
    if (caller && a.pub !== caller) {
      throw new Error('var.set: the envelope was signed by someone other than the caller — a relayed envelope is not accepted')
    }
    const record = (await identity.profileActa?.().catch(() => null))?.acta
    const m = (record?.members || []).find((x) => x.pub === a.pub)
    if (!record || !m) {
      throw new Error('var.set: the envelope is signed by a key the record does not name')
    }
    // UN SERVICIO SOLO PARA SU CAJÓN (dueño, 2026-09-01: «un cn no puede poner un sobre
    // faltante fuera de su cn»). Es la misma regla que ya aplica el reparto delegado
    // (`handleRewrapOk`), y tiene que valer también aquí: si no, un servicio con `admin`
    // podría escribir en el cajón de otro. Quien administra sin `cn` sí puede: ese es su
    // trabajo, y para eso se le concede a mano.
    const ns = owner.startsWith('ns:') ? owner.slice(3) : null
    if (m.cn && ns && m.cn !== ns) {
      throw new Error(`var.set: "${m.cn}" cannot write into "${owner}" — a service only authors envelopes for its own drawer`)
    }
    // Y UN SERVICIO NO PISA LO QUE YA HAY (dueño, 2026-09-01: «un cn no puede sobrescribir
    // un sobre existente; solamente el admin y el vault editan sobres, los otros pueden
    // crear los que faltan nomás»).
    //
    // Es la misma regla que `putWrap` («solo añade, nunca pisa») y por el mismo motivo: un
    // servicio que pudiera reemplazar un sobre podría dejar sin leer a otro miembro con uno
    // basura — denegación de servicio disfrazada de escritura. Rellenar lo que falta no
    // quita nada a nadie; reemplazar sí, y eso es de quien administra.
    if (m.cn && secrets.has?.(owner, key)) {
      throw new Error(`var.set: "${m.cn}" cannot overwrite "${key}" — a service only fills in what is missing; replacing is for who administers`)
    }
    const cuerpo = authorBody(owner, key, sealed.e, a.ts)
    if (!(await verifyDeviceSig({ publickey: a.pub, data: cuerpo, signature: a.sig }))) {
      throw new Error('var.set: the author signature does not verify over this envelope')
    }
  }

  /**
   * ¿ESTE SOBRE ENVUELVE A QUIEN TOCA? Lo único que se puede comprobar sin la llave.
   *
   * No se puede saber si dentro de cada envoltura está la CEK correcta —para eso habría que
   * abrirla, que es justo lo que ya no se hace—, pero sí QUIÉN puede abrirlas. Y eso ya
   * ataja lo que importa: que no falte nadie (un servicio que arrancaría sin configuración)
   * y que no sobre nadie (alguien a quien el acta no nombra leyendo el cajón).
   *
   * Lo de dentro lo corrige el repaso al abrir la bóveda, que es para lo que está.
   */
  async function verificarDestinatarios (owner, wraps, isPublic = false) {
    if (!wraps || typeof wraps !== 'object') throw new Error('var.set: the envelope carries no wraps')
    const { recoveryPub, members } = await secrets.recipientsFor(owner, { public: isPublic })
    if (!recoveryPub) throw new Error('var.set: this vault has no recovery key yet')
    const deben = new Set(members.map((m) => m.pub))
    const traidos = new Set(Object.keys(wraps).filter((k) => k !== RECOVERY_WRAP))
    const faltan = [...deben].filter((p) => !traidos.has(p))
    const sobran = [...traidos].filter((p) => !deben.has(p))
    if (faltan.length) {
      throw new Error(`var.set: the envelope leaves ${faltan.length} member(s) of "${owner}" out — they could not read it (ask the vault for the recipients with \`var.recipients\`)`)
    }
    if (sobran.length) {
      throw new Error(`var.set: the envelope wraps for ${sobran.length} key(s) the record does not name for "${owner}"`)
    }
  }

  async function refreshWraps (motivo) {
    // HAY CANDADO SOLO SI HAY LAS DOS COSAS: contraseña Y alguien que sepa abrirla.
    //
    // `startVault` sin gestor de perfiles trae `hasPassword = () => true` y `openKey =
    // null`, que leído a la letra dice «tiene contraseña pero no hay con qué abrirla» — el
    // estado imposible. Mirando solo `hasPassword` se daba por cerrada una bóveda que abre
    // con la llave de la máquina, y el repaso del llavero se saltaba ENTERO: el servicio se
    // quedaba sin su envoltura y contestábamos un paquete que no podía abrir. Es el mismo
    // fallo que se está arreglando, colado por la puerta de al lado.
    const conCandado = typeof openKey === 'function' && (() => { try { return !!hasPassword() } catch (_) { return true } })()
    const k = conCandado ? openKey() : null
    if (conCandado && !k) {
      log(`[vault] ${motivo}: the record changed but the profile key is not here — the record cannot be sealed while locked, so this should not happen; the keyring was NOT rebuilt`)
      return null
    }
    const r = await resealAll(k).catch((e) => { log(`[vault] ${motivo}: could not rebuild the keyring: ${e.message}`); return null })
    if (r?.wrapped) log(`[vault] ${motivo}: keyring rebuilt (${r.wrapped} wrap(s) in ${r.drawers} drawer(s))`)
    // LOS SOBRES CADUCOS SE DICEN. Son envolturas de quien ya no debería poder abrir ese
    // cajón: retirarlas en silencio esconde que alguien las tuvo de más.
    if (r?.dropped) log(`[vault] ${motivo}: ${r.dropped} stale wrap(s) dropped (they belonged to members the record no longer names)`)
    if (r?.failed?.length) log(`[vault] ${motivo}: ${r.failed.length} drawer(s) could NOT be resealed: ${r.failed.map((f) => f.owner).join(', ')}`)
    return r
  }

  /**
   * MIGRACIÓN, CON FECHA: la copia de recuperación pudo quedar sellada con la llave de la
   * MÁQUINA aunque el perfil tenga contraseña.
   *
   * Pasa por un camino perfectamente normal: escribir una variable NO pide la frase (§8.1),
   * así que si el cajón se estrenó con el perfil cerrado, `ensureRecovery` la selló con lo
   * único que había — la llave de la máquina. A partir de ahí, abrir el perfil y reenvolver
   * pasa la llave de la CONTRASEÑA, que no abre ese sobre: «wrong password», el llavero no
   * se rehace, y los servicios se quedan sin poder leer sus cajones para siempre. Es
   * exactamente lo que le pasó a un perfil real el 2026-09-01.
   *
   * Aquí se abre con la de la máquina y se vuelve a cerrar con la de la contraseña, que es
   * el `rekey` que aquel `password-set` no llegó a hacer. NO es un repliegue: no decide un
   * permiso, no deja pasar a nadie, y **se acaba** — al primer desbloqueo el sobre queda
   * bajo la frase y esta rama no vuelve a entrar. Y va en el sentido estricto: el material
   * de la llave de máquina vive en este mismo disco, así que pasar a la contraseña PROTEGE
   * más de lo que había, no menos.
   *
   * Se puede quitar cuando no queden perfiles de antes de 0.81.0 (2027-03-01).
   */
  const MIGRACION_RECUPERACION_HASTA = Date.parse('2027-03-01T00:00:00Z')
  async function migrarRecuperacionALaFrase (adminKey) {
    if (!adminKey || Date.now() > MIGRACION_RECUPERACION_HASTA) return false
    try {
      // Si la frase ya la abre, no hay nada que migrar.
      await secrets.recoveryOpensWith(adminKey)
      return false
    } catch (_) {}
    try {
      // LA LLAVE DE LA MÁQUINA, EXPLÍCITA. `null` NO vale aquí: `defaultKey()` mira primero
      // `openKey()`, y con el perfil ABIERTO eso es la llave de la contraseña — o sea que
      // pasar `null` probaba la misma llave dos veces y la migración no migraba nada. Lo
      // dijo el propio diagnóstico: «no abre ni con la contraseña ni con la de la máquina»,
      // cuando la de la máquina no se había llegado a probar.
      const maquina = new Uint8Array(kekFor(dir))
      await secrets.recoveryOpensWith(maquina)                // si esta tampoco, no hay migración que hacer
      const r = await secrets.rekeyRecovery(maquina, adminKey)
      if (!r?.rekeyed) return false
      log('[vault] the recovery copy was sealed with this machine\'s key: re-sealed under the profile password')
      audit('secret.recovery-rekeyed', {})
      return true
    } catch (e) {
      log(`[vault] the recovery copy does not open with the password nor with this machine's key (${e.message}): the drawers cannot be re-wrapped`)
      return false
    }
  }

  async function resealAll (adminKey = null) {
    // ANTES de reenvolver nada: si la copia de recuperación se quedó bajo la llave de la
    // máquina, se pasa a la frase. Sin esto, todo lo de abajo falla con «wrong password».
    if (adminKey) await migrarRecuperacionALaFrase(adminKey)
    const out = { drawers: 0, wrapped: 0, dropped: 0, sinLlave: [], failed: [] }
    for (const owner of secrets.owners?.() || []) {
      const before = new Set(secrets.recipientsIn(owner))
      // POR VISIBILIDAD, no una lista fija: una pública lleva además la envoltura de quien
      // administra. Con una sola lista se le daría también la de una privada con dueño, que
      // es justo lo que no puede pasar.
      const members = (esPublica) => recipientsOf(owner, { public: esPublica })
      try {
        const r = await secrets.rewrap(owner, members, adminKey, { exact: true })
        const after = new Set(secrets.recipientsIn(owner))
        out.drawers++
        out.wrapped += r?.wrapped || 0
        out.dropped += [...before].filter((p) => !after.has(p)).length
        for (const p of r?.sinLlave || []) out.sinLlave.push(p)
      } catch (e) {
        log(`[vault] ${owner}: could not reseal (${e.message})`)
        out.failed.push({ owner, error: e.message })
      }
    }
    if (out.dropped) audit('secret.reseal', { drawers: out.drawers, dropped: out.dropped })
    if (out.failed.length) audit('secret.reseal-failed', { drawers: out.failed.map((f) => f.owner) })
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
      const members = (esPublica) => recipientsOf(owner, { public: esPublica })
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
  async function settleDebts (owner) {
    const ns = owner.startsWith('ns:') ? owner.slice(3) : null
    const owed = (ns && store.getSetting(`rotate-due:${ns}`)) ||
      (await incompleteMembers()).some((m) => m.owners[owner])
    if (!owed) return null
    // QUIÉN RECIBE ENVOLTURA LO DICE `recipientsOf`, Y SOLO ÉL.
    //
    // Antes cada llamador traía su propia lista (`nsMembers`, o el miembro suelto), y todas
    // se dejaban fuera a los SELLADORES — que `recipientsOf` sí incluye. Resultado: escribir
    // una variable envolvía para el servicio y dejaba al sellador con la generación vieja
    // (dueño, 2026-09-01: «al envolver hay que envolver siempre para todos los selladores,
    // para que siempre tengan la info fresca»). Dos listas para la misma pregunta acaban
    // siempre así: una se actualiza y la otra no.
    try { return await spreadKey(owner, (esPublica) => recipientsOf(owner, { public: esPublica }), null) } catch (_) { return null }
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
      await settleDebts(`ns:${ns}`)
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
      await settleDebts(`dev:${pub}`)
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
  /**
   * LE PONE A CADA PÚBLICA SU SOBRE Y LA ENVOLTURA DE QUIEN PREGUNTA, para que pueda leerla.
   *
   * Solo a las públicas: es la política de despacho, y es lo único que cambia entre una y
   * otra. A una privada no se le manda nada — y aunque se le mandara, quien administra no
   * tiene su envoltura en un cajón con dueño, así que no la abriría igual.
   *
   * Si falta la envoltura de quien pregunta (todavía no se le ha hecho, o el cajón se
   * escribió antes de que entrara) se manda la variable SIN sobre: se ve que existe y que es
   * pública, y no se puede leer. Eso es cierto y se arregla abriendo la bóveda; inventarse
   * un valor o esconder la fila sería peor.
   */
  const conSobres = (lista, tipo, caller) => {
    if (!caller) return lista
    const dar = (owner, k) => {
      if (!k.public) return k
      const e = secrets.entryOf?.(owner, k.key)
      const wrap = e?.gen != null ? secrets.wrapOf?.(owner, e.gen, caller) : null
      return e?.e && wrap ? { ...k, e: e.e, wrap } : k
    }
    if (tipo === 'ns') {
      const out = {}
      for (const [ns, keys] of Object.entries(lista)) out[ns] = keys.map((k) => dar(`ns:${ns}`, k))
      return out
    }
    return lista.map((row) => ({ ...row, keys: row.keys.map((k) => dar(`dev:${row.pub}`, k)) }))
  }

  function listSecrets () {
    // YA NO SE ENSEÑA EL VALOR DE UNA PÚBLICA (dueño, 2026-09-02). Desde que todas van en
    // sobre, «pública» dejó de significar «en claro»: dice a quién se le despacha sin
    // aprobación, nada más. Para ver un valor hay que poder abrirlo, igual que cualquiera —
    // y en un cajón con dueño, quien administra deliberadamente no puede.
    return secrets.list()
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
    await settleDebts(`dev:${pub}`)
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
      out.push({
        pub,
        id: m?.id || await deviceIdOf(pub).catch(() => null),
        label: m?.label || '',
        cn: m?.cn || null,
        // Sin valores: desde 2026-09-02 una pública también va en sobre (ver `listSecrets`).
        keys,
        orphan: !!members.length && !m
      })
    }
    return out
  }

  return {
    identity, client, store, threads, secrets, master, fingerprint: fp, dir,
    // Se expone para poder PROBAR que una respuesta que no cabe no mata la conexión: es el
    // único punto por el que sale todo, y el fallo que cierra vive justo ahí.
    reply,
    /**
     * SOLTAR LA MAESTRA. Cerrar el perfil tiene que sacarla de la memoria, no solo dejar de
     * cargarla en el siguiente arranque: si no, el candado seguiría siendo una bandera al
     * lado de una llave descifrada, que es exactamente lo que se quitó de en medio.
     *
     * Se recarga el par: sin la llave del perfil el pilar lo deja SIN privada, así que a
     * partir de aquí firmar se niega con `vault-locked`. Servir sigue igual — eso lo hace la
     * llave de comunicación, que no depende de la contraseña.
     */
    async dropMasterKey () {
      const r = await identity.reloadMasterKey?.()
      return { locked: r?.locked !== false }
    },
    /** Al abrir: recuperar la maestra y, si venía en claro de antes, dejarla sellada. */
    async takeMasterKey () {
      const r = await identity.reloadMasterKey?.()
      if (r?.locked === false) { try { await identity.sealMasterKey?.() } catch (_) {} }
      return { locked: r?.locked !== false }
    },
    startPairing: desk.startPairing,
    stopPairing: desk.stopPairing,
    listPending: desk.listPending,
    // ¿Pide permiso este aparato para recibir claves privadas? Lo dice el ACTA
    // (`unattended`), no una lista de esta máquina — por eso ya no hay `setApproval` ni
    // `supervised`: se concede y se quita como cualquier otro permiso, con `caps`.
    needsApproval: async (pub) => needsApproval(pub, await refreshActa()),
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
        // POR `recipientsOf`, NO por `nsMembers`. Quien debe tener envoltura de un cajón lo
        // dice UN sitio, y ahí dentro están también los SELLADORES (dueño, 2026-09-01: «al
        // envolver hay que envolver siempre para todos los selladores, para que siempre
        // tengan la info fresca»). Repartiendo solo a los del ns, un cajón tocado por esta
        // puerta dejaba a los selladores con la envoltura vieja.
        await spreadKey(`ns:${m.cn}`, (esPublica) => recipientsOf(`ns:${m.cn}`, { public: esPublica }), adminKey).catch(async (e) => {
          log('[vault] could not hand the key to the new service:', e.message)
          // Sin la frase la bóveda no puede envolvérsela… pero un HERMANO suyo sí: otro
          // servicio del mismo cajón ya tiene la llave abierta (§8.11). Si contesta, el
          // recién llegado arranca completo; si no hay ninguno encendido, la deuda queda
          // a la vista y se salda al abrir la bóveda.
          const r2 = await delegateRewrap(`ns:${m.cn}`, m.pub).catch(() => ({ done: 0 }))
          if (!r2.done) log(`[vault] ns:${m.cn}: nobody could hand it the key — it stays in debt until the vault is opened`)
        })
      }
      // Y el llavero ENTERO: el recién llegado también es destinatario de su propio cajón,
      // y si entra con `sella` lo es de TODOS. Repartir solo el suyo dejaba el resto atrás.
      await refreshWraps('enrolled')
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
    /**
     * QUIÉN tiene envoltura de la generación vigente de un cajón (llaves de firma, más
     * `#recovery`). Es diagnóstico: saber a cuántos se les envolvió no ayuda a abrir nada,
     * y en cambio es lo único que contesta de verdad a «¿quién puede leer esto?».
     *
     * Se expone porque hacía falta para COMPROBARLO en una prueba en vez de argumentarlo:
     * la condición del dueño para acotar los sobres por cajón y permisos —en vez de
     * envolver para todos— fue estar seguro de que no falta ninguno.
     */
    secretRecipients: (owner) => secrets.recipientsIn(owner),
    // ¿Es ESTA bóveda la que sella el acta? Lo usa el freno de borrado (D12).
    isMaster: () => identity.isMaster(),
    setCaps: async (pub, caps) => {
      const r = await identity.setCaps(pub, caps)
      // ¿SE QUEDÓ ALGUNO POR EL CAMINO? El acta tiene una lista CERRADA de permisos y
      // `cleanCaps` descarta los que no conoce — correcto al recibir un acta ajena, y
      // pésimo aquí: conceder `+sella` con una versión del pilar que no sabe qué es
      // devolvía «Listo», resellaba el acta y no concedía nada. Costó una tarde en un
      // contenedor, porque la imagen traía la versión de npm y el árbol local otra.
      try {
        const quedaron = new Set((await identity.profileMembers()).members.find((m) => m.pub === pub)?.caps || [])
        const perdidos = caps.filter((c) => !quedaron.has(c))
        if (perdidos.length) {
          log(`[vault] WARNING these permissions were DROPPED: ${perdidos.join(', ')} — this build's @dotrino/identity does not know them (record unchanged for those)`)
        }
      } catch (_) { /* comprobar es un extra: si falla, no rompe el cambio */ }
      audit('caps', { device: await deviceIdOf(pub).catch(() => null), caps })
      // El acta acaba de cambiar QUIÉN debe tener envoltura de qué: se repasa antes de
      // avisar, para que el aviso salga con el llavero ya al día.
      await refreshWraps('caps')
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
    //
    // Al salir alguien el acta cambia igual que al entrar, así que el llavero se repasa
    // también aquí: lo que sobra se quita (`resealAll` lo hace) y el que se queda sigue
    // completo. Un llavero que solo se repasa al añadir acumula envolturas de quien ya no
    // está, que es lo contrario de lo que se quiso al expulsarlo.
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
      await refreshWraps('revoked')
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
