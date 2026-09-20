<script setup>
/**
 * EL MOSTRADOR DE CONTRASEÑAS de la bóveda-en-pestaña — mientras esta pestaña esté abierta.
 *
 * No es una página: es una SECCIÓN de `/vault`, y solo se monta cuando esa página ha
 * determinado que la bóveda de esta cuenta es este mismo aparato. Si la bóveda vive en
 * otra máquina, es ella quien responde y aquí no se levanta un segundo mostrador: una
 * cuenta no tiene dos bóvedas.
 *
 * Su sitio es el vault y no la app de contraseñas: la bóveda es del vault, y las apps le
 * piden. Que exista es lo que hace que el ecosistema cumpla su propia regla — **ninguna
 * app puede exigir que el usuario tenga un daemon encendido**. El daemon del PC sigue
 * siendo el upgrade: añade estar disponible con el navegador cerrado, no otra cosa.
 *
 * Guarda lo mismo, responde de a una y habla el mismo protocolo que el daemon, así que
 * pasar de una a otro es enlazar de nuevo y nada más.
 */
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { Identity } from '@dotrino/identity'
import { WebSocketProxyClient } from '@dotrino/proxy-client'
import { samePubkey, importAuto, identitySealing, SealedStore, SealedResponder } from '@dotrino/passmanager'
import { RECOVERY, makeRecovery, openRecovery, hasRecovery, recoveryPubOf, convertToSealed, buildSealedEntry, profileKeys } from '@dotrino/passmanager/sealed'
import { openWrap, decryptWithCek } from '@dotrino/identity/content'
import { verifyDeviceSig } from '@dotrino/identity/capabilities'

const props = defineProps({
  lang: { type: String, default: 'es' },
  /**
   * La identidad YA abierta de la consola. Se pasa en vez de abrir otra: `Identity.connect()`
   * monta su propio iframe, así que hacerlo aquí ponía DOS en la misma página — y, en
   * local, uno contra `id.dotrino.com` y el otro contra el del disco, o sea dos perfiles
   * distintos en la misma pantalla. Va `markRaw` desde la consola (un Proxy de Vue no
   * sobrevive al `postMessage`).
   */
  identity: { type: Object, default: null },
})

/**
 * El proxio: el del ecosistema. En localhost se puede apuntar a otro con `?proxy=`, que es
 * lo que hace el banco de pruebas — sin eso, un escenario de punta a punta abría una
 * conexión de verdad contra producción, que es justo lo que promete no hacer.
 */
function proxyUrl () {
  try {
    const u = new URL(location.href)
    const p = u.searchParams.get('proxy')
    if (p && /^wss?:\/\//.test(p) && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)) return p
  } catch (_) { /* URL rara: el del ecosistema */ }
  return 'wss://proxy.dotrino.com'
}

const T = {
  es: {
    // --- la copia de recuperación y la conversión (sealed-passwords.md §2.7) ---
    pwTitle: 'Elige la contraseña de tus contraseñas',
    pwWhy: 'Desde ahora esta bóveda guarda tus contraseñas cerradas para tus aparatos, y ella no puede abrirlas. Esta contraseña es la única forma de volver a abrirlas el día que no te quede ningún aparato.',
    pwWarn: 'No se puede recuperar. Si la pierdes, pierdes lo que haya aquí dentro.',
    pw1: 'Contraseña',
    pw2: 'Otra vez',
    pwGo: 'Crear',
    pwWorking: 'Convirtiendo…',
    pwShort: 'Tiene que tener al menos 12 caracteres.',
    pwMismatch: 'No coinciden.',
    badPassword: 'Esa contraseña no abre la copia de recuperación.',
    converted: (n) => n ? `Listo: ${n} entrada${n === 1 ? '' : 's'} pasada${n === 1 ? '' : 's'} al formato nuevo.` : 'Listo.',
    importAsk: 'Escribe la contraseña de tus contraseñas para poder guardarlas.',
    askPwOk: 'Continuar',
    askPwNo: 'Cancelar',
    keptCount: (n) => n ? `${n} entrada${n === 1 ? '' : 's'}` : 'Nada guardado todavía.',
    keptBlind: 'Esta bóveda no puede leerlas: las guarda cerradas para tus aparatos. Lo único que sabe de ellas es cuántas hay.',
    opening: 'Abriendo tus contraseñas…',
    active: 'Respondiendo a tus aparatos',
    inactive: 'No está respondiendo',
    warning: 'Mientras esta pestaña esté abierta, tu bóveda responde a tus aparatos. Si la cierras, dejan de poder pedir contraseñas — nada se pierde, pero no responden hasta que vuelvas a abrirla.',
    devices: 'Aparatos que pueden pedir credenciales',
    none: 'Ninguno todavía. Conéctalo como cualquier otro aparato, arriba, y dale el permiso de contraseñas.',
    manage: 'Se conectan y se quitan arriba, con el resto de tus aparatos.',
    kept: 'Guardado en esta bóveda',
    empty: 'Nada guardado. Importa lo que ya tienes desde otro gestor.',
    importBtn: 'Importar de 1Password, Bitwarden o Chrome',
    imported: (n) => `${n} entrada${n === 1 ? '' : 's'} importada${n === 1 ? '' : 's'}`,
    asking: (q) => `«${q}» pide una contraseña`,
    askingText: 'Si le dices que sí, podrá pedir credenciales mientras esta bóveda siga abierta.',
    yes: 'Sí, dásela',
    no: 'No',
    askNotifTitle: 'Te están pidiendo una contraseña',
    askNotifBody: (q) => `«${q}» espera tu respuesta. Nadie recibe nada hasta que contestes.`,
    ring_t: 'Avísame cuando alguien pida algo',
    ring_b: 'Con esto, tu navegador te avisa aunque esta pestaña esté cerrada: al pulsar el aviso se abre la bóveda y responde lo que quedó esperando.',
    ring_on: 'Activar los avisos',
    ring_ok: 'Los avisos están activados.',
    ring_bad: 'No se pudieron activar los avisos aquí:',
    anySite: 'cualquier sitio',
    noIdentity: 'Hace falta tu perfil de Dotrino. Créalo y vuelve.',
  },
  en: {
    pwTitle: 'Choose the password for your passwords',
    pwWhy: 'From now on this vault keeps your passwords sealed for your devices, and it cannot open them. This password is the only way to open them again the day you have no device left.',
    pwWarn: 'It cannot be recovered. If you lose it, you lose whatever is in here.',
    pw1: 'Password',
    pw2: 'Again',
    pwGo: 'Create',
    pwWorking: 'Converting…',
    pwShort: 'It must be at least 12 characters.',
    pwMismatch: 'They do not match.',
    badPassword: 'That password does not open the recovery copy.',
    converted: (n) => n ? `Done: ${n} entr${n === 1 ? 'y' : 'ies'} moved to the new format.` : 'Done.',
    importAsk: 'Type the password for your passwords so they can be saved.',
    askPwOk: 'Continue',
    askPwNo: 'Cancel',
    keptCount: (n) => n ? `${n} entr${n === 1 ? 'y' : 'ies'}` : 'Nothing kept yet.',
    keptBlind: 'This vault cannot read them: it keeps them sealed for your devices. All it knows about them is how many there are.',
    opening: 'Opening your passwords…',
    active: 'Answering your devices',
    inactive: 'Not answering',
    warning: 'While this tab is open, your vault answers your devices. If you close it they can no longer ask for passwords — nothing is lost, but they get no answer until you open it again.',
    devices: 'Devices that may ask for credentials',
    none: 'None yet. Connect it like any other device, above, and give it the passwords permission.',
    manage: 'They are connected and removed above, with the rest of your devices.',
    kept: 'Kept in this vault',
    empty: 'Nothing kept yet. Import what you already have from another manager.',
    importBtn: 'Import from 1Password, Bitwarden or Chrome',
    imported: (n) => `${n} entr${n === 1 ? 'y' : 'ies'} imported`,
    asking: (q) => `“${q}” is asking for a password`,
    askingText: 'If you say yes, it can ask for credentials while this vault stays open.',
    yes: 'Yes, give it',
    no: 'No',
    askNotifTitle: 'Someone is asking for a password',
    askNotifBody: (q) => `“${q}” is waiting for your answer. Nothing goes out until you reply.`,
    ring_t: 'Tell me when something asks',
    ring_b: 'With this on, your browser tells you even when this tab is closed: tapping the notice opens the vault and answers what was waiting.',
    ring_on: 'Turn on notices',
    ring_ok: 'Notices are on.',
    ring_bad: 'Notices could not be turned on here:',
    anySite: 'any site',
    noIdentity: 'Your Dotrino profile is needed. Create it and come back.',
  },
}
const t = (k, ...a) => {
  const v = (T[props.lang] || T.es)[k] ?? T.es[k] ?? k
  return typeof v === 'function' ? v(...a) : v
}

// --- almacén: IndexedDB de este origen ---------------------------------------

const DB = 'dotrino-vault-passwords'
const STORE = 'kv'

function openDb () {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function idb (mode, fn) {
  const db = await openDb()
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode)
      const req = fn(tx.objectStore(STORE))
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
  } finally { db.close() }
}

const store = {
  async get (k) { return idb('readonly', s => s.get(k)) },
  async set (k, v) { return idb('readwrite', s => s.put(v, k)) },
}

/**
 * LA LLAVE VIEJA, y ya no se estrena ninguna.
 *
 * Hasta ahora esta bóveda tenía una llave suya con la que cifraba todo, aquí mismo en
 * IndexedDB. No extraíble, sí — pero de este navegador, así que **la bóveda podía leer
 * todas las contraseñas**. Es el mismo agujero que se cerró en el binario, y esta pestaña
 * era una de las tres que seguía con él.
 *
 * Ahora solo se lee, y para una cosa: convertir lo que quedó del formato viejo. Después se
 * borra. Si no hay nada que convertir, no se crea ninguna.
 */
async function llaveVieja () {
  const saved = await store.get('cek')
  return saved instanceof CryptoKey ? saved : null
}

/** Y se va con lo último que cifraba: mientras siga ahí, el agujero sigue abierto. */
async function soltarLlaveVieja () { await store.set('cek', null) }

// --- estado -------------------------------------------------------------------

const ready = ref(false)
const error = ref('')
const devices = ref([])
const note = ref('')
const asking = ref(null)
// LA CONTRASEÑA DE LA COPIA DE RECUPERACIÓN. Mientras esto esté puesto, la pantalla pide
// crearla: sin ella no se puede convertir nada, y la bóveda no atiende.
const pidiendoClave = ref(false)
const clave1 = ref('')
const clave2 = ref('')
const claveError = ref('')
const convirtiendo = ref(false)
const claveUna = ref('')
// Cuántas entradas guarda. Es TODO lo que una bóveda que no puede leer sabe de lo suyo, y
// decir eso es más honesto que enseñar una lista de títulos que ya no puede sacar.
const cuantas = ref(0)
// El TIMBRE: si este navegador puede recibir el aviso que despierta la bóveda.
const pushListo = ref(false)
const pushError = ref('')
let encender = null

let identity = null
let sealed = null          // la SealedStore: sobres que esta bóveda no puede abrir
let responder = null
let miPub = null           // la llave de ESTE navegador, para no envolvérsela a sí mismo
let sweeper = null         // el refresco del acta; se para al desmontar

// --- las piezas que necesita quien ESCRIBE (el dueño con su contraseña) -------

/** Los destinatarios de ahora mismo, tal como los pide `buildSealedEntry`. */
async function recipientsAhora () {
  return {
    recoveryPub: recoveryPubOf(await store.get('recovery')),
    main: await recipientsOf('main'),
    passkeys: await recipientsOf('passkeys')
  }
}

/**
 * LA LLAVE DEL PERFIL, abierta con la copia de recuperación. De ella salen el índice de
 * sitios y los resúmenes, así que sin ella no se puede ni guardar ni buscar.
 *
 * Se abre por la envoltura `#recovery`, que es la de quien sabe la contraseña — el mismo
 * camino que usaría el dueño para reparar la bóveda.
 */
async function baseDelPerfil (privateKey) {
  const { envelope, wrap } = await sealed.profile({ pub: RECOVERY })
  const cek = await openWrap({ wrap, myEncPrivateKey: privateKey })
  return decryptWithCek({ cek, envelope })
}

/** Quien firma lo que se escribe: este navegador, que es miembro del acta. */
function autor () {
  // `sign` devuelve `{ signature }`, que es lo que espera `buildSealedEntry` —y es
  // justo lo que da `identity.signData`, así que se pasa tal cual. Desenvolverlo aquí
  // dejaba una firma `undefined` que la bóveda rechaza sin decir por qué.
  return { publickey: miPub, sign: (body) => identity.signData(body) }
}

/**
 * Quién puede pedir credenciales lo dice el ACTA, como cualquier otro permiso: los
 * miembros con la capacidad `passwords` (`caps <ID> +contrasenas`, o al emparejar con
 * `--scope contrasenas`). Aquí no hay una segunda lista ni un código que pegar — un
 * gestor entra como cualquier otro aparato del perfil.
 */
async function listDevices () {
  const r = await identity.profileMembers()
  return (r?.members || []).filter(m => (m.caps || []).includes('passwords'))
}

/**
 * A QUIÉN HAY QUE ENVOLVERLE CADA LLAVE, y aquí está la regla que sostiene todo esto:
 * **esta bóveda NUNCA está en la lista**. Ni su llave ni ninguna otra suya.
 *
 * Es la misma que aplica el binario en `passwordRecipients()`. Si se colara, la bóveda
 * volvería a poder leer y no se notaría nada: seguiría funcionando igual.
 *
 * Un miembro sin `encPub` no puede recibir envolturas — no se le salta en silencio, se
 * queda fuera de la lista y `SealedStore` lo dirá al comprobar los destinatarios.
 */
async function recipientsOf (kind) {
  const r = await identity.profileMembers()
  const cap = kind === 'passkeys' ? 'passkeys' : 'passwords'
  return (r?.members || [])
    .filter((m) => (m.caps || []).includes(cap) && m.encPub && !samePubkey(m.pub, miPub))
    .map((m) => ({ pub: m.pub, encPub: m.encPub }))
}

/**
 * El sobre lo arma el PILAR, no esta pantalla: es la misma pieza que usa la extensión al
 * otro lado (`identitySealing` de `@dotrino/passmanager`). Estaba escrito aquí y allí, y
 * son las dos puntas del mismo sobre — dos copias es una que se queda atrás, y cuando eso
 * pasa no hay error: la petición sale, al otro lado «no es para mí», y desde fuera se ve
 * como que nadie respondió.
 */
let sealing = null

async function refresh () {
  devices.value = await listDevices()
  // NO se listan las entradas, y no es que falte: **esta bóveda ya no puede leerlas**. Lo
  // único que sabe de lo suyo es cuántas hay, y eso es lo que se enseña. Una lista de
  // títulos aquí querría decir que la bóveda los tiene, que es justo lo que se quitó.
  cuantas.value = sealed ? (await sealed.stats()).entries : 0
}

/**
 * IMPORTAR ya no es cosa de la bóveda, y es la consecuencia visible del cambio: para
 * escribir una entrada hay que CERRARLA, y cerrarla necesita la llave del perfil, que
 * ninguna bóveda tiene. Aquí la abre quien sabe la contraseña de la copia de recuperación
 * — que es el dueño, actuando como un aparato más.
 *
 * Se pide en el momento y no se guarda: tenerla en memoria «por comodidad» sería volver a
 * poner una llave dentro de la bóveda con otro nombre.
 */
async function importFile (ev) {
  const f = ev.target.files?.[0]
  if (!f) return
  const texto = await f.text().catch(() => null)
  ev.target.value = ''
  if (!texto) return
  const pwd = await pedirClave(t('importAsk'))
  if (pwd == null) return
  try {
    const { entries: list } = importAuto(texto)
    const priv = await openRecovery({ record: await store.get('recovery'), password: pwd })
    const keys = await profileKeys(await baseDelPerfil(priv))
    const recipients = await recipientsAhora()
    for (const e of list) {
      await sealed.putSealed(await buildSealedEntry({ plain: e, keys, recipients, author: autor() }))
    }
    note.value = t('imported', list.length)
    await refresh()
  } catch (e) {
    error.value = e?.code === 'wrong-password' ? t('badPassword') : (e?.message || String(e))
  }
}

/**
 * CREAR LA COPIA DE RECUPERACIÓN Y CONVERTIR. Es el paso que abre todo lo demás.
 *
 * La contraseña no se guarda en ninguna parte y no se puede recuperar — se dice en
 * pantalla, porque es la mitad del trato: una copia que se pudiera reponer desde este
 * mismo navegador no sería una copia de recuperación, sería otra llave de la bóveda.
 */
async function crearYConvertir () {
  claveError.value = ''
  if (clave1.value.length < 12) { claveError.value = t('pwShort'); return }
  if (clave1.value !== clave2.value) { claveError.value = t('pwMismatch'); return }
  convirtiendo.value = true
  try {
    let record = await store.get('recovery')
    if (!hasRecovery(record)) {
      const hecha = await makeRecovery({ password: clave1.value })
      record = hecha.record
      await store.set('recovery', record)
    }
    const r = await convertToSealed({
      store,
      sealed,
      cek: await llaveVieja(),
      recipients: await recipientsAhora(),
      author: autor(),
      dropOldKey: soltarLlaveVieja
    })
    note.value = t('converted', r.entries)
    clave1.value = ''; clave2.value = ''
    pidiendoClave.value = false
    // La bóveda ya puede atender: se arranca lo que se saltó al entrar.
    ready.value = false
    await arrancar()
  } catch (e) {
    claveError.value = e?.message || String(e)
  } finally { convirtiendo.value = false }
}

/**
 * Pide la contraseña para UNA operación y la devuelve, o `null` si se canceló. No se
 * guarda: tenerla en memoria «por comodidad» sería volver a poner una llave dentro de la
 * bóveda con otro nombre.
 */
let pidiendo = null
const pidiendoTexto = ref('')
function pedirClave (texto) {
  pidiendoTexto.value = texto
  return new Promise((resolve) => { pidiendo = resolve })
}
function responderClave (valor) {
  pidiendoTexto.value = ''
  claveUna.value = ''
  const r = pidiendo; pidiendo = null
  r?.(valor)
}

/**
 * Aprobar es del usuario y está delante: se le pregunta aquí, no en un log.
 *
 * Y si NO está delante —la pestaña en segundo plano, o la ventana minimizada—, se le
 * avisa (dueño, 2026-08-29). Una bóveda que pregunta en una pestaña que nadie mira es
 * una bóveda que no contesta: el que pidió se queda esperando tres minutos y acaba
 * viendo «nadie respondió», sin saber que la respuesta estaba a un clic.
 */
let avisoAbierto = null
function askUser (who) {
  if (typeof document !== 'undefined' && document.hidden) avisar(who)
  return new Promise((resolve) => { asking.value = { who, resolve } })
}
async function avisar (who) {
  try {
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return
    const reg = await navigator.serviceWorker?.ready
    // Por el service worker y no `new Notification(...)`: así se puede pulsar para
    // volver a esta pestaña, que es para lo único que sirve el aviso.
    await reg?.showNotification(t('askNotifTitle'), {
      body: t('askNotifBody', who),
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: 'dotrino-vault-ask',
      renotify: true,
      data: { url: '/vault' },
    })
    avisoAbierto = reg
  } catch (_) { /* sin aviso, la pregunta sigue en la pantalla */ }
}
async function cerrarAviso () {
  try {
    const ns = await avisoAbierto?.getNotifications({ tag: 'dotrino-vault-ask' })
    for (const n of ns || []) n.close()
  } catch (_) {}
  avisoAbierto = null
}
/**
 * Suscribir ESTE navegador al timbre del proxio, bajo la llave del acta.
 *
 * Lo hace el pilar (`enablePush` de `@dotrino/proxy-client`): pide la VAPID al proxio,
 * se suscribe con el service worker que ya tiene la PWA —no registra otro— y deja la
 * suscripción firmada en el proxio. Aquí no se escribe nada de eso a mano.
 */
async function suscribirTimbre (client, publickey) {
  try {
    await client.enablePush({ publicKey: publickey, sign: (data) => identity.signData(data) })
    pushError.value = ''
  } catch (e) {
    // No es un fallo de la bóveda: sigue atendiendo mientras esté abierta. Solo no se
    // la puede despertar, y eso se dice.
    pushError.value = e?.message || String(e)
  }
}

function answer (yes) {
  asking.value?.resolve(yes)
  asking.value = null
  // El aviso se va con la respuesta: uno que sigue ahí después de contestar dice algo
  // que ya no es cierto.
  cerrarAviso()
}

async function arrancar () {
  try {
    // `identity` NUNCA en un ref reactivo: el Proxy de Vue rompe el postMessage al
    // iframe («could not be cloned»). Por eso es un `let` suelto y no un `ref`.
    identity = props.identity || await Identity.connect()

    // QUIÉN ES ESTE NAVEGADOR dentro del acta. Hace falta antes que nada: es lo que se
    // excluye de los destinatarios (una bóveda no se envuelve a sí misma) y lo que firma.
    const yo = await identity.profileMembers()
    miPub = (yo?.members || []).find((m) => m.isMe)?.pub
    if (!miPub) throw new Error('este navegador no está en el acta de su propio perfil')

    // LA BÓVEDA: guarda sobres y comprueba lo que se puede comprobar SIN llave — que los
    // destinatarios son exactamente los del acta, que está la copia de recuperación, y que
    // quien escribe lo firmó y puede escribir.
    sealed = new SealedStore(store, {
      recipients: (kind) => recipientsOf(kind),
      verifyAuthor: async ({ body, author }) => {
        const miembros = (await identity.profileMembers())?.members || []
        const m = miembros.find((x) => samePubkey(x.pub, author?.pub))
        if (!m || !(m.caps || []).includes('passwords')) return false
        return verifyDeviceSig({ publickey: author.pub, data: body, signature: author.sig })
      }
    })

    // ¿HAY QUE CONVERTIR? Si no hay copia de recuperación, esta bóveda todavía es la de
    // antes —una llave suya abriendo todo— y no se atiende hasta arreglarlo. Nada de
    // servir con la llave vieja «mientras tanto»: eso es el agujero con otro nombre.
    if (!hasRecovery(await store.get('recovery')) || !(await sealed.sealed())) {
      pidiendoClave.value = true
      ready.value = true
      return
    }

    sealing = identitySealing(identity)
    const client = new WebSocketProxyClient({
      url: proxyUrl(),
      enableWebRTC: false,
      requireSealed: true,
      sealing,
    })
    await client.connect()
    // SE IDENTIFICA CON LA LLAVE DEL ACTA, no con la del cliente del proxio.
    //
    // Aquí estaba `getPublicKeyJwk()` de `@dotrino/proxy-client`, que es una llave SUYA,
    // guardada en este navegador y sin relación con el perfil. El proxio direcciona por
    // la llave con la que cada uno se identifica, y quien viene a pedir contraseñas
    // —la extensión— direcciona por la del ACTA, que es la única que conoce. Registrarse
    // con otra dejaba esta pestaña escuchando en una dirección a la que nadie escribe:
    // las peticiones salían, no llegaban a nadie, y del otro lado se veían como «nadie
    // respondió a tiempo». Con el daemon no pasaba, porque él sí se identifica con la
    // suya. Encontrado el 2026-08-29 al probar la bóveda de pestaña de punta a punta.
    const publickey = miPub
    const data = { op: 'identify', publickey, token: client.token, ts: Date.now() }
    const { signature } = await identity.signData(data)
    await client.identify({ data, signature })

    // El acta en caché: `isAllowed`/`encPubOf` se llaman por cada mensaje que entra y
    // son SÍNCRONOS, así que se refresca aparte. Quitarle el permiso a un aparato —o
    // quitarlo del perfil— le corta esto en la siguiente pasada.
    let known = await listDevices()
    // El intervalo se guarda fuera: `arrancar()` se puede llamar otra vez (al convertir),
    // y `onBeforeUnmount` solo vale mientras el componente se está montando — registrarlo
    // aquí una segunda vez es un aviso de Vue y un intervalo que no se para.
    if (sweeper) clearInterval(sweeper)
    sweeper = setInterval(() => { listDevices().then(l => { known = l }).catch(() => {}) }, 5000)

    responder = new SealedResponder({
      client,
      store: sealed,
      recipients: () => recipientsAhora(),
      isAllowed: (pub) => known.some(d => samePubkey(d.pub, pub)),
      encPubOf: (pub) => known.find(d => samePubkey(d.pub, pub))?.encPub || null,
      // Qué exige un dedo encima lo decide el responder por defecto: **solo `get`, y
      // solo si lo pedido incluye algo privado** (dueño, 2026-08-29). Rellenar un nombre
      // no es sacar un secreto, y pedir permiso para todo enseña a decir que sí sin
      // mirar. Aquí decía `() => true`, así que esta bóveda preguntaba hasta para buscar.
      approve: async ({ pubkey }) => askUser(known.find(d => samePubkey(d.pub, pubkey))?.label || '?'),
      // Sin mostrador de administración: los aparatos se conectan y se quitan en la
      // consola de arriba, que es la única pantalla del ecosistema donde se hace eso.
      onRequest: async () => { known = await listDevices(); refresh() },
    })
    responder.start()

    // EL TIMBRE. Con la bóveda cerrada, la petición de la extensión se queda encolada en
    // el proxio (24 h) y este navegador recibe un aviso sin contenido; al pulsarlo se
    // abre `/vault`, la bóveda conecta y **baja la cola sola**. Sin esto, una bóveda que
    // vive en una pestaña solo existe mientras la pestaña está abierta.
    //
    // Se suscribe con la MISMA llave con la que se identifica —la del acta—, porque es
    // la dirección por la que le llegan las cosas. Best-effort: si el navegador no lo
    // admite, o el proxio no tiene Web Push, todo lo demás sigue igual.
    pushListo.value = typeof Notification !== 'undefined' && Notification.permission === 'granted'
    if (pushListo.value) suscribirTimbre(client, publickey)
    encender = async () => {
      const ok = await Notification.requestPermission()
      pushListo.value = ok === 'granted'
      if (pushListo.value) await suscribirTimbre(client, publickey)
    }

    await refresh()
    ready.value = true
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

onMounted(arrancar)

onBeforeUnmount(() => { responder?.stop(); if (sweeper) clearInterval(sweeper) })
</script>

<template>
  <section class="vault" data-testid="passwords-desk">
    <p v-if="!ready && !error" class="loading">{{ t('opening') }}</p>

    <template v-if="error">
      <div class="state"><span class="dot"></span><span>{{ t('inactive') }}</span></div>
      <p class="err">{{ error }}</p>
      <p class="hint">{{ t('noIdentity') }}</p>
    </template>

    <!-- CONVERTIR. Mientras esto esté, la bóveda NO atiende: servir con la llave vieja
         «mientras tanto» sería el mismo agujero con otro nombre. -->
    <template v-if="ready && pidiendoClave">
      <h2>{{ t('pwTitle') }}</h2>
      <p class="hint">{{ t('pwWhy') }}</p>
      <p class="warn">{{ t('pwWarn') }}</p>
      <form class="pw" @submit.prevent="crearYConvertir">
        <input v-model="clave1" type="password" :placeholder="t('pw1')" autocomplete="new-password" data-testid="pw1">
        <input v-model="clave2" type="password" :placeholder="t('pw2')" autocomplete="new-password" data-testid="pw2">
        <button type="submit" :disabled="convirtiendo" data-testid="pw-go">
          {{ convirtiendo ? t('pwWorking') : t('pwGo') }}
        </button>
      </form>
      <p v-if="claveError" class="err" data-testid="pw-error">{{ claveError }}</p>
    </template>

    <template v-if="ready && !pidiendoClave">
      <div class="state"><span class="dot on"></span><span>{{ t('active') }}</span></div>
      <p class="warn">{{ t('warning') }}</p>

      <h2>{{ t('devices') }}</h2>
      <ul v-if="devices.length" class="rows">
        <li v-for="d in devices" :key="d.pub" class="row" data-testid="password-device">
          <div>
            <strong>{{ d.label || d.id }}</strong>
            <div class="hint">{{ d.id }}</div>
          </div>
        </li>
      </ul>
      <p v-else class="hint">{{ t('none') }}</p>
      <p v-if="devices.length" class="hint">{{ t('manage') }}</p>

      <h2>{{ t('kept') }}</h2>
      <!-- NI UN TÍTULO, y eso es la noticia: esta bóveda ya no puede leer lo que guarda.
           Enseñar aquí una lista querría decir que los tiene. -->
      <p class="hint" data-testid="kept-count">{{ t('keptCount', cuantas) }}</p>
      <p class="hint">{{ t('keptBlind') }}</p>
      <p v-if="note" class="hint">{{ note }}</p>

      <!-- EL TIMBRE. Es lo único que hace que una bóveda que vive en una pestaña sirva
           con la pestaña cerrada: el pedido queda esperando en el proxio y el aviso trae
           al usuario de vuelta. No se pide el permiso solo al abrir —un navegador que
           pregunta sin que hayas pulsado nada es un navegador que molesta—: se pide aquí,
           y hasta entonces la bóveda funciona igual mientras esté abierta. -->
      <h2>{{ t('ring_t') }}</h2>
      <p class="hint">{{ t('ring_b') }}</p>
      <p v-if="pushListo && !pushError" class="hint" data-testid="ring-on">{{ t('ring_ok') }}</p>
      <button v-else-if="!pushListo" class="import" data-testid="ring-enable" @click="encender && encender()">
        {{ t('ring_on') }}
      </button>
      <p v-if="pushError" class="hint" data-testid="ring-error">{{ t('ring_bad') }} {{ pushError }}</p>
      <label class="import">
        {{ t('importBtn') }}
        <input type="file" accept=".csv,.json,.txt" hidden @change="importFile">
      </label>
    </template>

    <!-- Pedir la contraseña para UNA operación (importar). Sin `prompt()`: bloquea, no se
         traduce y se ve fatal (CONVENCIONES §5). -->
    <div v-if="pidiendoTexto" class="ask-backdrop">
      <form class="ask" @submit.prevent="responderClave(claveUna)">
        <strong>{{ pidiendoTexto }}</strong>
        <input v-model="claveUna" type="password" :placeholder="t('pw1')" autocomplete="current-password" data-testid="ask-pw">
        <div class="ask-row">
          <button type="button" class="danger" @click="responderClave(null); claveUna = ''">{{ t('askPwNo') }}</button>
          <button type="submit" data-testid="ask-pw-ok">{{ t('askPwOk') }}</button>
        </div>
      </form>
    </div>

    <!-- Sin `confirm()`: bloquea, no se traduce y se ve mal (CONVENCIONES §5). -->
    <div v-if="asking" class="ask-backdrop">
      <div class="ask">
        <strong>{{ t('asking', asking.who) }}</strong>
        <p class="hint">{{ t('askingText') }}</p>
        <div class="ask-row">
          <button class="danger" data-testid="deny" @click="answer(false)">{{ t('no') }}</button>
          <button data-testid="approve" @click="answer(true)">{{ t('yes') }}</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
/* Es una sección de la consola, no una página: el ancho y el aire los pone `/vault`. */
.vault { padding: 0; }
h2 { font-size: .95rem; margin: 1.4rem 0 .6rem; opacity: .85; }
.loading, .hint { opacity: .7; font-size: .9rem; }
.err { color: #ff8a8a; font-size: .9rem; }
.state { display: flex; align-items: center; gap: .6rem; font-weight: 600; }
.dot { width: .7rem; height: .7rem; border-radius: 50%; background: #777; }
.dot.on { background: #35d07f; box-shadow: 0 0 .6rem #35d07f; }
.warn { margin: .8rem 0 0; padding: .8rem 1rem; border-left: 3px solid #f0b429;
        background: rgba(240,180,41,.08); font-size: .9rem; }
.rows { list-style: none; margin: 0; padding: 0; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 1rem;
       padding: .7rem 0; border-bottom: 1px solid rgba(255,255,255,.08); }
button, .import { cursor: pointer; padding: .55rem .9rem; border-radius: .5rem; border: 0;
                  background: #2f6df6; color: #fff; font: inherit; }
button.danger { background: transparent; color: #ff8a8a; border: 1px solid rgba(255,138,138,.4); }
.import { display: inline-block; margin-top: .8rem; }
.ask-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: grid;
                place-items: center; padding: 1rem; z-index: 50; }
.ask { max-width: 26rem; background: #14161c; padding: 1.4rem; border-radius: .8rem;
       border: 1px solid rgba(255,255,255,.12); }
.ask-row { display: flex; gap: .6rem; justify-content: flex-end; margin-top: 1rem; }
.pw { display: flex; flex-wrap: wrap; gap: .6rem; margin: .8rem 0; }
.pw input, .ask input { flex: 1 1 12rem; padding: .55rem .7rem; border-radius: .5rem; font: inherit;
        border: 1px solid rgba(255,255,255,.18); background: #0f1116; color: inherit; }
.ask input { margin-top: .8rem; width: 100%; }
</style>
