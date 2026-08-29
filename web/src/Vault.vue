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
import { WebSocketProxyClient, getPublicKeyJwk, signData } from '@dotrino/proxy-client'
import { LocalVault, VaultResponder, samePubkey, importAuto } from '@dotrino/passmanager'

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
    anySite: 'cualquier sitio',
    noIdentity: 'Hace falta tu perfil de Dotrino. Créalo y vuelve.',
  },
  en: {
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
 * La llave vive como `CryptoKey` NO EXTRAÍBLE: IndexedDB la clona en vez de
 * serializarla, así que nunca existe en forma exportable — ni este código puede sacarla.
 * Y se comprueba QUÉ hay guardado, no solo que haya algo: un dato viejo reventaba dentro
 * de WebCrypto con un error que no dice de dónde viene.
 */
async function vaultKey () {
  const saved = await store.get('cek')
  if (saved instanceof CryptoKey) return saved
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  await store.set('cek', key)
  return key
}

// --- estado -------------------------------------------------------------------

const ready = ref(false)
const error = ref('')
const devices = ref([])
const entries = ref([])
const note = ref('')
const asking = ref(null)

let identity = null
let vault = null
let responder = null

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

const sealing = {
  async seal (msg, peerEncPub) {
    if (!peerEncPub) throw Object.assign(new Error('no encryption key'), { code: 'unsealed' })
    return {
      app: 'passmanager',
      // Destinatarios como OBJETOS: `encrypt` expande cada uno a todos los aparatos de
      // esa persona, y una llave suelta se le cae sin envolver nada — el sobre salía
      // vacío, sin error, y al otro lado era «no es para mí».
      sealed: await identity.encrypt([{ encryptionPubkey: peerEncPub }], JSON.stringify(msg)),
      from: await identity.getEncryptionPubkey(),
    }
  },
  // `decrypt` devuelve `{ plaintext }`, no la cadena.
  async open (env) {
    return JSON.parse((await identity.decrypt(env.from, null, env.sealed)).plaintext)
  },
  isSealed: (m) => !!m && m.app === 'passmanager' && !!m.sealed,
}

async function refresh () {
  devices.value = await listDevices()
  entries.value = vault ? await vault.list() : []
}

async function importFile (ev) {
  const f = ev.target.files?.[0]
  if (!f) return
  try {
    const { entries: list } = importAuto(await f.text())
    for (const e of list) await vault.put(e)
    note.value = t('imported', list.length)
    await refresh()
  } catch (e) { error.value = e.message }
  ev.target.value = ''
}

/** Aprobar es del usuario y está delante: se le pregunta aquí, no en un log. */
function askUser (who) {
  return new Promise((resolve) => { asking.value = { who, resolve } })
}
function answer (yes) {
  asking.value?.resolve(yes)
  asking.value = null
}

onMounted(async () => {
  try {
    // `identity` NUNCA en un ref reactivo: el Proxy de Vue rompe el postMessage al
    // iframe («could not be cloned»). Por eso es un `let` suelto y no un `ref`.
    identity = props.identity || await Identity.connect()
    vault = new LocalVault(store)
    vault.unlock(await vaultKey())

    const client = new WebSocketProxyClient({
      url: proxyUrl(),
      enableWebRTC: false,
      requireSealed: true,
      sealing,
    })
    await client.connect()
    const publickey = await getPublicKeyJwk()
    const data = { op: 'identify', publickey, token: client.token, ts: Date.now() }
    await client.identify({ data, signature: await signData(data) })

    // El acta en caché: `isAllowed`/`encPubOf` se llaman por cada mensaje que entra y
    // son SÍNCRONOS, así que se refresca aparte. Quitarle el permiso a un aparato —o
    // quitarlo del perfil— le corta esto en la siguiente pasada.
    let known = await listDevices()
    const sweeper = setInterval(() => { listDevices().then(l => { known = l }).catch(() => {}) }, 5000)
    onBeforeUnmount(() => clearInterval(sweeper))

    responder = new VaultResponder({
      client,
      vault,
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

    await refresh()
    ready.value = true
  } catch (e) {
    error.value = e?.message || String(e)
  }
})

onBeforeUnmount(() => responder?.stop())
</script>

<template>
  <section class="vault">
    <p v-if="!ready && !error" class="loading">{{ t('opening') }}</p>

    <template v-if="error">
      <div class="state"><span class="dot"></span><span>{{ t('inactive') }}</span></div>
      <p class="err">{{ error }}</p>
      <p class="hint">{{ t('noIdentity') }}</p>
    </template>

    <template v-if="ready">
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
      <ul v-if="entries.length" class="rows">
        <li v-for="e in entries" :key="e.id" class="row">
          <div>
            <strong>{{ e.title || e.sites?.[0] || '—' }}</strong>
            <div class="hint">{{ (e.sites || []).join(' ') || t('anySite') }}</div>
          </div>
          <span class="hint">{{ [e.hasSecret && '🔑', e.hasTotp && '2FA', e.hasFields && '+'].filter(Boolean).join(' ') }}</span>
        </li>
      </ul>
      <p v-else class="hint">{{ t('empty') }}</p>
      <p v-if="note" class="hint">{{ note }}</p>
      <label class="import">
        {{ t('importBtn') }}
        <input type="file" accept=".csv,.json,.txt" hidden @change="importFile">
      </label>
    </template>

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
</style>
