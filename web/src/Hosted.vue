<script setup>
/**
 * LA BÓVEDA EN LA NUBE (`/hosted`): contratarla, activarla y ver o cancelar las tuyas.
 *
 * Es una pantalla administrativa (CONVENCIONES §5.1): precio, un botón y tus suscripciones; lo
 * que explica va en el wiki. Habla con `accounts.dotrino.com` (`dotrino-accounts`), que cobra
 * con PayPal y crea la bóveda en AWS:
 *
 *   1. «Contratar» pide la suscripción y se va a PayPal. Lo que identifica la compra (`id` y
 *      `claim`) se queda en esta pestaña (sessionStorage): solo quien compró ve la activación.
 *   2. PayPal vuelve aquí con `?sub=<id>`. Se confirma, y mientras la bóveda se crea (unos
 *      minutos) se pregunta cada pocos segundos.
 *   3. Lista: se enseña la dirección para «Iniciar sesión» y el código de activación, que es la
 *      contraseña de la primera vez.
 *
 * Lo tuyo (ver y cancelar) va firmado por tu perfil (`signedFor` del pilar): no hay cuenta ni
 * contraseña aparte en Dotrino. Dentro de una app nativa no se vende nada (`noPayments`).
 */
import { ref, computed, onMounted, onBeforeUnmount, markRaw } from 'vue'
import { Identity } from '@dotrino/identity'
import { signedFor } from '@dotrino/identity/assertion'
import { noPayments } from '@dotrino/support/policy'
import { identityOptions } from './identity.js'

const props = defineProps({ lang: { type: String, default: 'es' } })

const ACCOUNTS = (import.meta.env.VITE_ACCOUNTS_URL || 'https://accounts.dotrino.com').replace(/\/$/, '')
const AUD = 'https://accounts.dotrino.com'
const FORMAT_V = 1
const PENDING_KEY = 'vault.hosted.pending'
const WIKI = { es: 'https://wiki.dotrino.com/vault/nube/', en: 'https://wiki.dotrino.com/en/vault/nube/' }

const T = {
  es: {
    title: 'Bóveda en la nube',
    lead: 'Tu bóveda siempre localizable, sin tener una computadora encendida.',
    price: (p) => `US$ ${p.subtotal} al mes + IVA (US$ ${p.total} en total). Se renueva sola cada mes y la cancelas cuando quieras.`,
    buy: 'Contratar con PayPal',
    buying: 'Abriendo PayPal…',
    native: 'La bóveda en la nube se contrata desde el navegador, en vault.dotrino.com/hosted.',
    howto: 'Cómo funciona',
    back_working: 'Confirmando el pago…',
    creating: 'Estamos creando tu bóveda. Tarda unos minutos; puedes dejar esta pestaña abierta.',
    ready: 'Tu bóveda está lista.',
    login: 'Para entrar, abre «Iniciar sesión» en el menú del perfil y escribe:',
    address: 'Dirección',
    code: 'Código de activación (es tu contraseña la primera vez)',
    keep: 'Guárdalo ahora: esta pantalla solo lo enseña en esta pestaña. Cámbialo después de entrar.',
    copy: 'Copiar', copied: 'Copiado',
    failed: 'No pudimos crear la bóveda. No se te cobrará el mes siguiente.',
    pending: 'PayPal todavía no confirma el pago. Si lo aprobaste, espera un momento.',
    lost: 'Esta compra no se empezó en esta pestaña, así que no podemos enseñarte su activación aquí.',
    mine: 'Tus bóvedas en la nube',
    none: 'Todavía no tienes ninguna.',
    no_profile: 'Abre o crea tu perfil para ver tus bóvedas en la nube.',
    status: { ACTIVE: 'Activa', APPROVAL_PENDING: 'Esperando a PayPal', SUSPENDED: 'Pago pendiente', CANCELLED: 'Cancelada', EXPIRED: 'Vencida' },
    on: 'encendida', off: 'apagada',
    paid_through: (d) => `pagada hasta el ${d}`,
    cancel: 'Cancelar', cancel_sure: 'Seguirá encendida hasta el fin de lo pagado y después se apagará; lo guardado no se borra.', cancel_yes: 'Sí, cancelar', keep_it: 'No',
    error: 'Algo falló. Inténtalo de nuevo.',
    errors: { 'payments-unavailable': 'Ahora mismo no se puede contratar. Inténtalo más tarde.', 'payment-declined': 'PayPal no aceptó esa forma de pago. Elige otra.', unreachable: 'No hay conexión con el servicio. Inténtalo de nuevo.' },
  },
  en: {
    title: 'Vault in the cloud',
    lead: 'Your vault always reachable, without a computer on.',
    price: (p) => `US$ ${p.subtotal} a month + VAT (US$ ${p.total} in total). It renews every month and you cancel whenever you want.`,
    buy: 'Subscribe with PayPal',
    buying: 'Opening PayPal…',
    native: 'The vault in the cloud is subscribed from the browser, at vault.dotrino.com/hosted.',
    howto: 'How it works',
    back_working: 'Confirming the payment…',
    creating: 'We are creating your vault. It takes a few minutes; you can leave this tab open.',
    ready: 'Your vault is ready.',
    login: 'To get in, open «Sign in» in the profile menu and type:',
    address: 'Address',
    code: 'Activation code (your password the first time)',
    keep: 'Save it now: this screen only shows it in this tab. Change it after signing in.',
    copy: 'Copy', copied: 'Copied',
    failed: 'We could not create the vault. You will not be charged next month.',
    pending: 'PayPal has not confirmed the payment yet. If you approved it, wait a moment.',
    lost: 'This purchase was not started in this tab, so we cannot show its activation here.',
    mine: 'Your vaults in the cloud',
    none: 'You do not have any yet.',
    no_profile: 'Open or create your profile to see your vaults in the cloud.',
    status: { ACTIVE: 'Active', APPROVAL_PENDING: 'Waiting for PayPal', SUSPENDED: 'Payment pending', CANCELLED: 'Cancelled', EXPIRED: 'Expired' },
    on: 'on', off: 'off',
    paid_through: (d) => `paid until ${d}`,
    cancel: 'Cancel', cancel_sure: 'It stays on until the end of what you paid and then turns off; nothing stored is deleted.', cancel_yes: 'Yes, cancel', keep_it: 'No',
    error: 'Something went wrong. Try again.',
    errors: { 'payments-unavailable': 'You cannot subscribe right now. Try later.', 'payment-declined': 'PayPal did not accept that payment method. Pick another one.', unreachable: 'No connection to the service. Try again.' },
  },
}
const t = computed(() => T[props.lang] || T.es)
const wiki = computed(() => WIKI[props.lang] || WIKI.es)
const native = noPayments()

class ApiError extends Error { constructor (code, message) { super(message); this.code = code } }
async function api (method, path, body) {
  let res
  try {
    res = await fetch(ACCOUNTS + path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined })
  } catch (e) { throw new ApiError('unreachable', e.message) }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new ApiError(data.code || 'http-' + res.status, data.error || res.statusText)
  return data
}
const errorText = (e) => t.value.errors[e?.code] || t.value.error

const price = ref(null)
const busy = ref(false)
const notice = ref(null) // { kind: 'ok' | 'error', text }

// ----- comprar -----
async function buy () {
  busy.value = true
  notice.value = null
  try {
    const r = await api('POST', '/subscribe')
    try { sessionStorage.setItem(PENDING_KEY, JSON.stringify({ id: r.id, claim: r.claim })) } catch (_) {}
    location.href = r.approveUrl
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; busy.value = false }
}

// ----- la vuelta de PayPal y la activación -----
const purchase = ref(null) // la vista de la compra de esta pestaña (lo que da `confirm` / `status`)
let timer = null
async function finishPurchase () {
  const sub = new URLSearchParams(location.search).get('sub')
  if (!sub) return
  history.replaceState(null, '', location.pathname)
  let pending = null
  try { pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || 'null') } catch (_) {}
  if (!pending || pending.id !== sub) { notice.value = { kind: 'error', text: t.value.lost }; return }
  notice.value = { kind: 'ok', text: t.value.back_working }
  try { purchase.value = await api('POST', '/confirm', pending) } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; return }
  notice.value = null
  poll(pending)
}
function poll (pending) {
  clearTimeout(timer)
  const v = purchase.value
  if (!v || v.stack !== 'creating') {
    if (v?.stack === 'ready') loadMine()
    return
  }
  timer = setTimeout(async () => {
    try { purchase.value = await api('POST', '/status', pending) } catch (_) {}
    poll(pending)
  }, 5000)
}
onBeforeUnmount(() => clearTimeout(timer))

const copied = ref('')
async function copy (what, text) {
  try { await navigator.clipboard.writeText(text); copied.value = what; setTimeout(() => { if (copied.value === what) copied.value = '' }, 1500) } catch (_) {}
}

// ----- lo mío, firmado por el perfil -----
const identity = ref(null)
const hasProfile = ref(true)
const mine = ref([])
const cancelling = ref(null)
async function connect () {
  try {
    const id = markRaw(await Identity.connect(identityOptions()))
    const chain = await id.sealerChain()
    if (!Array.isArray(chain) || !chain.length) { hasProfile.value = false; return }
    identity.value = id
  } catch (_) { hasProfile.value = false }
}
const signed = (fields) => signedFor(identity.value, { aud: AUD, fields: { v: FORMAT_V, ...fields } })
async function loadMine () {
  if (!identity.value) return
  try { mine.value = await api('POST', '/mine', { req: await signed({ op: 'mine' }) }) } catch (e) { notice.value = { kind: 'error', text: errorText(e) } }
}
async function cancel (s) {
  busy.value = true
  try {
    await api('POST', '/cancel', { id: s.id, req: await signed({ op: 'cancel', id: s.id }) })
    cancelling.value = null
    await loadMine()
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) } } finally { busy.value = false }
}
const fmtDate = (ts) => new Intl.DateTimeFormat(props.lang, { dateStyle: 'medium' }).format(new Date(ts))

onMounted(async () => {
  if (native) return
  api('GET', '/price').then((p) => { price.value = p }).catch(() => {})
  await connect()
  await finishPurchase()
  await loadMine()
})
</script>

<template>
  <section class="hosted" data-testid="hosted">
    <h1>{{ t.title }}</h1>
    <p class="lead">{{ t.lead }} <a :href="wiki" rel="noopener">{{ t.howto }}</a></p>

    <p v-if="native" class="muted" data-testid="hosted-native">{{ t.native }}</p>

    <template v-else>
      <p v-if="notice" :class="['notice', notice.kind]" role="status" data-testid="hosted-notice">{{ notice.text }}</p>

      <div v-if="purchase" class="card" data-testid="hosted-purchase">
        <p v-if="purchase.stack === 'creating'" data-testid="hosted-creating">{{ t.creating }}</p>
        <p v-else-if="purchase.stack === 'failed'" class="notice error">{{ t.failed }}</p>
        <p v-else-if="purchase.stack === 'none'" class="muted">{{ t.pending }}</p>
        <template v-else-if="purchase.stack === 'ready'">
          <p><strong>{{ t.ready }}</strong> {{ t.login }}</p>
          <dl class="creds">
            <dt>{{ t.address }}</dt>
            <dd><code data-testid="hosted-login">{{ purchase.login }}</code>
              <button class="btn btn-ghost small" @click="copy('login', purchase.login)">{{ copied === 'login' ? t.copied : t.copy }}</button></dd>
            <template v-if="purchase.activation">
              <dt>{{ t.code }}</dt>
              <dd><code data-testid="hosted-code">{{ purchase.activation }}</code>
                <button class="btn btn-ghost small" @click="copy('code', purchase.activation)">{{ copied === 'code' ? t.copied : t.copy }}</button></dd>
            </template>
          </dl>
          <p v-if="purchase.activation" class="warn">{{ t.keep }}</p>
        </template>
      </div>

      <div v-else class="card" data-testid="hosted-buy">
        <p v-if="price" class="price" data-testid="hosted-price">{{ t.price(price) }}</p>
        <button class="btn btn-primary" :disabled="busy || !price" @click="buy" data-testid="hosted-subscribe">{{ busy ? t.buying : t.buy }}</button>
      </div>

      <div class="card" data-testid="hosted-mine">
        <h2>{{ t.mine }}</h2>
        <p v-if="!hasProfile" class="muted">{{ t.no_profile }}</p>
        <p v-else-if="!mine.length" class="muted">{{ t.none }}</p>
        <article v-for="s in mine" :key="s.id" class="sub" :data-sub-id="s.id" data-testid="hosted-sub">
          <p>
            <strong>{{ s.login || s.id.slice(0, 8) }}</strong> ·
            {{ t.status[s.status] || s.status }} · {{ s.on ? t.on : t.off }}<template v-if="s.paidThrough"> · {{ t.paid_through(fmtDate(s.paidThrough)) }}</template>
          </p>
          <p v-if="s.status === 'ACTIVE' || s.status === 'SUSPENDED'" class="row">
            <template v-if="cancelling === s.id">
              <span class="warn">{{ t.cancel_sure }}</span>
              <button class="btn btn-primary small" :disabled="busy" @click="cancel(s)" data-testid="hosted-cancel-yes">{{ t.cancel_yes }}</button>
              <button class="btn btn-ghost small" @click="cancelling = null">{{ t.keep_it }}</button>
            </template>
            <button v-else class="btn btn-ghost small" :disabled="busy" @click="cancelling = s.id" data-testid="hosted-cancel">{{ t.cancel }}</button>
          </p>
        </article>
      </div>
    </template>
  </section>
</template>

<style scoped>
.hosted { max-width: 720px; margin: 24px auto 64px; }
.lead { color: var(--muted); }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; margin: 16px 0; }
.price { font-weight: 700; }
.creds { display: grid; grid-template-columns: auto 1fr; gap: 6px 14px; align-items: center; }
.creds dt { color: var(--muted); }
.creds dd { margin: 0; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.creds code { font-size: 1.05rem; word-break: break-all; }
.notice { padding: 10px 14px; border-radius: 12px; border: 1px solid var(--line); }
.notice.error { border-color: var(--dt-danger, #b3261e); }
.warn { color: var(--dt-danger, #b3261e); }
.muted { color: var(--muted); }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.sub + .sub { border-top: 1px solid var(--line); }
.small { padding: 6px 12px; font-size: .9rem; }
</style>
