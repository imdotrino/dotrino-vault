<script setup>
/**
 * LA RÉPLICA EN LA NUBE (`/hosted`): contratarla, enrolarla en tu cuenta y ver o cancelar las
 * tuyas (`dotrino-accounts/docs/DISENO.md` §8.bis y §9).
 *
 * Es una pantalla administrativa (CONVENCIONES §5.1): precio, un botón y tus réplicas; lo que
 * explica va en el wiki. Habla con `accounts.dotrino.com` (`dotrino-accounts`), que cobra con
 * PayPal y crea la réplica en AWS. TODO va firmado por tu perfil (`signedFor` del pilar): la
 * réplica es de tu cuenta desde la compra, y se administra desde aquí sin cambiar de perfil.
 *
 *   1. «Contratar» pide la suscripción (firmada) y se va a PayPal. PayPal vuelve con `?sub=`.
 *   2. Se confirma y la réplica se crea VACÍA (tarda un par de minutos).
 *   3. Se enrola con una INVITACIÓN de tu bóveda: la saca este navegador si él es tu bóveda, o
 *      la pegas desde la máquina donde corre (`dotrino-vault pair --scope replica --quiet`). La
 *      réplica pide el alta y aquí sale el código, que apruebas en tu bóveda. Va después del
 *      pago porque una invitación caduca a los 5 minutos.
 *
 * Dentro de una app nativa no se vende nada (`noPayments`).
 */
import { ref, computed, onMounted, onBeforeUnmount, markRaw } from 'vue'
import { Identity } from '@dotrino/identity'
import { signedFor } from '@dotrino/identity/assertion'
import { noPayments } from '@dotrino/support/policy'
import { encodeInvite } from '../../lib/src/invite.js'
import { identityOptions } from './identity.js'

const props = defineProps({ lang: { type: String, default: 'es' } })

const ACCOUNTS = (import.meta.env.VITE_ACCOUNTS_URL || 'https://accounts.dotrino.com').replace(/\/$/, '')
const AUD = 'https://accounts.dotrino.com'
const FORMAT_V = 1
const PRODUCT = 'replica'
const WIKI = { es: 'https://wiki.dotrino.com/vault/nube/', en: 'https://wiki.dotrino.com/en/vault/nube/' }
const PAIR_CMD = 'dotrino-vault pair --scope replica --quiet'

const T = {
  es: {
    title: 'Réplica en la nube',
    lead: 'Tu cuenta contesta aunque tu bóveda esté apagada.',
    price: (p) => `US$ ${p.subtotal} al mes + IVA (US$ ${p.total} en total). Se renueva sola cada mes y la cancelas cuando quieras.`,
    buy: 'Contratar con PayPal',
    buying: 'Abriendo PayPal…',
    native: 'La réplica en la nube se contrata desde el navegador, en vault.dotrino.com/hosted.',
    howto: 'Cómo funciona',
    no_profile: 'Abre o crea tu perfil para contratar y ver tus réplicas.',
    back_working: 'Confirmando el pago…',
    mine: 'Tus réplicas',
    none: 'Todavía no tienes ninguna.',
    replica: (d) => d ? `Réplica ${d}` : 'Réplica',
    status: { ACTIVE: 'Activa', APPROVAL_PENDING: 'Esperando a PayPal', SUSPENDED: 'Pago pendiente', CANCELLED: 'Cancelada', EXPIRED: 'Vencida', COMP: 'Sin cargo' },
    stack: { creating: 'creándose', failed: 'no se pudo crear', deleted: 'borrada' },
    in_account: 'en tu cuenta',
    on: 'encendida', off: 'apagada',
    paid_through: (d) => `pagada hasta el ${d}`,
    creating: 'Se está creando. Tarda un par de minutos.',
    failed: 'No se pudo crear. Se canceló y se te devuelve lo cobrado.',
    enroll_h: 'Añádela a tu cuenta',
    enroll_before: (d) => `Si no la añades antes del ${d}, se cancela y se te devuelve lo cobrado.`,
    enroll_before_comp: (d) => `Si no la añades antes del ${d}, se borra.`,
    enroll_here: 'Sacar la invitación en este navegador',
    enroll_paste: 'O, en la máquina de tu bóveda, ejecuta esto y pega aquí lo que imprime:',
    enroll_placeholder: 'La invitación',
    enroll_go: 'Añadir',
    enrolling: 'Pidiendo el alta…',
    code_h: 'Aprueba este código en tu bóveda',
    code_cli: (c) => `dotrino-vault approve ${c}`,
    code_approve: 'Aprobarlo',
    self_starting: 'Tu bóveda está arrancando…',
    self_error: {
      'not-sealer': 'Este navegador no puede ser la bóveda de la cuenta abierta aquí: entraste con usuario y contraseña. Usa la invitación de tu bóveda.',
      'no-record': 'Esta cuenta todavía no tiene acta: abre tu perfil una vez.',
      'profile-changed': 'Cambió la cuenta abierta en esta pestaña. Recárgala.'
    },
    self_error_other: 'Tu bóveda no arrancó en este navegador.',
    code_wait: 'Cuando lo apruebes, aquí saldrá «en tu cuenta». La invitación vale 5 minutos: si caduca, saca otra.',
    copy: 'Copiar', copied: 'Copiado',
    cancel: 'Cancelar', cancel_sure: 'Seguirá encendida hasta el fin de lo pagado y después se apagará.', cancel_yes: 'Sí, cancelar', keep_it: 'No',
    error: 'Algo falló. Inténtalo de nuevo.',
    errors: {
      'payments-unavailable': 'Ahora mismo no se puede contratar. Inténtalo más tarde.',
      'payment-declined': 'PayPal no aceptó esa forma de pago. Elige otra.',
      unreachable: 'No hay conexión con el servicio. Inténtalo de nuevo.',
      'enroll-failed': 'La invitación no sirvió (caducada o ya usada). Saca otra.',
      'no-code': 'La réplica no recibió respuesta de tu bóveda. ¿Está encendida? Saca otra invitación.',
      'already-enrolled': 'Esta réplica ya está en tu cuenta.',
      'lease-busy': 'La réplica sigue esperando la invitación anterior. Inténtalo de nuevo en unos minutos.',
      'wrong-account': 'Esa invitación es de otra cuenta. La réplica solo entra en la cuenta con la que la compraste.'
    },
  },
  en: {
    title: 'Replica in the cloud',
    lead: 'Your account answers even with your vault off.',
    price: (p) => `US$ ${p.subtotal} a month + VAT (US$ ${p.total} in total). It renews every month and you cancel whenever you want.`,
    buy: 'Subscribe with PayPal',
    buying: 'Opening PayPal…',
    native: 'The replica in the cloud is subscribed from the browser, at vault.dotrino.com/hosted.',
    howto: 'How it works',
    no_profile: 'Open or create your profile to subscribe and see your replicas.',
    back_working: 'Confirming the payment…',
    mine: 'Your replicas',
    none: 'You do not have any yet.',
    replica: (d) => d ? `Replica ${d}` : 'Replica',
    status: { ACTIVE: 'Active', APPROVAL_PENDING: 'Waiting for PayPal', SUSPENDED: 'Payment pending', CANCELLED: 'Cancelled', EXPIRED: 'Expired', COMP: 'No charge' },
    stack: { creating: 'being created', failed: 'could not be created', deleted: 'deleted' },
    in_account: 'in your account',
    on: 'on', off: 'off',
    paid_through: (d) => `paid until ${d}`,
    creating: 'It is being created. It takes a couple of minutes.',
    failed: 'It could not be created. It was cancelled and you get your money back.',
    enroll_h: 'Add it to your account',
    enroll_before: (d) => `If you do not add it before ${d}, it is cancelled and you get your money back.`,
    enroll_before_comp: (d) => `If you do not add it before ${d}, it is deleted.`,
    enroll_here: 'Get the invitation in this browser',
    enroll_paste: 'Or, on your vault\'s machine, run this and paste what it prints:',
    enroll_placeholder: 'The invitation',
    enroll_go: 'Add',
    enrolling: 'Asking to join…',
    code_h: 'Approve this code on your vault',
    code_cli: (c) => `dotrino-vault approve ${c}`,
    code_approve: 'Approve it',
    self_starting: 'Your vault is starting…',
    self_error: {
      'not-sealer': 'This browser cannot be the vault of the account open here: you signed in with a username and password. Use your vault\'s invitation.',
      'no-record': 'This account has no record yet: open your profile once.',
      'profile-changed': 'The account open in this tab changed. Reload it.'
    },
    self_error_other: 'Your vault did not start in this browser.',
    code_wait: 'Once you approve it, it will say «in your account» here. The invitation lasts 5 minutes: if it expires, get another one.',
    copy: 'Copy', copied: 'Copied',
    cancel: 'Cancel', cancel_sure: 'It stays on until the end of what you paid and then turns off.', cancel_yes: 'Yes, cancel', keep_it: 'No',
    error: 'Something went wrong. Try again.',
    errors: {
      'payments-unavailable': 'You cannot subscribe right now. Try later.',
      'payment-declined': 'PayPal did not accept that payment method. Pick another one.',
      unreachable: 'No connection to the service. Try again.',
      'enroll-failed': 'The invitation did not work (expired or already used). Get another one.',
      'no-code': 'The replica got no answer from your vault. Is it on? Get another invitation.',
      'already-enrolled': 'This replica is already in your account.',
      'lease-busy': 'The replica is still waiting on the previous invitation. Try again in a few minutes.',
      'wrong-account': 'That invitation is from another account. The replica only joins the account you bought it with.'
    },
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
const busy = ref('')
const notice = ref(null) // { kind: 'ok' | 'error', text }

// ----- el perfil: todo lo que se pide va firmado por él -----
const identity = ref(null)
const hasProfile = ref(true)
// ¿Este navegador ES la bóveda de la cuenta? `enabled` lo dice el ajuste; `running`, si ya
// arrancó. Arranca después de que la página pregunte, así que mientras esté encendida y sin
// arrancar se vuelve a mirar: leerlo una vez dejaba el botón fuera para siempre.
const selfVault = ref({ enabled: false, running: false })
let selfTimer = null
async function refreshSelfVault () {
  clearTimeout(selfTimer)
  try { selfVault.value = await identity.value.selfVaultStatus() } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; return }
  // Si no arrancó y dijo por qué, no hay nada que esperar: se enseña.
  if (selfVault.value.enabled && !selfVault.value.running && !selfVault.value.error) selfTimer = setTimeout(refreshSelfVault, 1000)
}
async function connect () {
  try {
    const id = markRaw(await Identity.connect(identityOptions()))
    const chain = await id.sealerChain()
    if (!Array.isArray(chain) || !chain.length) { hasProfile.value = false; return }
    identity.value = id
  } catch (_) { hasProfile.value = false; return }
  await refreshSelfVault()
}
const signed = (fields) => signedFor(identity.value, { aud: AUD, fields: { v: FORMAT_V, ...fields } })

// ----- comprar -----
async function buy () {
  busy.value = 'buy'
  notice.value = null
  try {
    const r = await api('POST', '/subscribe', { req: await signed({ op: 'subscribe', product: PRODUCT }) })
    location.href = r.approveUrl
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; busy.value = '' }
}

// ----- la vuelta de PayPal -----
async function finishPurchase () {
  const sub = new URLSearchParams(location.search).get('sub')
  if (!sub || !identity.value) return
  history.replaceState(null, '', location.pathname)
  notice.value = { kind: 'ok', text: t.value.back_working }
  try { await api('POST', '/confirm', { id: sub, req: await signed({ op: 'confirm', id: sub }) }); notice.value = null } catch (e) { notice.value = { kind: 'error', text: errorText(e) } }
}

// ----- las mías -----
const mine = ref([])
const cancelling = ref(null)
const invitation = ref({}) // id -> lo pegado
const codes = ref({})      // id -> el código que salió al enrolar
let timer = null
async function loadMine () {
  if (!identity.value) return
  try { mine.value = await api('POST', '/mine', { req: await signed({ op: 'mine' }) }) } catch (e) { notice.value = { kind: 'error', text: errorText(e) } }
  clearTimeout(timer)
  // Mientras algo está en marcha (creándose, o esperando a que apruebes el código) se mira solo.
  if (mine.value.some((s) => s.stack === 'creating' || (s.stack === 'ready' && !s.enrolled && codes.value[s.id]))) timer = setTimeout(loadMine, 5000)
}
onBeforeUnmount(() => { clearTimeout(timer); clearTimeout(selfTimer) })

async function enroll (s, fromHere) {
  busy.value = 'enroll:' + s.id
  notice.value = null
  try {
    let inv = (invitation.value[s.id] || '').trim()
    if (fromHere) {
      const r = await identity.value.selfVaultPairing({ scope: ['vault:replica'], caps: ['replica'] })
      inv = encodeInvite(r.qr)
    }
    const r = await api('POST', '/enroll', { id: s.id, invitation: inv, req: await signed({ op: 'enroll', id: s.id }) })
    codes.value = { ...codes.value, [s.id]: r.code }
    await loadMine()
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) } } finally { busy.value = '' }
}

// Si la bóveda es ESTE navegador, el código pendiente vive en esta pestaña (la que tiene la
// bóveda), y «Mi bóveda» abierta en otra no lo ve: se aprueba aquí, con el mismo código.
async function approveHere (s) {
  busy.value = 'approve:' + s.id
  notice.value = null
  try {
    await identity.value.selfVaultApprove(s.device, codes.value[s.id])
    await loadMine()
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) } } finally { busy.value = '' }
}

async function cancel (s) {
  busy.value = 'cancel'
  try {
    await api('POST', '/cancel', { id: s.id, req: await signed({ op: 'cancel', id: s.id }) })
    cancelling.value = null
    await loadMine()
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) } } finally { busy.value = '' }
}

const copied = ref('')
async function copy (what, text) {
  try { await navigator.clipboard.writeText(text); copied.value = what; setTimeout(() => { if (copied.value === what) copied.value = '' }, 1500) } catch (_) {}
}
const fmtDate = (ts) => new Intl.DateTimeFormat(props.lang, { dateStyle: 'medium' }).format(new Date(ts))
const fmtWhen = (ts) => new Intl.DateTimeFormat(props.lang, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(ts))

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

      <div class="card" data-testid="hosted-buy">
        <p v-if="price" class="price" data-testid="hosted-price">{{ t.price(price) }}</p>
        <p v-if="!hasProfile" class="muted">{{ t.no_profile }}</p>
        <button class="btn btn-primary" :disabled="!!busy || !price || !identity" @click="buy" data-testid="hosted-subscribe">{{ busy === 'buy' ? t.buying : t.buy }}</button>
      </div>

      <div v-if="identity" class="card" data-testid="hosted-mine">
        <h2>{{ t.mine }}</h2>
        <p v-if="!mine.length" class="muted">{{ t.none }}</p>
        <article v-for="s in mine" :key="s.id" class="sub" :data-sub-id="s.id" data-testid="hosted-sub">
          <p>
            <strong>{{ t.replica(s.device) }}</strong> ·
            {{ t.status[s.status] || s.status }}
            <template v-if="s.stack !== 'ready'"> · {{ t.stack[s.stack] || s.stack }}</template>
            <template v-else> · {{ s.on ? t.on : t.off }}<template v-if="s.enrolled"> · <span data-testid="hosted-enrolled">{{ t.in_account }}</span></template></template>
            <template v-if="s.paidThrough"> · {{ t.paid_through(fmtDate(s.paidThrough)) }}</template>
          </p>
          <p v-if="s.stack === 'creating'" class="muted" data-testid="hosted-creating">{{ t.creating }}</p>
          <p v-else-if="s.stack === 'failed'" class="notice error">{{ t.failed }}</p>

          <div v-if="s.stack === 'ready' && !s.enrolled && (s.status === 'ACTIVE' || s.status === 'COMP')" class="enroll" data-testid="hosted-enroll">
            <h3>{{ t.enroll_h }}</h3>
            <template v-if="codes[s.id]">
              <p><strong>{{ t.code_h }}</strong></p>
              <p class="row"><code class="code" data-testid="hosted-code">{{ codes[s.id] }}</code>
                <button class="btn btn-ghost small" @click="copy('code-' + s.id, codes[s.id])">{{ copied === 'code-' + s.id ? t.copied : t.copy }}</button></p>
              <p v-if="selfVault.running && s.device" class="row">
                <button class="btn btn-primary" :disabled="!!busy" @click="approveHere(s)" data-testid="hosted-approve-here">{{ t.code_approve }}</button></p>
              <p v-else class="row"><code>{{ t.code_cli(codes[s.id]) }}</code>
                <button class="btn btn-ghost small" @click="copy('cli-' + s.id, t.code_cli(codes[s.id]))">{{ copied === 'cli-' + s.id ? t.copied : t.copy }}</button></p>
              <p class="muted">{{ t.code_wait }}</p>
            </template>
            <p v-if="selfVault.enabled" class="row">
              <button class="btn btn-primary" :disabled="!!busy || !selfVault.running" @click="enroll(s, true)" data-testid="hosted-enroll-here">{{ busy === 'enroll:' + s.id ? t.enrolling : t.enroll_here }}</button>
              <span v-if="!selfVault.running && selfVault.error" class="muted" data-testid="hosted-self-error">{{ t.self_error[selfVault.error.code] || t.self_error_other }}</span>
              <span v-else-if="!selfVault.running" class="muted">{{ t.self_starting }}</span>
            </p>
            <p class="muted">{{ t.enroll_paste }}</p>
            <p class="row"><code>{{ PAIR_CMD }}</code>
              <button class="btn btn-ghost small" @click="copy('pair-' + s.id, PAIR_CMD)">{{ copied === 'pair-' + s.id ? t.copied : t.copy }}</button></p>
            <p class="row">
              <input class="inv" v-model="invitation[s.id]" :placeholder="t.enroll_placeholder" data-testid="hosted-invitation" />
              <button class="btn" :disabled="!!busy || !(invitation[s.id] || '').trim()" @click="enroll(s, false)" data-testid="hosted-enroll-go">{{ busy === 'enroll:' + s.id ? t.enrolling : t.enroll_go }}</button>
            </p>
            <p v-if="s.enrollBefore" class="warn">{{ (s.status === 'COMP' ? t.enroll_before_comp : t.enroll_before)(fmtWhen(s.enrollBefore)) }}</p>
          </div>

          <p v-if="s.status === 'ACTIVE' || s.status === 'SUSPENDED'" class="row">
            <template v-if="cancelling === s.id">
              <span class="warn">{{ t.cancel_sure }}</span>
              <button class="btn btn-primary small" :disabled="!!busy" @click="cancel(s)" data-testid="hosted-cancel-yes">{{ t.cancel_yes }}</button>
              <button class="btn btn-ghost small" @click="cancelling = null">{{ t.keep_it }}</button>
            </template>
            <button v-else class="btn btn-ghost small" :disabled="!!busy" @click="cancelling = s.id" data-testid="hosted-cancel">{{ t.cancel }}</button>
          </p>
        </article>
      </div>
      <p v-else-if="!hasProfile" class="muted">{{ t.no_profile }}</p>
    </template>
  </section>
</template>

<style scoped>
.hosted { max-width: 720px; margin: 24px auto 64px; }
.lead { color: var(--muted); }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; margin: 16px 0; }
.price { font-weight: 700; }
.notice { padding: 10px 14px; border-radius: 12px; border: 1px solid var(--line); }
.notice.error { border-color: var(--dt-danger, #b3261e); }
.warn { color: var(--dt-danger, #b3261e); }
.muted { color: var(--muted); }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.sub + .sub { border-top: 1px solid var(--line); }
.small { padding: 6px 12px; font-size: .9rem; }
.enroll { border: 1px dashed var(--line); border-radius: 12px; padding: 12px 14px; margin: 10px 0; }
.enroll h3 { margin: 0 0 8px; font-size: 1rem; }
.code { font-size: 1.3rem; letter-spacing: .08em; }
.inv { flex: 1; min-width: 0; padding: 8px 10px; border-radius: 10px; border: 1px solid var(--line); background: var(--bg, transparent); color: inherit; }
</style>
