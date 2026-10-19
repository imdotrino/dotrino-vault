<script setup>
/**
 * ADMINISTRAR LAS RÉPLICAS ALOJADAS (`/admin`): la cara de `dotrino-accounts` para la cuenta de
 * Dotrino (`dotrino-accounts/docs/DISENO.md` §10).
 *
 * Pantalla administrativa (CONVENCIONES §5.1): datos y botones, sin texto que explique.
 *
 * Habla con cada servicio `accounts` del acta por una sesión cifrada de `@dotrino/remote-agent`
 * (`RemoteAgentClient`, con el enlace de este navegador a su bóveda). Quién puede administrar lo
 * decide EL SERVICIO contra el acta en cada petición (`admin`); aquí solo se enseña lo que
 * conteste, `forbidden` incluido.
 *
 *   → { type: 'admin', rid, op, args }    ← { type: 'admin.result', rid, ok, result | code, error }
 */
import { ref, reactive, computed, onMounted, onBeforeUnmount, markRaw } from 'vue'
import { RemoteAgentClient } from '@dotrino/remote-agent/client'
import { probeAgents } from '@dotrino/remote-agent/discover'
import { linkFromIdentity } from '@dotrino/remote-agent/browser-link'
import { keyLabel } from '@dotrino/identity/capabilities'

const props = defineProps({
  lang: { type: String, default: 'es' },
  /** La identidad de la página (ya `markRaw`). */
  identity: { type: Object, required: true },
  /** Los miembros del acta con cajón `accounts` (`listAgentsByLabel`), que encontró App.vue. */
  members: { type: Array, required: true }
})

const AGENT_KIND = 'accounts'
const REQUEST_TIMEOUT_MS = 30_000
const ACCOUNT_RE = /^[0-9a-f]{64}$/

const T = {
  es: {
    title: 'Administrar réplicas',
    service: 'Servicio',
    online: 'conectado', offline: 'no contesta', probing: 'comprobando…',
    open: 'Abrir', close: 'Cerrar', reload: 'Recargar',
    connecting: 'Conectando…',
    none: 'No hay suscripciones.',
    col: { account: 'Cuenta', id: 'Suscripción', status: 'Estado', stack: 'Réplica', device: 'Aparato', power: 'Encendida', paid: 'Pagada hasta', refund: 'Devolución', paypal: 'PayPal', actions: '' },
    status: { ACTIVE: 'Activa', APPROVAL_PENDING: 'Esperando a PayPal', SUSPENDED: 'Pago pendiente', CANCELLED: 'Cancelada', EXPIRED: 'Vencida', COMP: 'Sin cargo' },
    stack: { none: 'sin crear', creating: 'creándose', ready: 'lista', failed: 'falló', deleted: 'borrada' },
    enrolled: 'en la cuenta', not_enrolled: 'sin añadir',
    on: 'sí', off: 'no', forced: 'a mano',
    refund: { pending: 'pendiente', done: 'hecha', none: 'nada cobrado' },
    turn_on: 'Encender', turn_off: 'Apagar', release: 'Que mande el pago',
    refund_btn: 'Devolver el último cobro', refund_sure: '¿Devolver el último cobro? La suscripción se cancela.',
    remove_btn: 'Borrar la réplica', remove_sure: '¿Borrar esta réplica? Si la suscripción sigue activa, se cancela.',
    yes: 'Sí', no: 'No',
    refunded: (r) => `Devuelto ${r.amount} (${r.capture}).`,
    add_h: 'Añadir una réplica a una cuenta',
    add_placeholder: 'ID de la cuenta (64 caracteres hexadecimales)',
    add_go: 'Añadir',
    added: 'Réplica añadida. La cuenta la verá en su página «En la nube» para añadirla con su invitación.',
    error: (code, msg) => `No se pudo (${code})${msg ? ': ' + msg : ''}`,
    errors: {
      forbidden: 'Este aparato no tiene el permiso «admin» en la cuenta.',
      'no-record': 'El servicio no tiene el acta de la cuenta para comprobar permisos. Inténtalo en unos minutos.',
      'not-paired': 'Este navegador no está enlazado a tu bóveda. Enlázalo en «Mi bóveda».',
      'unauthorized': 'El servicio no reconoce a este aparato como parte de la cuenta.',
      timeout: 'El servicio no contestó.',
      'bad-account': 'Ese ID de cuenta no es válido: son 64 caracteres hexadecimales en minúscula.',
      'nothing-to-refund': 'No hay ningún cobro que devolver.',
      'no-subscription': 'No tiene suscripción de PayPal.'
    }
  },
  en: {
    title: 'Manage replicas',
    service: 'Service',
    online: 'connected', offline: 'not answering', probing: 'checking…',
    open: 'Open', close: 'Close', reload: 'Reload',
    connecting: 'Connecting…',
    none: 'No subscriptions.',
    col: { account: 'Account', id: 'Subscription', status: 'Status', stack: 'Replica', device: 'Device', power: 'On', paid: 'Paid until', refund: 'Refund', paypal: 'PayPal', actions: '' },
    status: { ACTIVE: 'Active', APPROVAL_PENDING: 'Waiting for PayPal', SUSPENDED: 'Payment pending', CANCELLED: 'Cancelled', EXPIRED: 'Expired', COMP: 'No charge' },
    stack: { none: 'not created', creating: 'being created', ready: 'ready', failed: 'failed', deleted: 'deleted' },
    enrolled: 'in the account', not_enrolled: 'not added',
    on: 'yes', off: 'no', forced: 'by hand',
    refund: { pending: 'pending', done: 'done', none: 'nothing charged' },
    turn_on: 'Turn on', turn_off: 'Turn off', release: 'Follow the payment',
    refund_btn: 'Refund the last payment', refund_sure: 'Refund the last payment? The subscription is cancelled.',
    remove_btn: 'Delete the replica', remove_sure: 'Delete this replica? If the subscription is still active, it is cancelled.',
    yes: 'Yes', no: 'No',
    refunded: (r) => `Refunded ${r.amount} (${r.capture}).`,
    add_h: 'Add a replica to an account',
    add_placeholder: 'Account ID (64 hexadecimal characters)',
    add_go: 'Add',
    added: 'Replica added. The account will see it on its «In the cloud» page to add it with its invitation.',
    error: (code, msg) => `It did not work (${code})${msg ? ': ' + msg : ''}`,
    errors: {
      forbidden: 'This device does not have the «admin» permission in the account.',
      'no-record': 'The service does not have the account record to check permissions. Try again in a few minutes.',
      'not-paired': 'This browser is not linked to your vault. Link it in «My vault».',
      'unauthorized': 'The service does not recognize this device as part of the account.',
      timeout: 'The service did not answer.',
      'bad-account': 'That account ID is not valid: it is 64 lowercase hexadecimal characters.',
      'nothing-to-refund': 'There is no payment to refund.',
      'no-subscription': 'It has no PayPal subscription.'
    }
  }
}
const t = computed(() => T[props.lang] || T.es)
const errorText = (e) => t.value.errors[e?.code] || t.value.error(e?.code || 'error', e?.message)

const link = ref(null)
const notice = ref(null) // { kind: 'ok' | 'error', text }
/** Un servicio por miembro: { sub, label, deviceId, online, open, client, rows, busy, notice, confirm, account } */
const agents = ref([])
let probe = null

class AdminError extends Error { constructor (code, message) { super(message); this.code = code } }

onMounted(async () => {
  let l
  try { l = await linkFromIdentity(props.identity) } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; return }
  if (!l.paired) { notice.value = { kind: 'error', text: errorText({ code: 'not-paired' }) }; return }
  link.value = markRaw(l)
  agents.value = await Promise.all(props.members.map(async (m) => reactive({
    sub: m.sub, label: m.label, deviceId: await keyLabel(m.sub), online: null,
    open: false, client: null, rows: null, busy: '', notice: null, confirm: null, account: ''
  })))
  try {
    const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
    probe = markRaw(new WebSocketProxyClient({ url: l.proxy, enableWebRTC: false, autoReconnect: true }))
    await probe.connect()
  } catch (e) { notice.value = { kind: 'error', text: errorText(e) }; return }
  const found = await probeAgents(probe, agents.value.map((a) => a.sub))
  for (const a of agents.value) a.online = found.get(a.sub)?.kind === AGENT_KIND
})

onBeforeUnmount(() => {
  probe?.close()
  for (const a of agents.value) a.client?.close()
})

// ----- la sesión con un servicio -----
let nextRid = 1
const pending = new Map() // rid -> { resolve, reject, timer }

function onReply (msg) {
  if (msg?.type !== 'admin.result') return
  const p = pending.get(msg.rid)
  if (!p) return
  pending.delete(msg.rid)
  clearTimeout(p.timer)
  if (msg.ok) p.resolve(msg.result)
  else p.reject(new AdminError(msg.code || 'internal', msg.error))
}

async function session (a) {
  if (a.client) return a.client
  const c = markRaw(new RemoteAgentClient(link.value, { agentPubkey: a.sub }))
  c.on('message', onReply)
  c.on('error', (e) => { a.notice = { kind: 'error', text: errorText(e) } })
  await c.connect()
  a.client = c
  return c
}

async function request (a, op, args) {
  const c = await session(a)
  const rid = nextRid++
  const answer = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(rid); reject(new AdminError('timeout', `${op}: no answer in ${REQUEST_TIMEOUT_MS / 1000} s`)) }, REQUEST_TIMEOUT_MS)
    pending.set(rid, { resolve, reject, timer })
  })
  try { await c.send({ type: 'admin', rid, op, args }) } catch (e) { clearTimeout(pending.get(rid)?.timer); pending.delete(rid); throw e }
  return answer
}

/** Corre una operación sobre un servicio: marca el botón, enseña el error con su código, y recarga. */
async function run (a, key, fn) {
  a.busy = key
  a.notice = null
  try { await fn() } catch (e) { a.notice = { kind: 'error', text: errorText(e) } } finally { a.busy = '' }
}

const load = (a) => run(a, 'list', async () => { a.rows = await request(a, 'list') })

async function toggle (a) {
  if (a.open) { a.open = false; return }
  a.open = true
  if (!a.rows) await load(a)
}

const setOn = (a, r, on) => run(a, 'setOn:' + r.id, async () => { await request(a, 'setOn', { id: r.id, on }); a.rows = await request(a, 'list') })

const refund = (a, r) => run(a, 'refund:' + r.id, async () => {
  const res = await request(a, 'refund', { id: r.id })
  a.confirm = null
  a.notice = { kind: 'ok', text: t.value.refunded(res.refunded) }
  a.rows = await request(a, 'list')
})

const remove = (a, r) => run(a, 'remove:' + r.id, async () => {
  await request(a, 'remove', { id: r.id })
  a.confirm = null
  a.rows = await request(a, 'list')
})

const addReplica = (a) => run(a, 'add', async () => {
  await request(a, 'addReplica', { account: a.account.trim() })
  a.account = ''
  a.notice = { kind: 'ok', text: t.value.added }
  a.rows = await request(a, 'list')
})

const fmtDate = (ts) => new Intl.DateTimeFormat(props.lang, { dateStyle: 'medium' }).format(new Date(ts))
const short = (s, n = 8) => (s && s.length > n ? s.slice(0, n) + '…' : s)
</script>

<template>
  <section class="admin" data-testid="admin">
    <h1>{{ t.title }}</h1>
    <p v-if="notice" :class="['notice', notice.kind]" role="status" data-testid="admin-notice">{{ notice.text }}</p>

    <article v-for="a in agents" :key="a.sub" class="card" :data-agent="a.deviceId" data-testid="admin-agent">
      <header class="row head">
        <h2>{{ t.service }} {{ a.label || a.deviceId }} <span class="muted">· {{ a.deviceId }}</span></h2>
        <span :class="['dot', a.online === true ? 'on' : a.online === false ? 'off' : '']" data-testid="admin-agent-state">{{ a.online === null ? t.probing : a.online ? t.online : t.offline }}</span>
        <button class="btn btn-ghost small" :disabled="!link" @click="toggle(a)" data-testid="admin-agent-open">{{ a.open ? t.close : t.open }}</button>
        <button v-if="a.open" class="btn btn-ghost small" :disabled="!!a.busy" @click="load(a)" data-testid="admin-reload">{{ t.reload }}</button>
      </header>

      <template v-if="a.open">
        <p v-if="a.notice" :class="['notice', a.notice.kind]" role="status" data-testid="admin-agent-notice">{{ a.notice.text }}</p>
        <p v-if="a.busy === 'list' && !a.rows" class="muted">{{ t.connecting }}</p>

        <template v-if="a.rows">
          <p v-if="!a.rows.length" class="muted" data-testid="admin-none">{{ t.none }}</p>
          <div v-else class="scroll">
            <table data-testid="admin-table">
              <thead><tr><th v-for="(h, k) in t.col" :key="k">{{ h }}</th></tr></thead>
              <tbody>
                <tr v-for="r in a.rows" :key="r.id" :data-sub-id="r.id" data-testid="admin-row">
                  <td><code :title="r.account">{{ short(r.account, 12) }}</code></td>
                  <td><code :title="r.id">{{ short(r.id) }}</code></td>
                  <td>{{ t.status[r.status] || r.status }}</td>
                  <td><span :title="r.note || ''">{{ t.stack[r.stack] || r.stack }}</span><template v-if="r.vault"><br><code class="muted">{{ r.vault }}</code></template></td>
                  <td>{{ r.enrolled ? t.enrolled : t.not_enrolled }}<template v-if="r.device"><br><code>{{ r.device }}</code></template></td>
                  <td>{{ r.on ? t.on : t.off }}<span v-if="r.adminOn !== null" class="muted"> · {{ t.forced }}</span></td>
                  <td>{{ r.paidThrough ? fmtDate(r.paidThrough) : '—' }}</td>
                  <td>{{ r.refund ? (t.refund[r.refund] || r.refund) : '—' }}</td>
                  <td><code v-if="r.paypalId">{{ r.paypalId }}</code><template v-else>—</template></td>
                  <td class="actions">
                    <template v-if="a.confirm && a.confirm.id === r.id">
                      <span class="warn">{{ a.confirm.op === 'refund' ? t.refund_sure : t.remove_sure }}</span>
                      <button class="btn btn-primary small" :disabled="!!a.busy" @click="a.confirm.op === 'refund' ? refund(a, r) : remove(a, r)" data-testid="admin-confirm-yes">{{ t.yes }}</button>
                      <button class="btn btn-ghost small" :disabled="!!a.busy" @click="a.confirm = null" data-testid="admin-confirm-no">{{ t.no }}</button>
                    </template>
                    <template v-else>
                      <template v-if="r.stack === 'ready'">
                        <button v-if="r.on" class="btn btn-ghost small" :disabled="!!a.busy" @click="setOn(a, r, false)" data-testid="admin-turn-off">{{ t.turn_off }}</button>
                        <button v-else class="btn btn-ghost small" :disabled="!!a.busy" @click="setOn(a, r, true)" data-testid="admin-turn-on">{{ t.turn_on }}</button>
                        <button v-if="r.adminOn !== null" class="btn btn-ghost small" :disabled="!!a.busy" @click="setOn(a, r, null)" data-testid="admin-release">{{ t.release }}</button>
                      </template>
                      <button class="btn btn-ghost small" :disabled="!!a.busy || !r.paypalId" @click="a.confirm = { id: r.id, op: 'refund' }" data-testid="admin-refund">{{ t.refund_btn }}</button>
                      <button class="btn btn-ghost small" :disabled="!!a.busy || r.stack === 'deleted' || r.stack === 'none'" @click="a.confirm = { id: r.id, op: 'remove' }" data-testid="admin-remove">{{ t.remove_btn }}</button>
                    </template>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <h3>{{ t.add_h }}</h3>
          <p class="row">
            <input class="inp" v-model="a.account" :placeholder="t.add_placeholder" spellcheck="false" autocomplete="off" data-testid="admin-add-account" />
            <button class="btn" :disabled="!!a.busy || !ACCOUNT_RE.test(a.account.trim())" @click="addReplica(a)" data-testid="admin-add-go">{{ t.add_go }}</button>
          </p>
        </template>
      </template>
    </article>
  </section>
</template>

<style scoped>
.admin { max-width: 1200px; margin: 24px auto 64px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; margin: 16px 0; }
.head h2 { margin: 0; font-size: 1.1rem; flex: 1; min-width: 0; }
.notice { padding: 10px 14px; border-radius: 12px; border: 1px solid var(--line); }
.notice.error { border-color: var(--dt-danger, #b3261e); }
.warn { color: var(--dt-danger, #b3261e); }
.muted { color: var(--muted); }
.row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.small { padding: 6px 12px; font-size: .9rem; }
.dot::before { content: '●'; margin-right: 4px; color: var(--muted); }
.dot.on::before { color: var(--dt-success, #2e7d32); }
.dot.off::before { color: var(--dt-danger, #b3261e); }
.scroll { overflow-x: auto; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; vertical-align: top; padding: 8px 10px; border-bottom: 1px solid var(--line); }
th { font-weight: 700; white-space: nowrap; }
.actions { display: flex; gap: 6px; flex-wrap: wrap; min-width: 220px; }
.inp { flex: 1; min-width: 0; padding: 8px 10px; border-radius: 10px; border: 1px solid var(--line); background: var(--bg, transparent); color: inherit; font-family: monospace; }
</style>
