<script setup>
/**
 * Consola «Dónde vive tu perfil» — la ÚNICA pantalla del ecosistema donde se gestionan
 * los dispositivos de un perfil. Muestra el acta: quién es del perfil, qué puede hacer
 * cada uno y quién manda (el master, el único que puede cambiarla).
 *
 * Cero criptografía aquí dentro: todo va por RPC al iframe de identidad
 * (`@dotrino/identity`), que es quien custodia la llave y sella el acta.
 * Diseño: dotrino-vault/docs/acta-de-perfil.md
 */
import { ref, computed, markRaw, onMounted, onBeforeUnmount } from 'vue'
import { Identity } from '@dotrino/identity'
import jsQR from 'jsqr'
import { qrSvg } from './qr.js'
import { parseInvite, inviteUrl } from '../../lib/src/invite.js'

const props = defineProps({ lang: { type: String, default: 'es' } })

const T = {
  es: {
    title: 'Dónde vive tu perfil',
    lead: 'Estos son los dispositivos de tu perfil y lo que puede hacer cada uno. El acta la firma uno solo —el que manda—, y ninguna llave sale nunca de su dispositivo.',
    loading: 'Cargando…',
    err_connect: 'No se pudo abrir tu identidad. Recarga la página e inténtalo otra vez.',
    profile: 'Perfil', version: 'Versión del acta', master: 'Manda',
    members: 'Dispositivos', me: 'este dispositivo', is_master: 'manda',
    caps: { sign: 'Firma por ti', store: 'Guarda tu contenido', read: 'Lee tu contenido', secrets: 'Lee sus propias claves' },
    service: 'servicio',
    service_note: 'Un servicio solo puede abrir las claves de su propio nombre: no ve nada más de lo tuyo.',
    caps_none: 'sin permisos',
    solo_warn_t: 'Solo tienes este dispositivo',
    solo_warn_b: 'Si lo pierdes, pierdes el perfil: no hay forma de recuperarlo. Conecta al menos otro dispositivo o tu bóveda.',
    not_master_t: 'Este dispositivo no manda',
    not_master_b: 'Los cambios (conectar, quitar o cambiar permisos) se hacen desde el que manda.',
    act_add: 'Conectar un dispositivo', act_remove: 'Quitar', act_handover: 'Que mande este',
    act_renounce: 'Que deje de firmar por mí', act_renounced: 'Ya no firma',
    confirm_remove: '¿Quitar este dispositivo del perfil?',
    confirm_handover: 'A partir de ahora mandará ese dispositivo y este dejará de poder cambiar el acta. ¿Seguir?',
    confirm_renounce: 'Este dispositivo dejará de firmar por ti. Podrás devolvérselo desde el que manda. ¿Seguir?',
    yes: 'Sí, hazlo', cancel: 'Cancelar',
    pair_t: 'Conectar este dispositivo a una bóveda',
    pair_b: 'Escanea el código que te muestra tu bóveda, o pégalo aquí.',
    pair_scan: 'Escanear con la cámara', pair_file: 'Abrir imagen o archivo',
    pair_paste: 'Pegar el código', pair_go: 'Conectar',
    pair_bad: 'Ese código no vale. Copia otra vez el que te muestra tu bóveda.',
    pair_old: 'Ese código es de una versión antigua. Genera uno nuevo en tu bóveda.',
    pair_wait: 'Conectando… espera un momento.',
    pair_code_t: 'Escribe este código en tu bóveda',
    pair_code_b: 'Ábrela y teclea estos seis dígitos para aprobar la conexión. Nadie más los conoce.',
    pair_done: 'Listo, este dispositivo ya está conectado.',
    pair_new_account: 'Se creará aquí una cuenta nueva: la de tu bóveda. La que estás usando ahora no se toca.',
    ann_t: 'Esto es lo que quiere hacer tu bóveda',
    ann_join_h: (n) => n ? `Crear en este dispositivo una cuenta nueva: «${n}», la de tu bóveda.` : 'Crear en este dispositivo una cuenta nueva: la de tu bóveda.',
    ann_join_c: 'La cuenta que estás usando ahora no se toca. Al terminar tendrás dos y podrás cambiar entre ellas cuando quieras.',
    ann_adopt_h: (n) => n ? `Guardar y administrar tu cuenta «${n}»: pasaría a vivir en tu bóveda.` : 'Guardar y administrar la cuenta que usas en este dispositivo.',
    ann_adopt_c: 'Tu cuenta seguiría siendo la misma para todo el mundo, pero a partir de ahí manda tu bóveda: este dispositivo dejaría de ser quien firma los cambios.',
    ann_adopt_no: 'Este dispositivo todavía no sabe entregar su cuenta. Actualiza la página, o elige la otra opción en tu bóveda.',
    ann_go: 'Continuar', ann_cancel: 'Cancelar',
    two_title: 'Ahora tienes dos cuentas en este aparato',
    two_body: 'La que ya usabas sigue intacta, y se agregó la de tu bóveda, que es la que estás usando ahora. Puedes cambiar entre ellas cuando quieras desde el botón de tu foto, arriba.',
    two_del: 'Si no quieres conservar la anterior:',
    two_del_1: 'Abre tu página de perfil.',
    two_del_2: 'En «Tus perfiles», pulsa Borrar en la cuenta que no quieras.',
    two_del_3: 'Confirma. Se va con todo lo suyo y no se puede deshacer.',
    two_del_link: 'Abrir mi página de perfil',
    pair_fail: 'No se pudo conectar: ',
    cam_err: 'No se pudo abrir la cámara. Pega el código a mano.',
    no_qr: 'No se encontró ningún código en esa imagen.',
    self_t: 'Que este dispositivo sea la bóveda',
    self_b: 'Otros dispositivos tuyos podrán conectarse a este. Tiene que estar encendido y con la página abierta.',
    self_on: 'Encendida', self_off: 'Apagada', self_start: 'Encender', self_stop: 'Apagar',
    self_pair: 'Generar código para conectar otro',
    self_pending: 'Un dispositivo quiere conectarse',
    self_code_ph: 'Los 6 dígitos que muestra',
    self_approve: 'Aprobar', self_reject: 'Rechazar',
    back: 'Volver'
  },
  en: {
    title: 'Where your profile lives',
    lead: 'These are your profile’s devices and what each one can do. A single device signs the record —the one in charge— and no key ever leaves its device.',
    loading: 'Loading…',
    err_connect: 'Could not open your identity. Reload the page and try again.',
    profile: 'Profile', version: 'Record version', master: 'In charge',
    members: 'Devices', me: 'this device', is_master: 'in charge',
    caps: { sign: 'Signs for you', store: 'Stores your content', read: 'Reads your content', secrets: 'Reads its own keys' },
    service: 'service',
    service_note: 'A service can only open the keys under its own name: it sees nothing else of yours.',
    caps_none: 'no permissions',
    solo_warn_t: 'You only have this device',
    solo_warn_b: 'If you lose it, you lose the profile: there is no way to recover it. Connect at least one more device or your vault.',
    not_master_t: 'This device is not in charge',
    not_master_b: 'Changes (connecting, removing or changing permissions) are made from the one in charge.',
    act_add: 'Connect a device', act_remove: 'Remove', act_handover: 'Put this one in charge',
    act_renounce: 'Stop signing for me', act_renounced: 'No longer signs',
    confirm_remove: 'Remove this device from the profile?',
    confirm_handover: 'From now on that device will be in charge and this one will no longer be able to change the record. Continue?',
    confirm_renounce: 'This device will stop signing for you. You can give it back from the one in charge. Continue?',
    yes: 'Yes, do it', cancel: 'Cancel',
    pair_t: 'Connect this device to a vault',
    pair_b: 'Scan the code your vault shows you, or paste it here.',
    pair_scan: 'Scan with the camera', pair_file: 'Open image or file',
    pair_paste: 'Paste the code', pair_go: 'Connect',
    pair_bad: 'That code is not valid. Copy the one your vault shows again.',
    pair_old: 'That code is from an old version. Generate a new one in your vault.',
    pair_wait: 'Connecting… hold on.',
    pair_code_t: 'Type this code in your vault',
    pair_code_b: 'Open it and type these six digits to approve the connection. Nobody else knows them.',
    pair_done: 'Done, this device is connected.',
    pair_new_account: 'A new account will be created here: your vault\'s. The one you are using now is left untouched.',
    ann_t: 'This is what your vault wants to do',
    ann_join_h: (n) => n ? `Create a new account on this device: “${n}”, your vault's.` : 'Create a new account on this device: your vault\'s.',
    ann_join_c: 'The account you are using now is left untouched. When it is done you will have two, and you can switch between them any time.',
    ann_adopt_h: (n) => n ? `Keep and manage your account “${n}”: it would move into your vault.` : 'Keep and manage the account you use on this device.',
    ann_adopt_c: 'Your account would stay the same for everyone else, but from then on your vault is in charge: this device would no longer sign its changes.',
    ann_adopt_no: 'This device cannot hand its account over yet. Reload the page, or choose the other option in your vault.',
    ann_go: 'Continue', ann_cancel: 'Cancel',
    two_title: 'You now have two accounts on this device',
    two_body: 'The one you were using is untouched, and your vault\'s was added — that is the one you are using now. You can switch between them any time from your photo button, above.',
    two_del: 'If you do not want to keep the previous one:',
    two_del_1: 'Open your profile page.',
    two_del_2: 'Under “Your profiles”, press Delete on the account you do not want.',
    two_del_3: 'Confirm. It goes with everything in it and cannot be undone.',
    two_del_link: 'Open my profile page',
    pair_fail: 'Could not connect: ',
    cam_err: 'Could not open the camera. Paste the code by hand.',
    no_qr: 'No code found in that image.',
    self_t: 'Make this device the vault',
    self_b: 'Your other devices will be able to connect to this one. It has to be on, with the page open.',
    self_on: 'On', self_off: 'Off', self_start: 'Turn on', self_stop: 'Turn off',
    self_pair: 'Create a code to connect another one',
    self_pending: 'A device wants to connect',
    self_code_ph: 'The 6 digits it shows',
    self_approve: 'Approve', self_reject: 'Reject',
    back: 'Back'
  }
}
const t = computed(() => T[props.lang] || T.es)

/**
 * En desarrollo se puede apuntar la identidad a un iframe LOCAL con `?vault=<url>`, para
 * poder probar la consola entera sin salir de la máquina.
 *
 * Solo se acepta si esta página se está sirviendo desde localhost. Es importante: sin ese
 * cerrojo, un enlace del tipo `vault.dotrino.com/dispositivos?vault=…` podría apuntar tu
 * identidad a un iframe ajeno, que es exactamente el ataque que este proyecto evita.
 */
function opcionesIdentidad () {
  const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)
  const url = local ? new URLSearchParams(location.search).get('vault') : null
  return url ? { vaultUrl: url } : {}
}

const id = ref(null)
const loading = ref(true)
const fatal = ref('')
const acta = ref(null)
const members = ref([])
const mine = ref(null)
const msg = ref(null) // { kind:'ok'|'bad'|'info', text }
const busy = ref('')

const isMaster = computed(() => !!mine.value?.isMaster)
const soloMember = computed(() => members.value.length <= 1)
const shortId = (s) => (s || '').slice(0, 8)

async function refresh () {
  const [a, m, mi] = await Promise.all([
    id.value.profileActa().catch(() => null),
    id.value.profileMembers().catch(() => ({ members: [] })),
    id.value.myMembership().catch(() => null)
  ])
  acta.value = a?.acta || null
  members.value = m.members || []
  mine.value = mi
}

onMounted(async () => {
  // `markRaw`: la identidad NO puede volverse reactiva. Vue envuelve en un Proxy lo
  // que metes en un ref, y esta instancia habla con su iframe por `postMessage`, que
  // no sabe clonar un Proxy: emparejar moría con «#<Object> could not be cloned».
  // (Venía roto desde que existe esta consola; lo destapó una prueba de punta a punta.)
  try { id.value = markRaw(await Identity.connect(opcionesIdentidad())) } catch { fatal.value = t.value.err_connect; loading.value = false; return }
  await refresh()
  loading.value = false
  // El QR de `dotrino-vault pair` abre esta página con el código en el #fragment
  // (que nunca llega al servidor). Si viene, arrancamos la conexión sola.
  const payload = extractPayload(location.hash)
  if (payload) { history.replaceState(null, '', location.pathname); announce(payload) }
  offVault = id.value.onVault?.((e) => { if (e?.phase === 'acta' || e?.phase === 'renounced') refresh() })
  await refreshSelf()
})

let offVault = null
onBeforeUnmount(() => { try { offVault?.() } catch (_) {} })

// ---------- acciones del master ----------

const confirming = ref(null) // { kind, pub }

async function run (key, fn) {
  busy.value = key; msg.value = null
  try { await fn(); await refresh() }
  catch (e) { msg.value = { kind: 'bad', text: e?.message || String(e) } }
  finally { busy.value = ''; confirming.value = null }
}

const toggleCap = (m, cap) => run('caps-' + m.pub, () => {
  const caps = m.caps.includes(cap) ? m.caps.filter((c) => c !== cap) : [...m.caps, cap]
  return id.value.setCaps(m.pub, caps)
})
const removeMember = (m) => run('rm-' + m.pub, () => id.value.removeMember(m.pub))
const handover = (m) => run('ho-' + m.pub, () => id.value.handoverMaster(m.pub))
const renounceSign = () => run('renounce', () => id.value.renounceCaps(['sign']))

// ---------- conectar este dispositivo a una bóveda ----------

const pairing = ref(false)
const pairCode = ref('')
const pasted = ref('')
// Recién emparejado: hay que explicar que el aparato quedó con DOS cuentas.
const justPaired = ref(false)
// Lo que la bóveda declara en el QR: { qr, mode: 'join'|'adopt', account }.
const pendingPair = ref(null)
const scanHost = ref(null)
const fileInput = ref(null)

/**
 * Lee la invitación con el parser COMPARTIDO (`lib/src/invite.js`): la marca de
 * formato del payload dice cómo leerlo, sin probar a ver cuál cuela. Hoy se emite
 * `c` (compacta: binario en base64url, ~100 caracteres, la misma para el QR y para
 * pegar); también acepta las formas largas (`b`, `j`) y las que no llevan marca,
 * porque hay bóvedas sin actualizar por ahí.
 */
function extractPayload (text) {
  const o = parseInvite(text)
  return (o && o.iss && o.token) ? o : null
}

/**
 * El QR NO empareja de una: primero se anuncia QUÉ quiere hacer la bóveda y QUÉ
 * consecuencias tiene, y el dueño decide (V9 de `vinculacion-de-cuentas.md`: la
 * pregunta la hace el vault, el dispositivo la muestra con sus consecuencias).
 * El modo viaja en el QR (`m`) junto al nombre de la cuenta (`acct`); un código de
 * una bóveda vieja no trae nada de eso y se trata como `join`, que es lo único que
 * esa bóveda sabe hacer.
 */
function announce (qr) {
  if (!qr?.iss || !qr?.token) { msg.value = { kind: 'bad', text: t.value.pair_bad }; return }
  if (!qr.sn || (qr.v && qr.v < 2)) { msg.value = { kind: 'bad', text: t.value.pair_old }; return }
  msg.value = null
  // `markRaw` + copia plana al aceptar: el QR viaja por `postMessage` al iframe de
  // identidad, y un Proxy reactivo de Vue NO es clonable («could not be cloned») —
  // guardar el objeto en un ref rompía el emparejamiento entero.
  pendingPair.value = { qr: markRaw(qr), mode: qr.m === 'adopt' ? 'adopt' : 'join', account: String(qr.acct || '').slice(0, 40) }
}

const cancelAnnounce = () => { pendingPair.value = null }
function acceptAnnounce () {
  const p = pendingPair.value
  if (!p || p.mode !== 'join') return // `adopt` todavía no existe de este lado
  pendingPair.value = null
  connect({ ...p.qr })
}

async function connect (qr) {
  if (!qr?.iss || !qr?.token) { msg.value = { kind: 'bad', text: t.value.pair_bad }; return }
  if (!qr.sn || (qr.v && qr.v < 2)) { msg.value = { kind: 'bad', text: t.value.pair_old }; return }
  pairing.value = true; pairCode.value = ''; msg.value = { kind: 'info', text: t.value.pair_wait }
  const off = id.value.onVault((e) => { if (e?.phase === 'challenge') { pairCode.value = e.code; msg.value = null } })
  try {
    // Camino B (`vinculacion-de-cuentas.md` §3): la cuenta de la bóveda se materializa aquí
    // como una cuenta MÁS, con llave nueva. La que estabas usando NO se toca — antes se
    // sobrescribía sin preguntar, que era la fusión de cuentas que el modelo prohíbe.
    await id.value.enrollDevice(qr, { join: 'new' })
    msg.value = { kind: 'ok', text: t.value.pair_done }
    // Emparejar deja DOS cuentas en el aparato, y eso hay que decirlo: si no, el
    // conmutador aparece con una entrada de más y nadie sabe de dónde salió.
    justPaired.value = true
    await refresh()
  } catch (e) {
    msg.value = { kind: 'bad', text: t.value.pair_fail + (e?.message || e) }
  } finally { off?.(); pairing.value = false; pairCode.value = '' }
}

const connectPasted = () => announce(extractPayload(pasted.value))

function decodeImage (file) {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight
      try {
        const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0)
        const d = ctx.getImageData(0, 0, c.width, c.height)
        resolve(jsQR(d.data, d.width, d.height)?.data || null)
      } catch { resolve(null) }
      URL.revokeObjectURL(img.src)
    }
    img.onerror = () => resolve(null)
    img.src = URL.createObjectURL(file)
  })
}

async function onFile (ev) {
  const f = ev.target.files?.[0]; if (!f) return
  const text = /^image\//.test(f.type) ? await decodeImage(f) : await f.text()
  if (!text) { msg.value = { kind: 'bad', text: t.value.no_qr }; return }
  announce(extractPayload(text))
}

const scanning = ref(false)
let scanStop = null
async function scan () {
  scanning.value = true
  const video = scanHost.value.querySelector('video')
  const c = document.createElement('canvas'); const ctx = c.getContext('2d')
  let stream = null, raf = null, done = false
  const stop = (val) => {
    if (done) return; done = true
    if (raf) cancelAnimationFrame(raf)
    stream?.getTracks().forEach((x) => x.stop())
    scanning.value = false
    if (val) announce(extractPayload(val))
  }
  scanStop = () => stop(null)
  const tick = () => {
    if (done) return
    if (video.readyState >= 2 && video.videoWidth) {
      c.width = video.videoWidth; c.height = video.videoHeight
      ctx.drawImage(video, 0, 0, c.width, c.height)
      try {
        const d = ctx.getImageData(0, 0, c.width, c.height)
        const r = jsQR(d.data, d.width, d.height)
        if (r?.data) return stop(r.data)
      } catch (_) {}
    }
    raf = requestAnimationFrame(tick)
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    video.srcObject = stream
    await video.play().catch(() => {})
    raf = requestAnimationFrame(tick)
  } catch { scanning.value = false; msg.value = { kind: 'bad', text: t.value.cam_err } }
}

// ---------- este dispositivo como bóveda ----------

const self = ref({ enabled: false, running: false })
const selfQr = ref(null)
const selfPending = ref([])
const selfCode = ref('')
let selfTimer = null

async function refreshSelf () {
  try {
    self.value = await id.value.selfVaultStatus()
    selfPending.value = self.value.running ? await id.value.selfVaultPending() : []
  } catch (_) {}
}
const selfToggle = () => run('self', async () => {
  await id.value.setSelfVault(!self.value.enabled)
  await refreshSelf()
})
const selfPair = () => run('selfpair', async () => {
  const r = await id.value.selfVaultPairing({})
  // El QR lleva el ENLACE compacto, no el JSON: así el otro aparato lo escanea con
  // la cámara y se le abre esta misma consola, en vez de quedarse con un texto que
  // hay que pegar a mano. Y de paso cabe: el JSON daba un QR de 69 módulos.
  selfQr.value = r?.qr ? qrSvg(inviteUrl(r.qr)) : null
  clearInterval(selfTimer)
  selfTimer = setInterval(refreshSelf, 2000)
})
const selfApprove = (deviceId) => run('sa-' + deviceId, async () => {
  await id.value.selfVaultApprove(deviceId, selfCode.value.trim())
  selfCode.value = ''; selfQr.value = null; clearInterval(selfTimer); await refreshSelf()
})
const selfReject = (deviceId) => run('sr-' + deviceId, async () => {
  await id.value.selfVaultReject(deviceId); await refreshSelf()
})
onBeforeUnmount(() => clearInterval(selfTimer))
</script>

<template>
  <section class="console">
    <h1>{{ t.title }}</h1>
    <p class="lead">{{ t.lead }}</p>

    <p v-if="loading" class="muted">{{ t.loading }}</p>
    <div v-else-if="fatal" class="banner bad">{{ fatal }}</div>

    <template v-else>
      <div v-if="msg" class="banner" :class="msg.kind">{{ msg.text }}</div>

      <div v-if="soloMember" class="banner warn" data-testid="solo-warning">
        <strong>{{ t.solo_warn_t }}</strong> — {{ t.solo_warn_b }}
      </div>
      <div v-else-if="!isMaster" class="banner info">
        <strong>{{ t.not_master_t }}</strong> — {{ t.not_master_b }}
      </div>

      <!-- Resumen del acta -->
      <ul class="facts" v-if="acta">
        <li>{{ t.profile }} <code>{{ shortId(acta.profileId) }}</code></li>
        <li>{{ t.version }} <code>#{{ acta.seq }}</code></li>
        <li>{{ t.master }} <code>{{ members.find(m => m.isMaster)?.label || members.find(m => m.isMaster)?.id }}</code></li>
      </ul>

      <!-- Miembros -->
      <h2>{{ t.members }}</h2>
      <ul class="members" data-testid="members">
        <li v-for="m in members" :key="m.pub" class="member" :data-member="m.id">
          <div class="who">
            <strong>{{ m.label || m.id }}</strong>
            <span class="tag" v-if="m.isMe">{{ t.me }}</span>
            <span class="tag master" v-if="m.isMaster">{{ t.is_master }}</span>
            <span class="tag svc" v-if="m.cn">{{ t.service }} «{{ m.cn }}»</span>
            <code class="mid">{{ m.id }}</code>
          </div>
          <div class="caps">
            <button v-for="c in (m.cn ? ['secrets'] : ['sign','store','read'])" :key="c"
                    class="cap" :class="{ on: m.caps.includes(c) }"
                    :disabled="!isMaster || busy === 'caps-' + m.pub"
                    :data-testid="'cap-' + c + '-' + m.id"
                    @click="toggleCap(m, c)">{{ t.caps[c] }}</button>
            <span v-if="!m.caps.length" class="muted">{{ t.caps_none }}</span>
          </div>
          <p v-if="m.cn" class="muted svc-note">{{ t.service_note }}</p>
          <div class="acts">
            <button v-if="m.isMe && m.caps.includes('sign')" class="btn ghost sm"
                    data-testid="renounce" @click="confirming = { kind: 'renounce', pub: m.pub }">{{ t.act_renounce }}</button>
            <template v-if="isMaster && !m.isMaster">
              <button class="btn ghost sm" :data-testid="'handover-' + m.id"
                      @click="confirming = { kind: 'handover', pub: m.pub }">{{ t.act_handover }}</button>
              <button class="btn danger sm" :data-testid="'remove-' + m.id"
                      @click="confirming = { kind: 'remove', pub: m.pub }">{{ t.act_remove }}</button>
            </template>
          </div>
          <div v-if="confirming && confirming.pub === m.pub" class="confirm">
            <span>{{ confirming.kind === 'remove' ? t.confirm_remove : confirming.kind === 'handover' ? t.confirm_handover : t.confirm_renounce }}</span>
            <button class="btn danger sm" data-testid="confirm-yes" @click="confirming.kind === 'remove' ? removeMember(m) : confirming.kind === 'handover' ? handover(m) : renounceSign()">{{ t.yes }}</button>
            <button class="btn ghost sm" @click="confirming = null">{{ t.cancel }}</button>
          </div>
        </li>
      </ul>

      <!-- Conectar este dispositivo a una bóveda -->
      <h2>{{ t.pair_t }}</h2>
      <p class="muted">{{ t.pair_b }}</p>
      <div v-if="pairCode" class="codebox" data-testid="pair-code">
        <p>{{ t.pair_code_t }}</p>
        <div class="digits">{{ pairCode }}</div>
        <p class="muted">{{ t.pair_code_b }}</p>
      </div>
      <!-- Emparejar deja el aparato con DOS cuentas: se dice, y se dice cómo deshacerse
           de la que no quieras. Lo contrario es que aparezca una entrada de más en el
           conmutador y nadie sepa de dónde salió. -->
      <div v-if="justPaired" class="banner two-accounts" data-testid="two-accounts">
        <strong>{{ t.two_title }}</strong>
        <p>{{ t.two_body }}</p>
        <p class="muted">{{ t.two_del }}</p>
        <ol class="muted">
          <li>{{ t.two_del_1 }}</li>
          <li>{{ t.two_del_2 }}</li>
          <li>{{ t.two_del_3 }}</li>
        </ol>
        <a class="btn ghost sm" href="https://profile.dotrino.com/" target="_blank" rel="noopener"
           data-testid="goto-profile">{{ t.two_del_link }}</a>
      </div>

      <!-- Lo que la bóveda declaró en el código: qué va a hacer y qué consecuencias
           tiene. Se dice ANTES, y no se toca nada hasta que el dueño acepta. -->
      <div v-else-if="pendingPair" class="banner announce" data-testid="pair-announce">
        <strong>{{ t.ann_t }}</strong>
        <p data-testid="announce-what">
          {{ pendingPair.mode === 'adopt' ? t.ann_adopt_h(pendingPair.account) : t.ann_join_h(pendingPair.account) }}
        </p>
        <p class="muted">{{ pendingPair.mode === 'adopt' ? t.ann_adopt_c : t.ann_join_c }}</p>
        <p v-if="pendingPair.mode === 'adopt'" class="muted" data-testid="announce-adopt-no">{{ t.ann_adopt_no }}</p>
        <div class="row">
          <button v-if="pendingPair.mode !== 'adopt'" class="btn" data-testid="announce-go"
                  :disabled="pairing" @click="acceptAnnounce">{{ t.ann_go }}</button>
          <button class="btn ghost" data-testid="announce-cancel" @click="cancelAnnounce">{{ t.ann_cancel }}</button>
        </div>
      </div>

      <template v-else-if="!pairCode">
        <p class="muted" data-testid="pair-new-account">{{ t.pair_new_account }}</p>
        <div class="row">
          <button class="btn" data-testid="scan" :disabled="pairing" @click="scan">{{ t.pair_scan }}</button>
          <button class="btn ghost" :disabled="pairing" @click="fileInput.click()">{{ t.pair_file }}</button>
        </div>
        <input ref="fileInput" type="file" accept="image/*,.dpair,.json,text/plain" hidden @change="onFile" />
        <div ref="scanHost" class="scanbox" v-show="scanning">
          <video playsinline muted></video>
          <button class="btn ghost sm" @click="scanStop && scanStop()">{{ t.cancel }}</button>
        </div>
        <details>
          <summary>{{ t.pair_paste }}</summary>
          <textarea v-model="pasted" rows="3" data-testid="pair-paste"
                    placeholder="cAgKy9m6jD310-TFoQuRirKOoh5EUSYOfjGi9BPEe-GX9sZT…"></textarea>
          <button class="btn ghost" data-testid="pair-go" :disabled="pairing" @click="connectPasted">{{ t.pair_go }}</button>
        </details>
      </template>

      <!-- Este dispositivo como bóveda -->
      <h2>{{ t.self_t }}</h2>
      <p class="muted">{{ t.self_b }}</p>
      <div class="row">
        <span class="tag" :class="{ master: self.running }">{{ self.running ? t.self_on : t.self_off }}</span>
        <button class="btn ghost" data-testid="self-toggle" @click="selfToggle">{{ self.enabled ? t.self_stop : t.self_start }}</button>
        <button v-if="self.running" class="btn" data-testid="self-pair" @click="selfPair">{{ t.self_pair }}</button>
      </div>
      <div v-if="selfQr" class="qrbox" v-html="selfQr"></div>
      <div v-for="p in selfPending" :key="p.deviceId" class="pending" data-testid="self-pending">
        <span>{{ t.self_pending }}: <code>{{ p.deviceId }}</code></span>
        <input v-model="selfCode" :placeholder="t.self_code_ph" inputmode="numeric" data-testid="self-code" />
        <button class="btn sm" data-testid="self-approve" @click="selfApprove(p.deviceId)">{{ t.self_approve }}</button>
        <button class="btn ghost sm" @click="selfReject(p.deviceId)">{{ t.self_reject }}</button>
      </div>
    </template>
  </section>
</template>

<style scoped>
.console { max-width: 860px; margin: 0 auto; padding: 24px 18px 64px; }
h1 { font-size: clamp(24px, 4vw, 34px); margin: 0 0 6px; }
h2 { font-size: 18px; margin: 32px 0 8px; }
.lead { color: #9fb0c9; margin: 0 0 20px; }
.muted { color: #8ea0b8; }
.facts { list-style: none; display: flex; flex-wrap: wrap; gap: 8px 18px; padding: 0; margin: 0 0 8px; color: #9fb0c9; }
.facts code, .mid { background: #131c2b; border-radius: 6px; padding: 1px 6px; font-size: 12px; }
.banner { border-radius: 10px; padding: 10px 12px; margin: 12px 0; font-size: 14px; }
.banner.ok { background: #0f2a1c; color: #7fe0a8; }
.banner.bad { background: #2a1113; color: #ff9aa2; }
.two-accounts, .announce { background: #101826; border: 1px solid #24344d; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
/* El aviso de lo que va a hacer la bóveda se lee ANTES de aceptar: destacado, no al vuelo. */
.announce { border-color: #2f4a6d; }
.announce p { margin: 0; }
.announce strong { color: #9cc4ff; }
.two-accounts p, .two-accounts ol { margin: 0; }
.two-accounts ol { padding-left: 20px; display: flex; flex-direction: column; gap: 3px; }
.banner.info { background: #10203a; color: #9cc4ff; }
.banner.warn { background: #2a2310; color: #ffd98a; }
.members { list-style: none; padding: 0; margin: 0; display: grid; gap: 10px; }
.member { background: #0f1725; border: 1px solid #1e2a3d; border-radius: 12px; padding: 12px 14px; }
.who { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.tag { font-size: 11px; background: #1b2536; color: #9fb0c9; border-radius: 999px; padding: 2px 8px; }
.tag.master { background: #1d3350; color: #9cc4ff; }
.tag.svc { background: #2a2310; color: #ffd98a; }
.svc-note { font-size: 12px; margin: 8px 0 0; }
.caps { display: flex; gap: 6px; flex-wrap: wrap; margin: 10px 0 0; }
.cap { font-size: 12px; border-radius: 999px; padding: 4px 10px; border: 1px solid #2a3a52; background: transparent; color: #7d8fa8; cursor: pointer; }
.cap.on { background: #14304a; color: #bfe0ff; border-color: #2f5f8f; }
.cap:disabled { cursor: default; opacity: .75; }
.acts { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.confirm { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 10px; font-size: 13px; color: #ffd98a; }
.btn { border-radius: 10px; padding: 8px 14px; border: 1px solid #2a3a52; background: #17263c; color: #dbe7f7; cursor: pointer; font: inherit; }
.btn.ghost { background: transparent; }
.btn.danger { background: #2a1113; border-color: #5a2027; color: #ff9aa2; }
.btn.sm { padding: 5px 10px; font-size: 13px; }
.btn:disabled { opacity: .5; cursor: default; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
textarea { width: 100%; background: #0d1521; color: #dbe7f7; border: 1px solid #223047; border-radius: 10px; padding: 10px; font-family: ui-monospace, monospace; font-size: 12px; }
.codebox { background: #0f1725; border: 1px solid #2f5f8f; border-radius: 12px; padding: 16px; text-align: center; margin: 12px 0; }
.digits { font-size: 34px; letter-spacing: .18em; font-family: ui-monospace, monospace; color: #bfe0ff; margin: 6px 0; }
.qrbox { background: #fff; padding: 12px; border-radius: 12px; width: max-content; margin: 12px 0; }
.qrbox :deep(svg) { width: 220px; height: 220px; display: block; }
.scanbox { margin: 10px 0; }
.scanbox video { width: 100%; max-width: 360px; border-radius: 12px; background: #000; }
.pending { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; background: #10203a; border-radius: 10px; padding: 10px 12px; margin: 10px 0; }
.pending input { background: #0d1521; color: #dbe7f7; border: 1px solid #223047; border-radius: 8px; padding: 6px 10px; width: 140px; font-family: ui-monospace, monospace; }
details summary { cursor: pointer; color: #9fb0c9; margin: 10px 0 6px; }
</style>
