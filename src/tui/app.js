/**
 * app.js — TUI del vault (pantalla completa, sin dependencias).
 *
 * Le habla al daemon por `vaultControl.js` (archivos + señales); NO abre la
 * identidad ni la red. Cubre lo que pidió el dueño:
 *
 *   · Bóvedas (perfiles): crear · cambiar activa · renombrar · borrar · candado
 *   · Dispositivos (pares): ver · emparejar · aprobar/rechazar · revocar
 *   · Scopes y variables (secretos): ver · agregar · quitar
 *
 * LAS VARIABLES DE ENTORNO SE PONEN EN DOS SITIOS, y cada uno está donde se elige lo
 * que las distingue: las del SCOPE, que comparten todos los aparatos del perfil que
 * sirven ese namespace, en su pestaña; las de UN APARATO, que solo lee él y pisan a
 * las del scope, dentro de Dispositivos (tecla `e`), que es donde ya elegiste el
 * aparato. No se repiten en las dos pantallas a propósito: la de scopes enlaza a la
 * otra en vez de duplicarla.
 *
 * Cada "bóveda" es un PERFIL (maestra propia, dir propio, dispositivos y secretos
 * propios). Las acciones operan sobre la bóveda ACTIVA; para operar otra, cámbiala
 * en la pantalla de bóvedas.
 *
 * BILINGÜE (CONVENCIONES §9): todo el texto sale de `i18n.js` según `st.lang`; la
 * tecla `l` conmuta es/en en cualquier pantalla y recuerda la elección.
 *
 * LAS TECLAS NO CAMBIAN CON EL IDIOMA: son mnemónicos en INGLÉS y son las mismas
 * en español (lo que se traduce es la palabra que las explica en la barra de
 * ayuda). new · rename · delete · password · unlock · locK · pair · approve ·
 * reject · reVoke · refresh · back · language · quit. Una tecla significa LO MISMO
 * en todas las pantallas: `p` es SIEMPRE emparejar (también en Bóvedas, sin tener
 * que entrar antes), el candado es `k` (la `l` es el idioma) y la contraseña `c`.
 */
import { execFile } from 'node:child_process'
import { createTerm, widthOf } from './term.js'
import { qrToString } from '../qr.js'
import { dict, otherLang, loadLang, saveLang } from './i18n.js'
import * as vc from '../vaultControl.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Regex de validación (mismas que el store de secretos, protocol.js).
const NS_RE = /^[a-z0-9-]{1,32}$/
const KEY_RE = /^[A-Z0-9_]{1,64}$/

// ------------------------------- utilidades --------------------------------

/** Diccionario del idioma activo (español si el estado aún no lo trae). */
const L = (st) => dict(st?.lang)

/**
 * Errores en el idioma de la TUI. Los que nacen aquí o en `vaultControl` tienen
 * `code` y se traducen; los que REENVÍA el daemon llegan como texto y se muestran
 * tal cual (son diagnósticos del servicio, no copy de la interfaz).
 */
function humanErr (e, st) {
  const t = L(st)
  const byCode = {
    DAEMON_DOWN: t.errDaemonDown,
    NO_REPLY: t.errNoReply,
    NOT_APPLIED: t.errNotApplied,
    NOT_DELETED: t.errNotDeleted,
    PAIR_FAILED: t.errPairFailed,
    MASTER_WITH_MEMBERS: t.errMasterWithMembers,
    PROFILE_LOCKED: t.errProfileLocked
  }
  return byCode[e?.code] || e?.message || String(e)
}

function flash (st, text, kind = 'ok') { st.flash = { text, kind, at: Date.now() } }

function fmtExp (exp) {
  if (!exp) return '—'
  const d = new Date(exp)
  return isNaN(d) ? String(exp) : d.toISOString().slice(0, 10)
}

const shortScope = (scope) => {
  const arr = Array.isArray(scope) ? scope : (scope ? [scope] : [])
  return arr.map((s) => String(s).replace(/^vault:/, '')).join(',') || '—'
}

/**
 * Un aparato = una llave (`sub`), aunque tenga varios certificados vigentes. Se queda con
 * el de vencimiento más lejano (el último emitido) y suma los alcances de todos, para que
 * la fila no prometa menos de lo que el aparato puede hacer de verdad.
 */
function groupByDevice (issued) {
  const by = new Map()
  for (const d of issued) {
    const key = d.sub || d.deviceId || d.nonce
    const prev = by.get(key)
    if (!prev) { by.set(key, { ...d, certCount: 1, scope: [...(Array.isArray(d.scope) ? d.scope : [d.scope])] }); continue }
    prev.certCount++
    for (const s of (Array.isArray(d.scope) ? d.scope : [d.scope])) if (!prev.scope.includes(s)) prev.scope.push(s)
    if ((d.exp || 0) > (prev.exp || 0)) { prev.exp = d.exp; prev.nonce = d.nonce; prev.label = d.label || prev.label }
  }
  return [...by.values()]
}

/**
 * LA lista de dispositivos: el acta, con el certificado de cada uno pegado.
 *
 * El acta es quien dice de quién es el perfil; los certificados son el reflejo de esa
 * decisión y pueden faltar (retirados, vencidos). Un miembro sin certificado sale igual,
 * marcado como «sin acceso», porque es exactamente el que hay que poder quitar.
 *
 * Si todavía no hay acta (bóveda anterior al acta, o sin volcar), se cae a los
 * certificados: peor lista, pero lista.
 */
function mergeMembersAndCerts (members, issued) {
  const certs = new Map()
  for (const d of groupByDevice(issued)) certs.set(d.sub || d.deviceId || d.nonce, d)
  if (!Array.isArray(members) || !members.length) return [...certs.values()]
  return members.map((m) => {
    const cert = certs.get(m.pub)
    return {
      ...(cert || {}),
      sub: m.pub,
      deviceId: m.id || cert?.deviceId || '????-????',
      label: m.label || cert?.label || '',
      isMaster: !!m.isMaster,
      cn: m.cn || null,
      // El master es la propia bóveda: no tiene (ni necesita) certificado. Un servicio
      // tampoco lleva uno de dispositivo. Marcarlos «sin acceso» sería una alarma falsa.
      noAccess: !cert && !m.isMaster && !m.cn
    }
  })
}

function activeProfile (st) {
  const list = st.profiles?.profiles || []
  return list.find((p) => p.current) || list[0] || null
}
const activeId = (st) => activeProfile(st)?.id || undefined

function lockGlyph (p) {
  if (!p?.protected) return ''
  return p.locked ? '🔒' : '🔓'
}

function startDaemonService () {
  return new Promise((res) => {
    execFile('systemctl', ['--user', 'start', 'dotrino-vault'], { timeout: 8000 }, (err, so, se) => {
      res({ ok: !err, err: err ? (String(se || '').trim() || err.message) : '' })
    })
  })
}

// -------------------- render: modelo de filas + listas ---------------------

/**
 * Dibuja una lista con scroll. `rows`: [{ text, sel?, meta? }]. `selIdx` indexa el
 * SUBCONJUNTO seleccionable. Devuelve exactamente `height` líneas.
 */
function renderList (rows, selIdx, height, cols, t, scrollRef) {
  const selectable = []
  rows.forEach((r, i) => { if (r.sel) selectable.push(i) })
  const curRow = selectable.length ? selectable[Math.max(0, Math.min(selIdx, selectable.length - 1))] : -1

  let top = scrollRef.value || 0
  if (curRow >= 0) {
    if (curRow < top) top = curRow
    else if (curRow >= top + height) top = curRow - height + 1
  }
  top = Math.max(0, Math.min(top, Math.max(0, rows.length - height)))
  scrollRef.value = top

  const out = []
  for (let i = 0; i < height; i++) {
    const r = rows[top + i]
    if (!r) { out.push(''); continue }
    if (top + i === curRow) out.push(t.sel(r.text, cols))
    else out.push(r.text)
  }
  return out
}

/**
 * Scroll simple para una lista de líneas planas (no seleccionables). Igual idea
 * que `renderList`, pero sin índice de selección: solo desplaza la ventana.
 */
function scrollBody (lines, height, scrollRef) {
  let top = scrollRef.value || 0
  top = Math.max(0, Math.min(top, Math.max(0, lines.length - height)))
  scrollRef.value = top
  const out = []
  for (let i = 0; i < height; i++) out.push(lines[top + i] ?? '')
  return out
}

/**
 * Barra de ayuda que SIEMPRE deja ver lo global (idioma y salir): si los segmentos
 * no caben, recorta desde el MEDIO y marca el corte con «…». Sin esto, en 80
 * columnas la ayuda se cortaba por la derecha y las teclas del final (justo las
 * globales) no existían para quien no las supiera de memoria.
 */
function fitHelp (segs, cols) {
  const join = (a) => a.join(' · ')
  if (widthOf(join(segs)) + 1 <= cols) return join(segs)
  const head = segs.slice(0, 1)
  const tail = segs.slice(-2)
  const mid = segs.slice(1, -2)
  while (mid.length) {
    mid.pop()
    const cand = join([...head, ...mid, '…', ...tail])
    if (widthOf(cand) + 1 <= cols) return cand
  }
  return join([...head, '…', ...tail])
}

// --------------------------------- pantallas -------------------------------

function profileRows (st, t) {
  const i = L(st)
  const list = st.profiles?.profiles || []
  return list.map((p) => {
    const mark = p.current ? t.accent('●') : ' '
    const lk = !p.protected ? t.muted(i.noPassword) : (p.locked ? t.warn(i.locked) : t.ok(i.unlocked))
    const name = p.current ? t.bold(p.name || i.noName) : (p.name || i.noName)
    return { text: ` ${mark} ${name}   ${t.muted(p.id)}   ${t.muted(p.fingerprint || '—')}   ${lk}`, sel: true, meta: p }
  })
}

function deviceRows (st, t) {
  const i = L(st)
  const rows = []
  const pend = st.pending
  if (pend) {
    rows.push({ text: t.warn(i.pendingDevice(pend.deviceId)) + t.muted(i.pendingHint), sel: false })
    rows.push({ text: '', sel: false })
  }
  // UNA FILA POR APARATO, no por certificado. Antes se pintaba `issued` tal cual y un
  // aparato con dos certs (el viejo + el de la renovación) salía dos veces: parecían dos
  // máquinas. Se agrupa por llave y se muestra el cert vigente más largo.
  //
  // Y la lista sale del ACTA, no de los certificados: el acta dice quién es del perfil, y
  // los certificados son su reflejo. Un miembro sin certificado vigente —porque le
  // retiraron el papel pero no lo sacaron del acta, o porque se le venció— no salía en
  // ninguna pantalla del PC: invisible aquí, presente en la del navegador, y sin forma de
  // quitarlo más que adivinando su ID para el `revoke` de la línea de comandos.
  const devices = mergeMembersAndCerts(st.members, st.devices?.issued || [])
  if (!devices.length) {
    rows.push({ text: t.muted(i.noDevices), sel: false })
  }
  for (const d of devices) {
    const label = d.label || t.muted(i.noLabel)
    const vars = devVarsOf(st, d.sub).length
    const extra = (d.certCount > 1 ? t.muted(`  certs:${d.certCount}`) : '') +
      (vars ? t.muted(`  vars:${vars}`) : '')
    // SIN ACCESO: está en el acta y no puede entrar. Es un aviso, no un adorno, así que va
    // en el color de aviso y en el sitio donde estaría su vencimiento.
    const estado = d.noAccess
      ? t.warn(i.deviceNoAccess)
      : d.isMaster
        ? t.muted(i.thisVault)
        : t.muted('scope:' + shortScope(d.scope)) + '  ' + t.muted('exp:' + fmtExp(d.exp))
    rows.push({ text: ` ${t.bold(d.deviceId)}  ${label}  ${estado}${extra}`, sel: true, meta: d })
  }
  const revoked = st.devices?.revoked || []
  if (revoked.length) {
    rows.push({ text: '', sel: false })
    rows.push({ text: t.muted(i.revokedCount(revoked.length)), sel: false })
  }
  return rows
}

/**
 * LA PREGUNTA DEL EMPAREJAMIENTO. La decisión es del vault (es quien lo inicia) y
 * este daemon puede tener varias cuentas: antes de mostrar el QR hay que decir a
 * cuál entra el dispositivo. Hoy se responde con las dos formas que existen —una
 * cuenta que ya vive aquí, o una nueva que se estrena para él—; la tercera
 * («adoptar la que trae el aparato») necesita el protocolo de adopción y se
 * muestra desactivada para no prometer lo que todavía no hace
 * (docs/vinculacion-de-cuentas.md §5).
 */
function pairModeRows (st, t) {
  const i = L(st)
  const ap = activeProfile(st)
  const rows = [{ text: t.muted(' ' + i.pairModeIntro), sel: false }, { text: '', sel: false }]
  rows.push({ text: ` ${t.bold(i.pairModeHere(ap?.name || ap?.id || '—'))}`, sel: true, meta: { mode: 'here' } })
  rows.push({ text: t.muted('     ' + i.pairModeHereHint), sel: false })
  rows.push({ text: '', sel: false })
  rows.push({ text: ` ${t.bold(i.pairModeNew)}`, sel: true, meta: { mode: 'new' } })
  rows.push({ text: t.muted('     ' + i.pairModeNewHint), sel: false })
  rows.push({ text: '', sel: false })
  rows.push({ text: ' ' + t.muted(i.pairModeAdopt), sel: false })
  rows.push({ text: t.muted('     (' + i.pairModeAdoptSoon + ')'), sel: false })
  return rows
}

/**
 * PERMISOS de un dispositivo. Los cuatro que existen, con lo que significan en cristiano y
 * una marca de si los tiene. El de administrar va aparte y avisado: es el único que deja
 * a ese aparato meter y sacar dispositivos sin venir aquí.
 */
const CAPS_ORDEN = ['sign', 'store', 'read', 'admin']

function capsRows (st, t) {
  const i = L(st)
  const target = st.capsFor
  if (!target) return [{ text: t.muted(i.loading), sel: false }]
  const member = (st.members || []).find((m) => m.pub === target.pub)
  if (!member) return [{ text: t.muted(i.capsNoMember), sel: false }]

  const has = new Set(member.caps || [])
  const rows = [
    { text: ' ' + t.bold(i.capsFor(target.deviceId, member.label || '')), sel: false },
    { text: '', sel: false }
  ]
  for (const cap of CAPS_ORDEN) {
    const mark = has.has(cap) ? '[x]' : '[ ]'
    const name = i.capName[cap]
    const line = ` ${mark}  ${cap === 'admin' ? t.bold(name) : name}`
    rows.push({ text: line, sel: true, meta: { cap } })
    rows.push({ text: t.muted('      ' + i.capHint[cap]), sel: false })
  }
  rows.push({ text: '', sel: false })
  rows.push({ text: t.muted(' ' + i.capsApplyHint), sel: false })
  return rows
}

/** Las variables por SCOPE: las que comparten todos los aparatos que sirven ese ns. */
function secretRows (st, t) {
  const i = L(st)
  const ns = st.secrets?.ns || {}
  const names = Object.keys(ns).sort()
  const rows = []
  // El puntero a la otra pantalla va SIEMPRE, con scopes y sin ellos: es la mitad de la
  // función y quien la busca no tiene por qué adivinar que vive en Dispositivos.
  const footer = [{ text: '', sel: false }, { text: t.muted(' ' + i.devVarsElsewhere), sel: false }]
  if (!names.length) return [{ text: t.muted(i.noScopes), sel: false }, ...footer]
  for (const n of names) {
    rows.push({ text: t.accent(` ▸ ${n}`) + t.muted(i.scopeOf(n)), sel: true, meta: { ns: n, key: null } })
    for (const k of sortByKey(ns[n])) {
      rows.push({ text: varLine(k, t, i), sel: true, meta: { ns: n, key: k.key, public: k.public } })
    }
  }
  return [...rows, ...footer]
}

/** Las claves guardadas para UN aparato (`pub`), o `[]`. Cada una es `{key, public}`. */
const devVarsOf = (st, pub) => (st.secrets?.dev || []).find((x) => x.pub === pub)?.keys || []

const sortByKey = (list) => (list || []).slice().sort((a, b) => a.key.localeCompare(b.key))

/**
 * Una variable: su nombre, el valor tapado y —si es pública— el aviso de que ese valor
 * SALE de esta máquina cuando la consola remota lo pide. Es un dato operativo, no un
 * adorno: es la diferencia entre un secreto que solo vive aquí y uno que viaja.
 */
const varLine = (v, t, i) => `      ${v.key}   ${t.muted('••••••')}${v.public ? '   ' + t.warn(i.varPublic) : ''}`

/**
 * Las variables de UN aparato. Se entra desde Dispositivos con `e`, ya con el aparato
 * elegido: por eso aquí no se vuelve a elegir, solo se agrega y se quita.
 */
function devVarRows (st, t) {
  const i = L(st)
  const target = st.varsFor
  if (!target) return [{ text: t.muted(i.loading), sel: false }]
  const keys = sortByKey(devVarsOf(st, target.pub))
  const rows = [
    { text: ' ' + t.bold(i.devVarsFor(target.deviceId, target.label || '')), sel: false },
    // Dato, no explicación: qué servicio es este aparato es lo que decide qué namespace
    // lee, y por lo tanto a qué variables del scope le ganan estas.
    { text: t.muted(' ' + i.devVarsService(target.cn)), sel: false },
    { text: '', sel: false }
  ]
  if (!keys.length) rows.push({ text: t.muted(' ' + i.noDevVars), sel: false })
  for (const k of keys) rows.push({ text: varLine(k, t, i), sel: true, meta: { key: k.key, public: k.public } })
  return rows
}

/**
 * PERFIL del usuario: nombre, foto y datos, tal como los tiene la bóveda. Es lo que se
 * edita en un dispositivo emparejado y se sincroniza aquí; esta pantalla sirve para
 * comprobar que llegó.
 *
 * Solo lectura A PROPÓSITO: el perfil se edita donde lo usas (el aparato), no en el
 * servidor donde vive la bóveda. Aquí se mira.
 */
function meRows (st, t) {
  const i = L(st)
  const me = st.me
  if (me === undefined) return [{ text: t.muted(i.loading), sel: false }]
  if (!me) return [{ text: t.muted(i.noProfile), sel: false }, { text: '', sel: false }, { text: t.muted(i.noProfileHint), sel: false }]

  const rows = []
  const campo = (etiqueta, valor, oculto) => rows.push({
    text: `  ${t.muted(String(etiqueta).padEnd(12))} ${valor}${oculto ? t.muted(i.hidden) : ''}`, sel: false
  })
  rows.push({ text: t.muted(i.profileUpdated(me.updatedAt ? new Date(me.updatedAt).toLocaleString() : '—')), sel: false })
  rows.push({ text: '', sel: false })
  campo(i.fieldName, me.nickname ? t.bold(me.nickname) : t.muted(i.noName))
  campo(i.fieldPhoto, me.avatar
    ? `${me.avatar.type || '?'} · ${(me.avatar.bytes / 1024).toFixed(1)} KB`
    : t.muted(i.no))

  const STD = [['nombres', i.fieldFirstName], ['apellidos', i.fieldLastName], ['email', i.fieldEmail],
    ['telefono', i.fieldPhone], ['direccion', i.fieldAddress]]
  const puestos = STD.filter(([k]) => me[k])
  if (puestos.length) rows.push({ text: '', sel: false })
  for (const [k, etiqueta] of puestos) campo(etiqueta, me[k], me[k + 'Visible'] === false)

  for (const [titulo, lista] of [[i.links, me.links], [i.otherData, me.fields]]) {
    if (!Array.isArray(lista) || !lista.length) continue
    rows.push({ text: '', sel: false })
    rows.push({ text: t.accent(' ▸ ' + titulo), sel: false })
    for (const x of lista) campo(x.type || x.label || '', x.value, x.visible === false)
  }
  return rows
}

// --------------------------------- entrada ---------------------------------

function setInput (st, opts) {
  st.input = { value: '', mask: false, hint: '', ...opts }
}
function setConfirm (st, opts) { st.confirm = { ...opts } }

// --------------------------------- refresco --------------------------------

async function guard (term, st, msg, fn) {
  st.busy = msg
  render(term, st)
  try { const v = await fn(); st.busy = null; return { ok: true, v } } catch (e) { st.busy = null; flash(st, humanErr(e, st), 'danger'); return { ok: false, e } }
}

/**
 * ¿La bóveda ACTIVA está cerrada? El candado es POR BÓVEDA, no del vault: que una esté
 * cerrada no puede dejarte sin la lista ni sin poder entrar a otra.
 */
const activeLocked = (st) => { const p = activeProfile(st); return !!(p?.protected && p.locked) }

// `api` es `vaultControl` — se recibe para poder probar ESTA función (la que se rompió)
// sin un daemon detrás, que es donde vive la regla de qué se pide y en qué orden.
async function refreshAll (term, st, api = vc) {
  // LA LISTA DE BÓVEDAS VA PRIMERO Y APARTE. Antes esto pedía el volcado de la bóveda
  // activa y, si esa era la cerrada, se salía sin llegar a guardar la lista: la TUI abría
  // en blanco, sin bóvedas y con un error rojo. O sea que la contraseña de UNA bóveda te
  // dejaba fuera del vault entero, que es exactamente lo que un candado por perfil no debe
  // hacer.
  const p = await guard(term, st, L(st).loadingVaults, () => api.listProfiles())
  if (p.ok) st.profiles = p.v
  // Cerrada: no se pide su contenido, y tampoco se enseña un error por mirarla desde
  // fuera. Lo que hubiera cargado se suelta, para no dejar en pantalla lo de antes.
  if (activeLocked(st)) {
    st.devices = null; st.secrets = null; st.members = []; st.me = undefined
    return
  }
  const r = await guard(term, st, L(st).loading, () => api.snapshot(activeId(st)))
  if (!r.ok) return
  const { devices, secrets, profiles, acta } = r.v
  if (profiles) st.profiles = profiles
  // Los DOS cajones de variables viajan juntos: `ns` (por scope) y `dev` (por aparato).
  if (secrets) st.secrets = { ns: secrets.ns || {}, dev: Array.isArray(secrets.dev) ? secrets.dev : [] }
  // El ACTA entra en el volcado normal: es de donde sale la lista de dispositivos (ver
  // `mergeMembersAndCerts`). Antes solo se pedía al abrir la pantalla de permisos.
  if (acta) st.members = acta.members || []
  if (devices) {
    const issued = (devices.issued || devices.active || devices.delegations || [])
    st.devices = { issued: await Promise.all(issued.map(async (d) => ({ ...d, deviceId: d.sub ? await api.deviceIdOf(d.sub) : '????-????' }))), revoked: devices.revoked || [] }
  }
}

async function refreshDevices (term, st) {
  const r = await guard(term, st, L(st).loadingDevices, () => vc.listDevices(activeId(st)))
  if (!r.ok) return
  st.devices = r.v
  // La lista se pinta desde el acta; traerla aparte dejaba la pantalla con los miembros de
  // hace dos operaciones (quitar uno no lo quitaba de la vista).
  if (Array.isArray(r.v.members)) st.members = r.v.members
}
async function refreshSecrets (term, st) {
  const r = await guard(term, st, L(st).loadingSecrets, () => vc.listSecrets(activeId(st)))
  if (r.ok) st.secrets = r.v
}
async function refreshMembers (term, st) {
  const r = await guard(term, st, L(st).loadingMembers, () => vc.listMembers(activeId(st)))
  if (r.ok) st.members = r.v
}
async function refreshMe (term, st) {
  const r = await guard(term, st, L(st).loadingProfile, () => vc.getMe(activeId(st)))
  st.me = r.ok ? r.v : null
}
async function refreshProfiles (term, st) {
  const r = await guard(term, st, L(st).loadingVaults, () => vc.listProfiles())
  if (r.ok) st.profiles = r.v
}

/**
 * Pide la contraseña si hace falta y sigue. Lo que se abre aquí queda anotado en
 * `st.unlockedHere` para volver a cerrarlo AL SALIR (ver `runTui`): la contraseña dura lo
 * que dura la sesión, no hasta que alguien reinicie el servicio. Lo que ya estaba abierto
 * antes de entrar no se toca — no lo abrió esta pantalla, no le toca cerrarlo.
 */
async function ensureUnlocked (term, st, p, thenFn) {
  if (!p.protected || !p.locked) return thenFn()
  const i = L(st)
  setInput(st, {
    label: i.passwordOf(p.name || p.id),
    mask: true,
    hint: i.passwordToEdit,
    onSubmit: async (pwd) => {
      st.input = null
      const r = await guard(term, st, i.unlocking, () => vc.unlockProfile(p.id, pwd))
      if (!r.ok) return
      st.unlockedHere?.add(p.id)
      await refreshProfiles(term, st)
      const fresh = (st.profiles.profiles || []).find((x) => x.id === p.id) || p
      await thenFn(fresh)
    },
    onCancel: () => { st.input = null }
  })
}

// --------------------------------- teclas ----------------------------------

function moveSel (st, key, screen, count) {
  if (count <= 0) { st.sel[screen] = 0; return }
  // Clampa el índice guardado ANTES de apply el delta: si la lista encogió, la
  // primera flecha debe moverse desde la posición visible, no desde un índice viejo.
  st.sel[screen] = Math.max(0, Math.min(st.sel[screen], count - 1))
  if (key.name === 'up') st.sel[screen] = Math.max(0, st.sel[screen] - 1)
  else if (key.name === 'down') st.sel[screen] = Math.min(count - 1, st.sel[screen] + 1)
  else if (key.name === 'pageup') st.sel[screen] = Math.max(0, st.sel[screen] - 5)
  else if (key.name === 'pagedown') st.sel[screen] = Math.min(count - 1, st.sel[screen] + 5)
  else if (key.name === 'home') st.sel[screen] = 0
  else if (key.name === 'end') st.sel[screen] = count - 1
}

/** Conmuta es⇄en, lo recuerda y lo dice en el idioma NUEVO. */
function toggleLang (st) {
  st.lang = otherLang(st.lang)
  saveLang(st.lang)
  flash(st, L(st).langChanged)
}

async function onKeyProfiles (term, st, key) {
  const i = L(st)
  const rows = profileRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'profiles', sels.length)
  const cur = sels[Math.min(st.sel.profiles, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (key.name === 'enter' && cur) {
    // Entrar a la bóveda: la activa (si no lo estaba ya) y pasa a sus pestañas
    // (Dispositivos/Scopes) — así siempre es explícito de qué bóveda son los ítems.
    //
    // Y si tiene candado, se pide la contraseña AQUÍ, antes de enseñar nada: dentro se ven
    // los aparatos, las variables y tus datos, que es justo lo que la contraseña tapa.
    await ensureUnlocked(term, st, cur, async (p = cur) => {
      if (!p.current) {
        const r = await guard(term, st, i.switchingVault, () => vc.useProfile(p.id))
        if (!r.ok) return
        flash(st, i.vaultNowActive(p.name || p.id))
        await refreshAll(term, st)
      }
      st.screen = 'devices'
      await refreshDevices(term, st)
    })
  } else if (ch === 'p' && cur) {
    // Emparejar SIN tener que entrar antes: `p` significa lo mismo aquí que en la
    // pestaña Dispositivos. Se activa la bóveda elegida (el QR sale de UNA, y las
    // acciones siguientes —aprobar, revocar— miran a la activa) y se abre la
    // pregunta de a qué cuenta entra el dispositivo.
    await ensureUnlocked(term, st, cur, async (p = cur) => {
      if (!p.current) {
        const r = await guard(term, st, i.switchingVault, () => vc.useProfile(p.id))
        if (!r.ok) return
        await refreshAll(term, st)
      }
      st.sel.pairmode = 0
      st.scroll.pairmode = { value: 0 }
      st.screen = 'pairmode'
    })
  } else if (ch === 'n') {
    setInput(st, {
      label: i.newVaultLabel,
      hint: i.newVaultHint,
      onSubmit: async (name) => {
        st.input = null
        if (!name.trim()) { flash(st, i.nameEmpty, 'danger'); return }
        const r = await guard(term, st, i.creatingVault, () => vc.addProfile(name.trim()))
        if (r.ok) { flash(st, i.vaultCreated(name.trim())); await refreshProfiles(term, st) }
      },
      onCancel: () => { st.input = null }
    })
  } else if (ch === 'r' && cur) {
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: i.renameLabel(p.name || p.id),
      value: p.name || '',
      onSubmit: async (name) => {
        st.input = null
        if (!name.trim()) { flash(st, i.nameEmpty, 'danger'); return }
        const r = await guard(term, st, i.renaming, () => vc.renameProfile(p.id, name.trim()))
        if (r.ok) { flash(st, i.vaultRenamed); await refreshProfiles(term, st) }
      },
      onCancel: () => { st.input = null }
    }))
  } else if ((key.name === 'delete' || ch === 'd') && cur) {
    if ((st.profiles.profiles || []).length <= 1) { flash(st, i.cantDeleteLast, 'danger'); return true }
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: i.deleteLabel(p.name || p.id),
      hint: i.deleteHint,
      onSubmit: async (typed) => {
        st.input = null
        if (typed.trim() !== (p.name || p.id)) { flash(st, i.deleteMismatch, 'warn'); return }
        const r = await guard(term, st, i.deletingVault, () => vc.removeProfile(p.id))
        if (r.ok) { flash(st, i.vaultDeleted); st.sel.profiles = 0; await refreshAll(term, st) }
      },
      onCancel: () => { st.input = null }
    }))
  } else if (ch === 'c' && cur) { // change password (la `p` es emparejar, igual que en Dispositivos)
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: i.newPasswordLabel(p.name || p.id),
      mask: true,
      onSubmit: async (pwd) => {
        st.input = null
        if (pwd.length < 4) { flash(st, i.passwordTooShort, 'danger'); return }
        setInput(st, {
          label: i.repeatPassword,
          mask: true,
          onSubmit: async (again) => {
            st.input = null
            if (again !== pwd) { flash(st, i.passwordMismatch, 'danger'); return }
            const r = await guard(term, st, i.savingPassword, () => vc.setProfilePassword(p.id, pwd))
            if (r.ok) { flash(st, i.passwordSaved); await refreshProfiles(term, st) }
          },
          onCancel: () => { st.input = null }
        })
      },
      onCancel: () => { st.input = null }
    }))
  } else if (ch === 'x' && cur) { // quitar contraseña
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    await ensureUnlocked(term, st, cur, async (p = cur) => {
      const r = await guard(term, st, i.removingPassword, () => vc.removeProfilePassword(p.id))
      if (r.ok) { flash(st, i.passwordRemoved); await refreshProfiles(term, st) }
    })
  } else if (ch === 'u' && cur) {
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    if (!cur.locked) { flash(st, i.alreadyUnlocked, 'warn'); return true }
    await ensureUnlocked(term, st, cur, async () => { flash(st, i.vaultUnlocked); await refreshProfiles(term, st) })
  } else if (ch === 'k' && cur) { // locK (antes `l`, que ahora es el idioma)
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    const r = await guard(term, st, i.lockingVault, () => vc.lockProfile(cur.id))
    if (r.ok) { flash(st, i.vaultLocked); await refreshProfiles(term, st) }
  }
  return true
}

async function onKeyDevices (term, st, key) {
  const i = L(st)
  // Sondea el dispositivo pendiente en cada tick (uno puede conectarse mientras
  // estás en esta pantalla, no solo en la de emparejamiento).
  if (key.name === 'tick') { st.pending = vc.pendingEnroll(); return true }

  const rows = deviceRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'devices', sels.length)
  const cur = sels[Math.min(st.sel.devices, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (ch === 'p') { // pair → primero LA PREGUNTA (a qué cuenta entra), luego el QR
    st.sel.pairmode = 0
    st.scroll.pairmode = { value: 0 }
    st.screen = 'pairmode'
  } else if (ch === 'a') { // aprobar el pendiente
    if (!st.pending) { flash(st, i.noPending, 'warn'); return true }
    promptApprove(term, st)
  } else if (ch === 'x') { // rechazar el pendiente
    if (!st.pending) { flash(st, i.noPendingToReject, 'warn'); return true }
    const r = await guard(term, st, i.rejecting, () => vc.rejectPending(st.pending.deviceId, activeId(st)))
    if (r.ok) { flash(st, i.deviceRejected); st.pending = null }
  } else if ((ch === 'v' || key.name === 'delete') && cur?.isMaster) {
    // La bóveda no se echa a sí misma: el acta la necesita para poder sellarse. Se dice
    // en vez de mandar la orden y enseñar el error del daemon, que no explica nada.
    flash(st, i.cantRemoveMaster, 'warn')
  } else if ((ch === 'v' || key.name === 'delete') && (cur?.sub || cur?.nonce != null)) { // quitar el aparato seleccionado
    setConfirm(st, {
      text: i.revokeConfirm(cur.deviceId),
      onYes: async () => {
        st.confirm = null
        // Por `sub`: se le retiran TODOS los certificados, no solo el de esta fila.
        const r = await guard(term, st, i.revoking, () => vc.revokeDevice({ sub: cur.sub, nonce: cur.nonce }, activeId(st)))
        if (r.ok) { flash(st, i.deviceRevoked(cur.deviceId)); st.devices = r.v; st.sel.devices = 0 }
      },
      onNo: () => { st.confirm = null }
    })
  } else if (ch === 'r' && cur) {
    // Renombrar: el nombre lo trae el aparato al emparejarse (y si no le diste uno, entra
    // con TU apodo de ese momento), así que a la semana ya no dice nada. `r` es renombrar
    // también en Bóvedas: una tecla, un significado.
    setInput(st, {
      label: i.renameDeviceLabel(cur.deviceId),
      hint: i.renameDeviceHint,
      value: cur.label || '',
      onSubmit: async (raw) => {
        const name = String(raw || '').trim()
        if (!name) return
        const r = await guard(term, st, i.renaming, () => vc.setDeviceLabel(cur.sub, name, activeId(st)))
        if (r.ok) { st.devices = r.v; flash(st, i.deviceRenamed(name)) }
      }
    })
  } else if (ch === 'c' && cur?.sub) {
    st.capsFor = { pub: cur.sub, deviceId: cur.deviceId }
    st.sel.caps = 0
    await refreshMembers(term, st)
    st.screen = 'caps'
  } else if (ch === 'e' && cur?.sub) {
    // Variables de ESTE aparato. Solo un servicio las lee (es el único que pide su
    // bundle), así que a un teléfono se le dice que no y por qué, en vez de dejarle
    // guardar configuración que no va a leer nadie.
    if (!cur.cn) { flash(st, i.devVarsOnlyServices, 'warn'); return true }
    st.varsFor = { pub: cur.sub, deviceId: cur.deviceId, label: cur.label || '', cn: cur.cn }
    st.sel.devvars = 0
    await refreshSecrets(term, st)
    st.screen = 'devvars'
  } else if (key.name === 'f5') {
    await refreshDevices(term, st)
  }
  return true
}

/** Abre el emparejamiento contra `profile` y salta a la pantalla del QR. */
async function beginPairing (term, st, profile) {
  const r = await guard(term, st, L(st).startingPairing, () => vc.startPairing({ profile }))
  if (r.ok) { st.pairing = r.v; st.pending = null; st.scroll.pairing = { value: 0 }; st.screen = 'pairing' }
  return r.ok
}

/**
 * Enter marca o desmarca un permiso y lo aplica en el acto. Sin botón de «guardar»: cada
 * cambio se sella en el acta y se avisa a los demás aparatos, así que acumularlos en
 * pantalla solo serviría para que el acta y lo que ves dijeran cosas distintas.
 */
async function onKeyCaps (term, st, key) {
  const i = L(st)
  const rows = capsRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'caps', sels.length)
  const cur = sels[Math.min(st.sel.caps || 0, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (key.name === 'escape' || ch === 'b') { st.screen = 'devices'; st.capsFor = null; return true }
  if (key.name === 'f5') { await refreshMembers(term, st); return true }
  if ((key.name !== 'enter' && ch !== ' ') || !cur) return true

  const member = (st.members || []).find((m) => m.pub === st.capsFor?.pub)
  if (!member) return true
  const caps = new Set(member.caps || [])
  const giving = !caps.has(cur.cap)
  if (giving) caps.add(cur.cap); else caps.delete(cur.cap)

  const apply = async () => {
    const r = await guard(term, st, i.applyingCaps, () => vc.setDeviceCaps(member.pub, [...caps], activeId(st)))
    if (!r.ok) return
    st.devices = r.v
    await refreshMembers(term, st)
    flash(st, giving ? i.capGiven(i.capName[cur.cap]) : i.capTaken(i.capName[cur.cap]))
  }

  // Administrar se PREGUNTA: es el permiso que deja a ese aparato admitir y expulsar
  // dispositivos sin pasar por aquí. Los otros tres se marcan y ya.
  if (cur.cap === 'admin' && giving) {
    setConfirm(st, { text: i.confirmAdmin(st.capsFor.deviceId), onYes: apply })
    return true
  }
  await apply()
  return true
}

async function onKeyPairMode (term, st, key) {
  const i = L(st)
  const rows = pairModeRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'pairmode', sels.length)
  const cur = sels[Math.min(st.sel.pairmode, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (key.name === 'escape' || ch === 'b') { st.screen = 'devices'; return true }
  if (key.name !== 'enter' || !cur) return true

  if (cur.mode === 'here') { await beginPairing(term, st, activeId(st)); return true }

  // Cuenta nueva: se crea aquí, se ACTIVA (así aprobar/rechazar y las listas miran
  // a la misma que el QR) y recién entonces se abre el emparejamiento contra ella.
  setInput(st, {
    label: i.newAccountLabel,
    hint: i.newAccountHint,
    onSubmit: async (raw) => {
      st.input = null
      const name = raw.trim()
      if (!name) { flash(st, i.nameEmpty, 'danger'); return }
      const r = await guard(term, st, i.creatingVault, () => vc.addProfile(name))
      if (!r.ok) return
      const created = r.v?.id || (r.v?.profiles || []).find((p) => p.name === name)?.id
      if (!created) { flash(st, i.errNoReply, 'danger'); return }
      const u = await guard(term, st, i.switchingVault, () => vc.useProfile(created))
      if (!u.ok) return
      await refreshAll(term, st)
      flash(st, i.accountCreated(name))
      await beginPairing(term, st, created)
    },
    onCancel: () => { st.input = null }
  })
  return true
}

function promptApprove (term, st) {
  const i = L(st)
  setInput(st, {
    label: i.approveLabel(st.pending?.deviceId || ''),
    hint: i.approveHint,
    onSubmit: async (code) => {
      st.input = null
      if (!code.trim()) { flash(st, i.codeMissing, 'danger'); return }
      const r = await guard(term, st, i.approving, () => vc.approvePending(code.trim(), activeId(st)))
      if (r.ok) { flash(st, i.deviceApproved); st.devices = r.v; st.pending = null; st.screen = 'devices' }
    },
    onCancel: () => { st.input = null }
  })
}

async function onKeyPairing (term, st, key) {
  const i = L(st)
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null
  if (key.name === 'tick') {
    const pend = vc.pendingEnroll()
    if (pend) st.pending = pend
    return true
  }
  // Scroll vertical para ver el QR completo cuando no cabe en la pantalla.
  if (['up', 'down', 'pageup', 'pagedown', 'home', 'end'].includes(key.name)) {
    const { rows } = term.size()
    const contentH = Math.max(1, rows - 7)
    const pb = pairingBody(st, term.t, term.size().cols, contentH)
    const maxScroll = Math.max(0, pb.length - contentH)
    const scroll = st.scroll.pairing || (st.scroll.pairing = { value: 0 })
    if (key.name === 'up') scroll.value = Math.max(0, scroll.value - 1)
    else if (key.name === 'down') scroll.value = Math.min(maxScroll, scroll.value + 1)
    else if (key.name === 'pageup') scroll.value = Math.max(0, scroll.value - 5)
    else if (key.name === 'pagedown') scroll.value = Math.min(maxScroll, scroll.value + 5)
    else if (key.name === 'home') scroll.value = 0
    else if (key.name === 'end') scroll.value = maxScroll
    return true
  }
  if (ch === 'a' && st.pending) { promptApprove(term, st); return true }
  if (ch === 'x' && st.pending) {
    const r = await guard(term, st, i.rejecting, () => vc.rejectPending(st.pending.deviceId, activeId(st)))
    if (r.ok) { flash(st, i.deviceRejected); st.pending = null }
    return true
  }
  if (ch === 'r') { // restart: reiniciar el emparejamiento
    const r = await guard(term, st, i.restartingPairing, () => vc.startPairing({ profile: activeId(st) }))
    if (r.ok) { st.pairing = r.v; st.pending = null; st.scroll.pairing = { value: 0 } }
    return true
  }
  if (key.name === 'escape' || ch === 'b') { st.screen = 'devices'; st.pairing = null; await refreshDevices(term, st) }
  return true
}

/**
 * Teclas del PERFIL: solo refrescar. Nada de editar — el perfil se edita en el dispositivo
 * que usas, no en la máquina donde vive la bóveda.
 */
async function onKeyMe (term, st, key) {
  if (key.name === 'f5') await refreshMe(term, st)
  return true
}

async function onKeySecrets (term, st, key) {
  const i = L(st)
  const rows = secretRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'secrets', sels.length)
  const cur = sels[Math.min(st.sel.secrets, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (ch === 'n') {
    promptNewVariable(term, st)
  } else if ((ch === 'x' || key.name === 'delete') && cur) {
    if (cur.key) {
      setConfirm(st, {
        text: i.removeVarConfirm(cur.ns, cur.key),
        onYes: async () => {
          st.confirm = null
          const r = await guard(term, st, i.removingVar, () => vc.deleteSecret(cur.ns, cur.key, activeId(st)))
          if (r.ok) { flash(st, i.varRemoved); st.secrets = r.v; st.sel.secrets = Math.max(0, st.sel.secrets - 1) }
        },
        onNo: () => { st.confirm = null }
      })
    } else {
      const count = (st.secrets?.ns?.[cur.ns] || []).length
      setConfirm(st, {
        text: i.removeScopeConfirm(cur.ns, count),
        onYes: async () => {
          st.confirm = null
          const r = await guard(term, st, i.removingScope, () => vc.deleteScope(cur.ns, activeId(st)))
          if (r.ok) { flash(st, i.scopeRemoved(cur.ns)); st.secrets = r.v; st.sel.secrets = 0 }
        },
        onNo: () => { st.confirm = null }
      })
    }
  } else if (ch === 't' && cur?.key) {
    await toggleVisibility(term, st, cur.public, () => vc.setSecretVisibility(cur.ns, cur.key, !cur.public, activeId(st)))
  } else if (key.name === 'f5') {
    await refreshSecrets(term, st)
  }
  return true
}

/**
 * Hacer pública una variable es dejar que su valor SALGA de esta máquina, así que se
 * pregunta; volverla privada no expone nada y se aplica directo.
 */
async function toggleVisibility (term, st, wasPublic, apply) {
  const i = L(st)
  const run = async () => {
    const r = await guard(term, st, i.changingVisibility, apply)
    if (r.ok) { flash(st, wasPublic ? i.nowPrivate : i.nowPublic); st.secrets = r.v }
  }
  if (wasPublic) return run()
  setConfirm(st, { text: i.makePublicConfirm, onYes: run, onNo: () => { st.confirm = null } })
}

/**
 * Teclas de las variables de UN aparato: agregar y quitar. Nada más — el aparato ya se
 * eligió en Dispositivos, y de ahí se vuelve con Esc.
 */
async function onKeyDevVars (term, st, key) {
  const i = L(st)
  const rows = devVarRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'devvars', sels.length)
  const cur = sels[Math.min(st.sel.devvars || 0, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null
  const target = st.varsFor

  if (key.name === 'escape' || ch === 'b') {
    st.screen = 'devices'; st.varsFor = null
    await refreshDevices(term, st)
    return true
  }
  if (key.name === 'f5') { await refreshSecrets(term, st); return true }
  if (ch === 'n') { promptNewDeviceVariable(term, st); return true }
  if (ch === 't' && cur && target) {
    await toggleVisibility(term, st, cur.public, () => vc.setDeviceSecretVisibility(target.pub, cur.key, !cur.public, activeId(st)))
    return true
  }
  if ((ch === 'x' || key.name === 'delete') && cur && target) {
    setConfirm(st, {
      text: i.removeDevVarConfirm(target.deviceId, cur.key),
      onYes: async () => {
        st.confirm = null
        const r = await guard(term, st, i.removingVar, () => vc.deleteDeviceSecret(target.pub, cur.key, activeId(st)))
        if (r.ok) { flash(st, i.varRemoved); st.secrets = r.v; st.sel.devvars = Math.max(0, st.sel.devvars - 1) }
      },
      onNo: () => { st.confirm = null }
    })
  }
  return true
}

/**
 * Al crear una variable se PREGUNTA si su valor puede salir de esta máquina. Se pregunta
 * al crearla, y no después, porque es cuando quien la escribe sabe qué es: un puerto se
 * puede enseñar, una llave de producción no. La respuesta por defecto —Enter, o `n`— es
 * la privada.
 */
function askVisibility (term, st, done) {
  const i = L(st)
  setConfirm(st, {
    text: i.newVarPublicAsk,
    onYes: () => { st.confirm = null; done(true) },
    onNo: () => { st.confirm = null; done(false) }
  })
}

function promptNewDeviceVariable (term, st) {
  const i = L(st)
  const target = st.varsFor
  if (!target) return
  setInput(st, {
    label: i.keyLabel(target.deviceId),
    hint: i.keyHint,
    onSubmit: (key) => {
      const kv = key.trim()
      if (!KEY_RE.test(kv)) { flash(st, i.keyInvalid, 'danger'); return }
      st.input = null
      setInput(st, {
        label: i.valueLabel(target.deviceId, kv),
        mask: true,
        hint: i.valueHint,
        onSubmit: async (value) => {
          st.input = null
          if (!value) { flash(st, i.valueEmpty, 'danger'); return }
          askVisibility(term, st, async (isPublic) => {
            const r = await guard(term, st, i.savingVar, () => vc.setDeviceSecret(target.pub, kv, value, activeId(st), isPublic))
            if (r.ok) { flash(st, i.varSaved(target.deviceId, kv)); st.secrets = r.v }
          })
        },
        onCancel: () => { st.input = null }
      })
    },
    onCancel: () => { st.input = null }
  })
}

function promptNewVariable (term, st) {
  const i = L(st)
  const existing = Object.keys(st.secrets?.ns || {})
  setInput(st, {
    label: i.nsLabel,
    hint: existing.length ? i.nsHintExisting(existing.join(', ')) : i.nsHint,
    onSubmit: (ns) => {
      const nsv = ns.trim()
      if (!NS_RE.test(nsv)) { flash(st, i.nsInvalid, 'danger'); promptNewVariable(term, st); return }
      st.input = null
      setInput(st, {
        label: i.keyLabel(nsv),
        hint: i.keyHint,
        onSubmit: (key) => {
          const kv = key.trim()
          if (!KEY_RE.test(kv)) { flash(st, i.keyInvalid, 'danger'); return }
          st.input = null
          setInput(st, {
            label: i.valueLabel(nsv, kv),
            mask: true,
            hint: i.valueHint,
            onSubmit: async (value) => {
              st.input = null
              if (!value) { flash(st, i.valueEmpty, 'danger'); return }
              askVisibility(term, st, async (isPublic) => {
                const r = await guard(term, st, i.savingVar, () => vc.setSecret(nsv, kv, value, activeId(st), isPublic))
                if (r.ok) { flash(st, i.varSaved(nsv, kv)); st.secrets = r.v }
              })
            },
            onCancel: () => { st.input = null }
          })
        },
        onCancel: () => { st.input = null }
      })
    },
    onCancel: () => { st.input = null }
  })
}

// async + awaited desde el loop: así una operación contra el daemon (que puede
// tardar un round-trip) se SERIALIZA y no se solapa con la siguiente tecla —si no,
// dos ops corren a la vez y se pisan los archivos de respuesta compartidos.
async function onInputKey (st, key) {
  const inp = st.input
  if (key.name === 'escape' || key.name === 'ctrl-c') { const c = inp.onCancel; st.input = null; await c?.(); return }
  if (key.name === 'enter') { const f = inp.onSubmit; const v = inp.value; await f?.(v); return }
  if (key.name === 'backspace') { inp.value = inp.value.slice(0, -1); return }
  if (key.name === 'ctrl-u') { inp.value = ''; return }
  if (key.name === 'ctrl-w') { inp.value = inp.value.replace(/\s*\S+\s*$/, ''); return }
  if (key.name === 'char') inp.value += key.ch
}

async function onConfirmKey (st, key) {
  const cf = st.confirm
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null
  // La tecla es `y` (yes) en los dos idiomas —como el resto, mnemónico inglés—;
  // `s` (sí) se sigue aceptando por costumbre, pero no se anuncia en la ayuda.
  if (ch === 's' || ch === 'y') { const f = cf.onYes; st.confirm = null; await f?.() }
  else if (ch === 'n' || key.name === 'escape' || key.name === 'enter' || key.name === 'ctrl-c') { const f = cf.onNo; st.confirm = null; await f?.() }
}

// --------------------------------- render ----------------------------------

// Pestañas INTERNAS de una bóveda ya elegida: se cambian con ←→. La lista de
// bóvedas (profiles) es el nivel de arriba (se entra con Enter, no es una pestaña).
const INNER_TABS = ['devices', 'secrets', 'me']
const tabLabel = (i, k) => ({ devices: i.tabDevices, secrets: i.tabSecrets, me: i.tabMe })[k]

/**
 * Las teclas que se pueden usar AHORA, no el catálogo entero. Aprobar/rechazar sin nadie
 * esperando, o revocar sin un aparato seleccionado, no hacen nada: anunciarlas confunde
 * («¿por qué no pasa nada?») y además quema esas letras para otros usos en la pantalla.
 */
const helpSegs = (i, screen, st = {}) => {
  const segs = {
    profiles: i.helpProfiles,
    devices: i.helpDevices,
    secrets: i.helpSecrets,
    pairing: i.helpPairing,
    pairmode: i.helpPairMode,
    me: i.helpMe,
    caps: i.helpCaps,
    devvars: i.helpDevVars
  }[screen] || []
  if (typeof segs !== 'function') return segs
  return segs({
    pending: !!st.pending,
    hasDevices: (st.devices?.issued || []).length > 0,
    hasSecrets: Object.keys(st.secrets?.ns || {}).length > 0,
    hasVars: devVarsOf(st, st.varsFor?.pub).length > 0
  })
}

const title = (i, screen) => ({
  profiles: i.titleProfiles,
  pairing: i.titlePairing,
  pairmode: i.titlePairMode,
  caps: i.titleCaps,
  devvars: i.titleDevVars
})[screen] || ''

/** Barra de pestañas horizontal (Dispositivos | Scopes y variables) de la bóveda entrada. */
function renderTabs (st, t) {
  const i = L(st)
  return INNER_TABS.map((k) => {
    const active = st.screen === k
    return active ? t.bold(t.accent('▐ ' + tabLabel(i, k) + ' ▌')) : t.muted('  ' + tabLabel(i, k) + '  ')
  }).join('   ') + t.muted(i.tabsHint)
}

function pairingBody (st, t, cols, height) {
  const i = L(st)
  const info = st.pairing
  const lines = []
  // QUÉ CUENTA se está compartiendo: el vault puede tener varias y el QR sale de
  // UNA (la bóveda en la que entraste). Decirlo aquí evita enrolar un dispositivo
  // en la cuenta equivocada sin enterarse.
  const ap = activeProfile(st)
  const acct = info.profileName || ap?.name || info.profile || ap?.id || '—'
  const left = Math.max(0, Math.round((info.expiresAt - Date.now()) / 60000))
  lines.push(t.bold(i.pairAccount(acct, left)))
  // QR: se dibuja siempre que quepa de ancho; si es más alto que la pantalla se
  // puede hacer scroll hacia arriba/abajo para verlo completo.
  let qr = ''
  try { qr = qrToString(info.url) } catch (_) {}
  const qrLines = qr ? qr.replace(/\n$/, '').split('\n') : []
  const qrWidth = qrLines.length ? Math.max(...qrLines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').length)) : 0
  if (qrLines.length && qrWidth <= cols) {
    for (const l of qrLines) lines.push(l)
    lines.push('')
  } else if (qrLines.length) {
    lines.push(t.warn(i.pairQrTooNarrow(cols, qrWidth)))
    lines.push('')
  }
  lines.push(t.muted(i.pairScan))
  lines.push(t.bold(i.pairUrl) + info.url)
  lines.push('')
  lines.push(t.muted(i.pairPaste))
  lines.push(info.b64 || info.payload)
  lines.push('')
  lines.push(t.danger(i.pairWarning))
  lines.push('')
  if (st.pending) lines.push(t.warn(i.pairConnected(st.pending.deviceId)))
  else lines.push(t.muted(i.pairWaiting))
  return lines
}

function render (term, st) {
  const t = term.t
  const i = L(st)
  const { cols, rows } = term.size()
  // La distribución necesita: header+contexto (5) + 1 de contenido + estado + ayuda.
  // En un terminal más chico, en vez de escribir en índices fuera de rango, avisamos.
  if (rows < 9 || cols < 24) {
    term.render([t.warn(i.tooSmall), i.tooSmallHint(cols, rows)])
    return
  }
  const lines = new Array(rows).fill('')

  const s = st.state
  const up = st.daemonUp
  const ver = s?.version || 'dev'
  const daemonTxt = up ? i.daemonRunning : i.daemonStopped
  lines[0] = t.bar(`dotrino-vault ${ver}   daemon: ${daemonTxt}   ${vc.vaultDir()}`, cols)

  const ap = activeProfile(st)
  const apTxt = ap ? `${t.accent('●')} ${t.bold(ap.name || i.noName)} ${lockGlyph(ap)} ${t.muted('· ' + (ap.fingerprint || '—'))}` : t.muted('—')
  lines[1] = ' ' + i.activeVault + apTxt
  lines[2] = ''
  // Dispositivos/Scopes son pestañas de la bóveda activa (se entra desde Bóvedas);
  // el resto muestra su título simple.
  lines[3] = INNER_TABS.includes(st.screen) ? ' ' + renderTabs(st, t) : ' ' + t.title('» ' + title(i, st.screen))
  lines[4] = ''

  const top = 5
  const bottom = 2 // status + help
  const contentH = Math.max(1, rows - top - bottom)
  const scrollRef = st.scroll[st.screen] || (st.scroll[st.screen] = { value: 0 })

  let body = []
  if (st.screen === 'profiles') body = renderList(profileRows(st, t), st.sel.profiles, contentH, cols, t, scrollRef)
  else if (st.screen === 'devices') body = renderList(deviceRows(st, t), st.sel.devices, contentH, cols, t, scrollRef)
  else if (st.screen === 'secrets') body = renderList(secretRows(st, t), st.sel.secrets, contentH, cols, t, scrollRef)
  else if (st.screen === 'me') body = renderList(meRows(st, t), -1, contentH, cols, t, scrollRef)
  else if (st.screen === 'caps') body = renderList(capsRows(st, t), st.sel.caps || 0, contentH, cols, t, scrollRef)
  else if (st.screen === 'devvars') body = renderList(devVarRows(st, t), st.sel.devvars || 0, contentH, cols, t, scrollRef)
  else if (st.screen === 'pairmode') body = renderList(pairModeRows(st, t), st.sel.pairmode, contentH, cols, t, scrollRef)
  else if (st.screen === 'pairing') {
    const pb = pairingBody(st, t, cols, contentH)
    body = scrollBody(pb, contentH, scrollRef)
  }
  for (let n = 0; n < contentH; n++) lines[top + n] = body[n] ?? ''

  // línea de estado: input / confirm / flash / busy
  const statusRow = rows - 2
  if (st.busy) lines[statusRow] = ' ' + t.accent('⏳ ' + st.busy)
  else if (st.input) {
    const inp = st.input
    const shown = inp.mask ? '•'.repeat(inp.value.length) : inp.value
    const hint = inp.hint ? t.muted('  [' + inp.hint + ']') : ''
    lines[statusRow] = ' ' + t.bold(inp.label + ': ') + shown + t.accent('▏') + hint
  } else if (st.confirm) {
    lines[statusRow] = ' ' + t.warn(st.confirm.text) + t.muted(i.confirmKeys)
  } else if (st.flash) {
    const kind = st.flash.kind
    const style = kind === 'danger' ? t.danger : kind === 'warn' ? t.warn : t.ok
    lines[statusRow] = ' ' + style((kind === 'danger' ? '✗ ' : kind === 'warn' ? '! ' : '✓ ') + st.flash.text)
  } else lines[statusRow] = ''

  // barra de ayuda
  let help = fitHelp(helpSegs(i, st.screen, st), cols)
  if (st.input) help = i.helpInput
  else if (st.confirm) help = i.helpConfirm
  lines[rows - 1] = t.bar(help, cols)

  term.render(lines)
}

// --------------------------- pantalla daemon caído -------------------------

async function daemonDownScreen (term, st) {
  while (true) {
    const t = term.t
    const i = L(st)
    const { cols, rows } = term.size()
    const lines = new Array(Math.max(rows, 2)).fill('')
    // Contenido en orden; se coloca desde la fila 2 y se corta si no cabe (no se
    // escribe nunca en índices fijos que se salgan de un terminal pequeño).
    const content = [
      t.danger(i.downTitle),
      '',
      i.downBody1,
      i.downBody2,
      '',
      t.bold('S') + i.downStart + t.muted('systemctl --user start dotrino-vault'),
      t.bold('R') + i.downRecheck,
      t.bold('l') + i.downLang,
      t.bold('Q') + i.downQuit,
      '',
      t.muted(i.downDev)
    ]
    if (st.flash) content.push('', (st.flash.kind === 'danger' ? t.danger : t.warn)(st.flash.text))
    lines[0] = t.bar(i.downHeader, cols)
    for (let n = 0; n < content.length && 2 + n < rows - 1; n++) lines[2 + n] = ' ' + content[n]
    lines[rows - 1] = t.bar(fitHelp(i.downHelp, cols), cols)
    term.render(lines)

    const key = await term.readKey()
    const ch = key.name === 'char' ? key.ch.toLowerCase() : null
    if (ch === 'q' || key.name === 'ctrl-c') return false
    if (ch === 'l') { toggleLang(st); continue }
    if (ch === 'r') { if (vc.daemonAlive()) return true; flash(st, L(st).stillDown, 'warn') }
    if (ch === 's') {
      st.busy = L(st).starting // (no re-render aquí; mensaje simple)
      flash(st, L(st).startingShort, 'warn'); term.render(lines)
      const r = await startDaemonService()
      await sleep(1500)
      if (vc.daemonAlive()) return true
      flash(st, r.ok ? L(st).startedNotReady : L(st).startFailed(r.err), 'danger')
      st.busy = null
    }
  }
}

// ---------------------------------- loop -----------------------------------

export async function runTui () {
  const term = createTerm()
  const st = {
    screen: 'profiles', // se arranca en la lista de bóvedas: hay que ENTRAR a una
    lang: loadLang(), // es/en — se conmuta con `l` y se recuerda en prefs.json
    sel: { profiles: 0, devices: 0, secrets: 0, pairmode: 0, devvars: 0 },
    // Las bóvedas que ha abierto ESTA sesión, para volver a cerrarlas al salir.
    unlockedHere: new Set(),
    scroll: {},
    profiles: null,
    devices: null,
    secrets: null,
    pending: null,
    pairing: null,
    state: null,
    daemonUp: false,
    busy: null,
    flash: null,
    input: null,
    confirm: null
  }

  try {
    // Arranque: exige daemon vivo.
    if (!vc.daemonAlive()) {
      const cont = await daemonDownScreen(term, st)
      if (!cont) { term.close(); return }
      st.flash = null
    }
    st.state = vc.readState()
    st.daemonUp = true
    await refreshAll(term, st)

    let running = true
    while (running) {
      st.state = vc.readState()
      st.daemonUp = vc.daemonAlive()
      // caducar el flash a los ~4 s
      if (st.flash && Date.now() - st.flash.at > 4000) st.flash = null
      render(term, st)

      const tick = (st.screen === 'pairing' || (st.screen === 'devices' && !st.input && !st.confirm)) ? 800 : 0
      const key = await term.readKey(tick)

      if (key.name === 'resize') continue
      // input/confirm se AWAITan: serializa las ops contra el daemon (ver onInputKey).
      // Ctrl-C dentro de un modal lo CANCELA (no sale); fuera de un modal, sale.
      if (st.input) { await onInputKey(st, key); continue }
      if (st.confirm) { await onConfirmKey(st, key); continue }
      if (key.name === 'ctrl-c') { running = false; continue }

      const ch = key.name === 'char' ? key.ch.toLowerCase() : null
      // 'q' global sale.
      if (ch === 'q') { running = false; continue }
      // 'l' global: idioma es⇄en en cualquier pantalla (por eso el candado es 'c').
      if (ch === 'l') { toggleLang(st); continue }
      // ←→ cambia entre las pestañas de la bóveda entrada (Dispositivos/Scopes).
      if ((key.name === 'left' || key.name === 'right') && INNER_TABS.includes(st.screen)) {
        const n = INNER_TABS.indexOf(st.screen)
        st.screen = INNER_TABS[(n + (key.name === 'right' ? 1 : -1) + INNER_TABS.length) % INNER_TABS.length]
        // El perfil se pide al ENTRAR en su pestaña, no al arrancar: es contenido del
        // usuario y no hay por qué sacarlo del cifrado si nadie lo está mirando.
        if (st.screen === 'me' && st.me === undefined) await refreshMe(term, st)
        continue
      }
      // Esc/'b' desde una pestaña vuelve a la lista de bóvedas (salir de la bóveda
      // entrada). La pantalla de emparejamiento maneja su propio Esc (va a Dispositivos).
      if ((key.name === 'escape' || ch === 'b') && INNER_TABS.includes(st.screen)) {
        st.screen = 'profiles'; continue
      }

      if (st.screen === 'profiles') running = await onKeyProfiles(term, st, key)
      else if (st.screen === 'devices') running = await onKeyDevices(term, st, key)
      else if (st.screen === 'secrets') running = await onKeySecrets(term, st, key)
      else if (st.screen === 'me') running = await onKeyMe(term, st, key)
      else if (st.screen === 'caps') running = await onKeyCaps(term, st, key)
      else if (st.screen === 'devvars') running = await onKeyDevVars(term, st, key)
      else if (st.screen === 'pairmode') running = await onKeyPairMode(term, st, key)
      else if (st.screen === 'pairing') running = await onKeyPairing(term, st, key)
    }
  } finally {
    // AL SALIR SE VUELVE A CERRAR lo que se abrió aquí. Sin esto, teclear la contraseña una
    // vez dejaba la bóveda abierta para todo el que pasara por esta máquina hasta el
    // siguiente reinicio del servicio — un candado que solo se cierra reiniciando no es un
    // candado. (Si la TUI muere de un tirón —kill, ventana cerrada— no hay quien lo haga:
    // ahí el cierre lo pone el reinicio, como antes.)
    for (const id of st.unlockedHere) { try { await vc.lockProfile(id) } catch (_) {} }
    term.close()
  }
}

// Solo para pruebas headless (render sin terminal real). No usar en runtime.
export const __test = { render, activeLocked, refreshAll, profileRows, deviceRows, secretRows, devVarRows, meRows, capsRows, pairModeRows, pairingBody, scrollBody, fitHelp, toggleLang, mergeMembersAndCerts }
