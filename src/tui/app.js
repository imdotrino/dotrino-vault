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
import fs from 'node:fs'
import { execFile } from 'node:child_process'
import { parseEnvInput } from '../../lib/src/envtext.js'
import { createTerm, widthOf } from './term.js'
import { qrToString } from '../qr.js'
import { dict, otherLang, loadLang, saveLang } from './i18n.js'
import * as vc from '../vaultControl.js'
import { VERSION } from '../version.js'
import { DEVICE_CAPS } from '@dotrino/identity/acta'

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
  // Con dato: «contraseña incorrecta (van 9 intentos)» y «espera 32 s» son lo que hace
  // falta para saber qué está pasando; «error» a secas parece que la pantalla se colgó.
  if (e?.code === 'WRONG_PASSWORD') return t.errWrongPassword(e.tries)
  if (e?.code === 'TOO_MANY_TRIES') return t.errTooManyTries(e.waitSec)
  const byCode = {
    DAEMON_DOWN: t.errDaemonDown,
    NO_REPLY: t.errNoReply,
    NOT_APPLIED: t.errNotApplied,
    NOT_DELETED: t.errNotDeleted,
    PAIR_FAILED: t.errPairFailed,
    APPROVE_FAILED: t.errWrongCode,
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
      // CUÁNDO ENTRÓ. Venía en el acta y se perdía aquí, así que la lista no podía
      // enseñarlo por mucho que se quisiera. El nombre lo pone el propio aparato y muchas
      // veces no distingue nada: la fecha es lo que deja reconocer cuál es cuál.
      addedAt: m.addedAt || null,
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
/**
 * La contraseña del perfil ACTIVO, que la TUI ya guarda para toda la sesión al
 * desbloquear (ver `reunlockSilently`). Las operaciones que SELLAN una variable la
 * necesitan: sin ella el daemon cae a la llave de la máquina, que no abre la copia
 * maestra de un perfil con contraseña, y la escritura falla con «wrong password».
 */
const activePwd = (st) => st.sessionPwd?.get(activeId(st)) || undefined

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
    const debt = debtOf(st, d.sub)
    const desde = d.addedAt ? t.muted(`  ${i.deviceSince}:${fmtExp(d.addedAt)}`) : ''
    const extra = (d.certCount > 1 ? t.muted(`  certs:${d.certCount}`) : '') +
      (vars ? t.muted(`  vars:${vars}`) : '') +
      // EN DEUDA: en el acta y sin poder abrir lo suyo. Va en color de aviso al lado de
      // sus variables, que es donde se mira cuando algo no arranca.
      (debt ? t.warn(`  ${i.deviceDebt(debt)}`) : '')
    // SIN ACCESO: está en el acta y no puede entrar. Es un aviso, no un adorno, así que va
    // en el color de aviso y en el sitio donde estaría su vencimiento.
    const status = d.noAccess
      ? t.warn(i.deviceNoAccess)
      : d.isMaster
        ? t.muted(i.thisVault)
        : t.muted('scope:' + shortScope(d.scope)) + '  ' + t.muted('exp:' + fmtExp(d.exp))
    rows.push({ text: ` ${t.bold(d.deviceId)}  ${label}${desde}  ${status}${extra}`, sel: true, meta: d })
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
 * cuál entra el dispositivo. Se responde con las tres formas que existen —una
 * cuenta que ya vive aquí, una nueva que se estrena para él, o un SERVICIO de la
 * cuenta activa—; la cuarta («adoptar la que trae el aparato») necesita el
 * protocolo de adopción y se muestra desactivada para no prometer lo que todavía
 * no hace (docs/vinculacion-de-cuentas.md §5).
 *
 * Lo del servicio estaba SOLO en la línea de comandos (`pair --service <ns>`), y una
 * máquina que sirve el proxy no se empareja de otra manera: sin esta opción, la TUI
 * te dejaba a medio camino y había que salirse a la terminal a terminar el trabajo.
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
  rows.push({ text: ` ${t.bold(i.pairModeService)}`, sel: true, meta: { mode: 'service' } })
  rows.push({ text: t.muted('     ' + i.pairModeServiceHint), sel: false })
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
/**
 * TODOS los permisos que el acta reconoce para un aparato, en el orden en que se leen: de
 * lo cotidiano a lo que cambia quién manda.
 *
 * `approve` y `sealer` faltaban, y solo se podían conceder por la CLI. Un permiso que
 * existe y no se ve en la pantalla que se llama «permisos» hace creer que no existe — y
 * `sealer` es justo el que hay que entender para el multivault. Se ven siempre, aunque en
 * un teléfono normal `sealer` no lo vaya a usar nadie: verlo apagado explica el modelo
 * (dueño, 2026-08-31).
 *
 * `unattended` entró por lo mismo (dueño, 2026-09-01): era una marca local de la bóveda
 * —invisible aquí y solo tocable por la CLI— y encima con el sentido invertido. Es EL
 * permiso que hay que entender para un servidor: dice si esa máquina se lleva tus claves
 * privadas sola o si te lo pregunta. Verlo apagado es la mitad del mensaje.
 */
/**
 * EL ORDEN LO ELIGE ESTA PANTALLA; LA LISTA LA MANDA EL ACTA.
 *
 * Antes esto era una lista suelta escrita a mano, y por eso cada permiso nuevo se quedó
 * invisible aquí durante semanas —`sealer`, `unattended` y `secrets`, tres veces el mismo
 * fallo—. Ahora el orden se cura a mano, que es una decisión de diseño, pero lo que no
 * esté nombrado se añade al final: un permiso puede salir en mal sitio, nunca desaparecer.
 * `test/tui-permisos.test.mjs` exige además que todos tengan nombre en los dos idiomas.
 */
const ORDEN = ['sign', 'store', 'read', 'admin', 'approve', 'passwords', 'sealer', 'unattended', 'replica']
const CAPS_ORDER = [...ORDEN.filter((c) => DEVICE_CAPS.includes(c)),
  ...DEVICE_CAPS.filter((c) => !ORDEN.includes(c))]

/**
 * Los permisos que se le pueden dar A ESTE miembro, en orden.
 *
 * `secrets` solo existe para un SERVICIO (los que tienen `cn`), y por eso faltaba: la
 * lista era fija y no cabía algo que depende de quién sea. Pero para un servicio es EL
 * permiso —el que decide si abre su cajón— y no verlo aquí hacía creer que no existe,
 * igual que pasaba con `unattended`. Se enseña primero, que es su importancia real.
 *
 * A un aparato SIN `cn` no se le ofrece: no hay cajón que abrir, el acta lo filtra
 * (`allowedCaps`) y enseñar una casilla que no hace nada es peor que no enseñarla.
 */
const capsForMember = (member) => (member?.cn ? ['secrets', ...CAPS_ORDER] : CAPS_ORDER)

function capsRows (st, t) {
  const i = L(st)
  const target = st.capsFor
  if (!target) return [{ text: t.muted(i.loading), sel: false }]
  const member = (st.members || []).find((m) => m.pub === target.pub)
  if (!member) return [{ text: t.muted(i.capsNoMember), sel: false }]

  // EL BORRADOR manda sobre lo que hay en el acta: es lo que estás a punto de dejar.
  const real = new Set(member.caps || [])
  const has = st.capsDraft?.pub === member.pub ? new Set(st.capsDraft.caps) : real

  const rows = [
    { text: ' ' + t.bold(i.capsFor(target.deviceId, member.label || '')), sel: false },
    { text: '', sel: false }
  ]
  let tocados = 0
  for (const cap of capsForMember(member)) {
    const mark = has.has(cap) ? '[x]' : '[ ]'
    // El nombre de `secrets` lleva el cajón dentro: «las claves de proxy» dice qué abre,
    // «lee sus claves» te deja preguntándote cuáles.
    const name = typeof i.capName[cap] === 'function' ? i.capName[cap](member.cn) : i.capName[cap]
    // LO QUE CAMBIA SE SEÑALA. Sin esto el borrador es indistinguible del acta y no sabes
    // qué vas a firmar — que es justo lo que hace peligroso acumular cambios.
    const cambia = has.has(cap) !== real.has(cap)
    if (cambia) tocados++
    // El título ES el nombre del permiso —el mismo que se teclea en `caps <ID> +administra`—
    // así que no hay que repetirlo al lado. Lo que hace va debajo.
    const line = ` ${mark}${cambia ? t.bold('*') : ' '} ${cap === 'admin' ? t.bold(name) : name}`
    rows.push({ text: line, sel: true, meta: { cap } })
    const hint = typeof i.capHint[cap] === 'function' ? i.capHint[cap](member.cn) : i.capHint[cap]
    rows.push({ text: t.muted('      ' + hint), sel: false })
  }
  rows.push({ text: '', sel: false })
  rows.push({
    text: tocados ? ' ' + t.bold(i.capsPending(tocados)) : t.muted(' ' + i.capsApplyHint),
    sel: false
  })
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
  // ARRIBA DEL TODO, antes que las variables: lo que está sin sellar significa que esos
  // aparatos NO están leyendo su configuración ahora mismo, y que solo la contraseña lo
  // arregla. Un aviso que hay que buscar no es un aviso.
  const head = []
  for (const [owner, info] of Object.entries(st.secrets?.pending || {})) {
    const who = (info?.members || []).map((m) => deviceIdOf(st, m.pub) + ' (' + m.keys.join(', ') + ')').join(', ')
    head.push({ text: t.warn(' ' + i.pendingSeal(owner, info?.kind, who)), sel: false })
  }
  const p = activeProfile(st)
  if (p && !p.protected) head.push({ text: t.warn(' ' + i.noPasswordWarn), sel: false })
  if (head.length) head.push({ text: '', sel: false })
  if (!names.length) return [...head, { text: t.muted(i.noScopes), sel: false }, ...footer]
  rows.push(...head)
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

/**
 * Lo que ese aparato NO puede abrir (§8.11). Un servicio que entra después de escrita
 * una variable no tiene envoltura de ella, y hasta que alguien se la reparta está en el
 * acta sin poder arrancar del todo. Aquí se cuenta cuántas, que es lo que cabe en una
 * fila; el detalle está en la consola.
 */
/** El ID corto de un aparato a partir de su llave, tal como lo enseña la lista de Aparatos. */
const deviceIdOf = (st, pub) =>
  (st.devices?.issued || []).find((d) => d.sub === pub)?.deviceId || (st.members || []).find((m) => m.pub === pub)?.id || pub.slice(0, 8)

const debtOf = (st, pub) => {
  const d = (st.secrets?.incomplete || []).find((x) => x.pub === pub)
  return d ? [...new Set(Object.values(d.owners || {}).flat())].length : 0
}

const sortByKey = (list) => (list || []).slice().sort((a, b) => a.key.localeCompare(b.key))

/**
 * Una variable: su nombre y su valor. La PÚBLICA enseña el suyo —pública significa que ese
 * valor puede salir de esta máquina, así que taparlo delante de su dueño, en la máquina
 * donde vive, era lo único que la marca no quería decir— con el aviso de que viaja cuando
 * la consola remota lo pide. La privada sigue tapada: no sale ni a esta pantalla.
 */
const varLine = (v, t, i) => `      ${v.key}   ` +
  (v.public ? `${short(v.value)}   ${t.warn(i.varPublic)}` : t.muted('••••••'))

/** Un valor largo no puede empujar la marca «pública» fuera de la pantalla. */
const short = (s) => {
  const v = String(s ?? '')
  return v.length > 40 ? v.slice(0, 39) + '…' : v
}

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
  const field = (label, value, hidden) => rows.push({
    text: `  ${t.muted(String(label).padEnd(12))} ${value}${hidden ? t.muted(i.hidden) : ''}`, sel: false
  })
  rows.push({ text: t.muted(i.profileUpdated(me.updatedAt ? new Date(me.updatedAt).toLocaleString() : '—')), sel: false })
  rows.push({ text: '', sel: false })
  field(i.fieldName, me.nickname ? t.bold(me.nickname) : t.muted(i.noName))
  field(i.fieldPhoto, me.avatar
    ? `${me.avatar.type || '?'} · ${(me.avatar.bytes / 1024).toFixed(1)} KB`
    : t.muted(i.no))

  const STD = [['nombres', i.fieldFirstName], ['apellidos', i.fieldLastName], ['email', i.fieldEmail],
    ['telefono', i.fieldPhone], ['direccion', i.fieldAddress]]
  const filled = STD.filter(([k]) => me[k])
  if (filled.length) rows.push({ text: '', sel: false })
  for (const [k, label] of filled) field(label, me[k], me[k + 'Visible'] === false)

  for (const [title, list] of [[i.links, me.links], [i.otherData, me.fields]]) {
    if (!Array.isArray(list) || !list.length) continue
    rows.push({ text: '', sel: false })
    rows.push({ text: t.accent(' ▸ ' + title), sel: false })
    for (const x of list) field(x.type || x.label || '', x.value, x.visible === false)
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

/** Los minutos que el daemon aguanta abierto (viene en `state.json`; 5 por defecto). */
const autoLockMin = (st) => Math.max(1, Math.round((st.state?.autoLockMs || 5 * 60 * 1000) / 60000))

/**
 * ¿Alguna de las bóvedas que abrió ESTA sesión se cerró sola?
 *
 * El plazo lo lleva el daemon (`profiles.js`), no la TUI: aquí solo se MIRA su foto
 * (`state.json`, que se reescribe cada dos segundos). Así hay un único reloj y no dos
 * que se desincronizan — y lo que decida el daemon es lo que manda, porque es quien
 * atiende.
 */
const autoLockedIds = (st) => (st.state?.profiles || [])
  .filter((p) => p.protected && p.locked && (st.sessionPwd?.has(p.id) || st.unlockedHere?.has(p.id)))
  .map((p) => p.id)

/**
 * Cuándo hay que despertar para enterarse. Sin esto la TUI se queda dormida en
 * `readKey()` hasta la siguiente tecla y seguiría enseñando los aparatos y los nombres
 * de las variables de una bóveda que el daemon ya cerró. Se suman ~2 s porque la foto
 * se reescribe cada dos: despertar en el instante justo leería la anterior.
 */
function autoLockWakeIn (st, now = Date.now()) {
  let at = 0
  for (const p of st.state?.profiles || []) {
    if (!p.until || !(st.sessionPwd?.has(p.id) || st.unlockedHere?.has(p.id))) continue
    at = at ? Math.min(at, p.until) : p.until
  }
  if (!at) return 0
  const left = at - now + 2200
  // El plazo ya pasó y la foto sigue diciendo que está abierta: el daemon no la está
  // reescribiendo (caído o colgado). Se insiste un rato y luego se deja de despertar, o
  // la TUI se quedaría dando vueltas contra una foto que no va a cambiar.
  if (left <= 0) return now - at > 15000 ? 0 : 1000
  return Math.max(250, left)
}

/**
 * BLOQUEO AUTOMÁTICO. Se cerró sola: se OLVIDA su contraseña y se sale de lo que se
 * estaba mirando (dentro se ven los aparatos, las variables y tus datos, que es justo
 * lo que el candado tapa).
 *
 * Olvidarla es la mitad que importa: sin esto la TUI la seguiría teniendo y la
 * reabriría sola en cuanto alguien pulsara Enter (ver `reunlockSilently`), así que el
 * candado del daemon no habría cerrado nada.
 */
/** Cada cuánto se le dice al daemon «sigo aquí». Muy por debajo del plazo del candado. */
const TOUCH_MS = 60_000
let ultimoToque = 0

/**
 * Le dice al daemon que sigues delante, sin pedirle nada. Se llama al teclear.
 *
 * No se espera (`await`): estirar el candado no puede meterse en medio de lo que estabas
 * haciendo, y si se pierde un aviso, el siguiente llega un minuto después — con cinco de
 * plazo, no pasa nada.
 */
function seguirAqui (st, api = vc) {
  const ahora = Date.now()
  if (ahora - ultimoToque < TOUCH_MS) return
  const p = (st.state?.profiles || []).find((x) => x.current)
  // Solo tiene sentido en un perfil con contraseña y abierto: sin candado no hay plazo
  // que estirar, y cerrado no hay nada que mantener abierto.
  if (!p?.protected || p.locked) return
  ultimoToque = ahora
  try { Promise.resolve(api.touchProfile(p.id)).catch(() => {}) } catch (_) {}
}

async function forgetAutoLocked (term, st, api = vc) {
  const ids = autoLockedIds(st)
  if (!ids.length) return false
  for (const id of ids) { st.sessionPwd?.delete(id); st.unlockedHere?.delete(id) }
  const cur = (st.state?.profiles || []).find((p) => p.current)
  if (ids.includes(cur?.id) && st.screen !== 'profiles') {
    // Un modal abierto (una pregunta a medias) también se cierra: quien lo dejó abierto
    // ya no está delante.
    st.input = null
    st.confirm = null
    st.screen = 'profiles'
  }
  // Suelta lo cargado y repinta la lista con el candado ya echado (`refreshAll` no pide
  // el contenido de una bóveda cerrada).
  await refreshAll(term, st, api)
  // El aviso va DESPUÉS del refresco: si no, un tropiezo al refrescar lo pisaría con su
  // error rojo y el candado se cerraría en silencio.
  flash(st, L(st).autoLocked(autoLockMin(st)), 'warn')
  return true
}

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
  const { devices, secrets, profiles, record } = r.v
  if (profiles) st.profiles = profiles
  // Los DOS cajones de variables viajan juntos: `ns` (por scope) y `dev` (por aparato).
  if (secrets) st.secrets = { ns: secrets.ns || {}, dev: Array.isArray(secrets.dev) ? secrets.dev : [] }
  // El ACTA entra en el volcado normal: es de donde sale la lista de dispositivos (ver
  // `mergeMembersAndCerts`). Antes solo se pedía al abrir la pantalla de permisos.
  if (record) st.members = record.members || []
  if (devices) {
    const issued = (devices.issued || devices.active || devices.delegations || [])
    st.devices = { issued: await Promise.all(issued.map(async (d) => ({ ...d, deviceId: d.sub ? await api.deviceIdOf(d.sub) : '????-????' }))), revoked: devices.revoked || [] }
  }
}

/**
 * Guarda un volcado de dispositivos EN LOS DOS SITIOS.
 *
 * La lista se pinta desde el ACTA (`st.members`) con los certificados pegados
 * (`st.devices`), así que quedarse solo con la mitad deja la pantalla mintiendo: aprobar
 * un aparato no lo hacía aparecer y quitarlo no lo hacía desaparecer, hasta que algo
 * volviera a pedir el acta. Peor todavía en una lista: el aparato recién entrado no salía,
 * así que la fila «la última» era otra y quitarla se llevaba por delante a quien no era.
 */
function applyDump (st, v) {
  st.devices = v
  if (Array.isArray(v?.members)) st.members = v.members
}

async function refreshDevices (term, st) {
  const r = await guard(term, st, L(st).loadingDevices, () => vc.listDevices(activeId(st)))
  if (r.ok) applyDump(st, r.v)
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
async function refreshProfiles (term, st, api = vc) {
  const r = await guard(term, st, L(st).loadingVaults, () => api.listProfiles())
  if (r.ok) st.profiles = r.v
}

/**
 * TECLEADA UNA VEZ, VALE PARA TODA LA SESIÓN de la TUI.
 *
 * El candado vive en la MEMORIA DEL DAEMON, así que cualquier cosa que se lleve ese
 * estado —un `systemctl restart` al actualizar, un reinicio del servicio, una petición
 * que se perdió— dejaba la bóveda cerrada otra vez EN MITAD de la sesión, y la TUI
 * volvía a pedir la contraseña como si nunca se hubiera tecleado.
 *
 * Por eso la contraseña de lo que se abre aquí se guarda en `st.sessionPwd` (SOLO en
 * memoria de este proceso) y se vuelve a usar en silencio para reabrir la misma bóveda.
 * Se olvida con el candado (`k`), al quitar la contraseña y al salir de la TUI, que es
 * exactamente donde el dueño dijo que tiene que volver a hacer falta.
 */
// `api` es `vaultControl` — se recibe para poder probar esto sin un daemon detrás.
async function reunlockSilently (term, st, p, api = vc) {
  const pwd = st.sessionPwd?.get(p.id)
  if (!pwd) return false
  const r = await guard(term, st, L(st).unlocking, () => api.unlockProfile(p.id, pwd))
  // Ya no vale (se la cambiaron desde otro sitio, o el freno está esperando): se olvida
  // y se vuelve al camino normal, que es preguntar diciendo por qué.
  if (!r.ok) { st.sessionPwd.delete(p.id); return false }
  await refreshProfiles(term, st, api)
  return true
}

/**
 * Pide la contraseña si hace falta y sigue. Lo que se abre aquí queda anotado en
 * `st.unlockedHere` para volver a cerrarlo AL SALIR (ver `runTui`): la contraseña dura lo
 * que dura la sesión, no hasta que alguien reinicie el servicio. Lo que ya estaba abierto
 * antes de entrar no se toca — no lo abrió esta pantalla, no le toca cerrarlo.
 */
async function ensureUnlocked (term, st, p, thenFn, reason = null, api = vc) {
  if (!p.protected || !p.locked) return thenFn()
  // Cerrada, pero la contraseña ya se tecleó en esta sesión: se reabre sin molestar.
  if (await reunlockSilently(term, st, p, api)) {
    const fresh = (st.profiles?.profiles || []).find((x) => x.id === p.id) || p
    return thenFn(fresh)
  }
  const i = L(st)
  setInput(st, {
    label: i.passwordOf(p.name || p.id),
    mask: true,
    // Si la anterior fue rechazada, el motivo se queda AQUÍ, pegado al campo, en vez de
    // irse en un aviso de cuatro segundos que se lleva el siguiente redibujado. Eso era lo
    // que hacía que un rechazo pareciera «me la vuelve a pedir porque sí».
    hint: reason || i.passwordToEdit,
    onSubmit: async (pwd) => {
      st.input = null
      const r = await guard(term, st, i.unlocking, () => api.unlockProfile(p.id, pwd))
      // Rechazada: se vuelve a pedir en el acto, diciendo por qué. Cerrar el campo obligaba
      // a adivinar qué había pasado y a empezar de nuevo.
      if (!r.ok) return ensureUnlocked(term, st, p, thenFn, humanErr(r.e, st), api)
      st.unlockedHere?.add(p.id)
      st.sessionPwd?.set(p.id, pwd) // vale para toda la sesión (ver reunlockSilently)
      await refreshProfiles(term, st, api)
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
      }
      // ENTRAR RECARGA TODO, SIEMPRE. Antes solo se recargaba al CAMBIAR de bóveda, y lo
      // que traía era `refreshDevices`: aparatos y acta, no las variables. Así que entrar a
      // la bóveda que ya estaba activa —el caso normal cuando estaba cerrada y acabas de
      // teclear la contraseña, que es cuando la memoria está vacía a propósito— dejaba
      // Scopes en blanco hasta que alguien pulsara F5. Un volcado trae las tres cosas.
      await refreshAll(term, st)
      st.screen = 'devices'
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
            const r = await guard(term, st, i.savingPassword, () => vc.setProfilePassword(p.id, pwd, st.sessionPwd?.get(p.id)))
            // La nueva es la que vale para el resto de la sesión: guardar la vieja dejaría
            // a la TUI reabriendo con una contraseña que ya no existe.
            if (r.ok) { st.sessionPwd?.set(p.id, pwd); flash(st, i.passwordSaved); await refreshProfiles(term, st) }
          },
          onCancel: () => { st.input = null }
        })
      },
      onCancel: () => { st.input = null }
    }))
  } else if (ch === 'x' && cur) { // quitar contraseña
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    await ensureUnlocked(term, st, cur, async (p = cur) => {
      const r = await guard(term, st, i.removingPassword, () => vc.removeProfilePassword(p.id, st.sessionPwd?.get(p.id)))
      if (r.ok) { st.sessionPwd?.delete(p.id); flash(st, i.passwordRemoved); await refreshProfiles(term, st) }
    })
  } else if (ch === 'u' && cur) {
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    if (!cur.locked) { flash(st, i.alreadyUnlocked, 'warn'); return true }
    await ensureUnlocked(term, st, cur, async () => { flash(st, i.vaultUnlocked); await refreshProfiles(term, st) })
  } else if (ch === 'k' && cur) { // locK (antes `l`, que ahora es el idioma)
    if (!cur.protected) { flash(st, i.noPasswordSet, 'warn'); return true }
    const r = await guard(term, st, i.lockingVault, () => vc.lockProfile(cur.id))
    // Echar el candado a mano es DECIR que vuelva a hacer falta la contraseña: si la TUI
    // se quedara con ella, la siguiente tecla la reabriría sola y el candado no cerraría
    // nada.
    if (r.ok) { st.sessionPwd?.delete(cur.id); st.unlockedHere?.delete(cur.id); flash(st, i.vaultLocked); await refreshProfiles(term, st) }
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
        if (r.ok) { flash(st, i.deviceRevoked(cur.deviceId)); applyDump(st, r.v); st.sel.devices = 0 }
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
        if (r.ok) { applyDump(st, r.v); flash(st, i.deviceRenamed(name)) }
      }
    })
  } else if (ch === 'c' && cur?.sub) {
    st.capsFor = { pub: cur.sub, deviceId: cur.deviceId }
    // Borrador limpio al entrar: arrastrar el de otro aparato sería firmar lo que no viste.
    st.capsDraft = null
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

/**
 * Tira la cuenta que NACIÓ para un emparejamiento que no llegó a término y vuelve a la que
 * estabas usando. Es una cuenta recién creada y vacía —el aparato nunca entró—, así que no
 * hay nada dentro que perder; lo que sí molesta es que se queden acumulando.
 */
async function descartarCuenta (term, st, id, volverA) {
  const i = L(st)
  const r = await guard(term, st, i.discardingAccount, () => vc.removeProfile(id))
  if (volverA) await guard(term, st, i.switchingVault, () => vc.useProfile(volverA))
  await refreshAll(term, st)
  if (r.ok) flash(st, i.accountDiscarded)
}

/**
 * PRIMERO EL NOMBRE, y luego el QR.
 *
 * Sin preguntarlo, el nombre lo pone el propio aparato al enrolarse, y por defecto usa el
 * apodo del PERFIL: te quedaban tres dispositivos llamados igual que tú y ninguna forma de
 * saber cuál era cuál sin renombrarlos después —cuando ya no te acordabas—. Se pregunta
 * ANTES porque después ya estás mirando un QR con el teléfono en la mano.
 *
 * Enter en blanco sigue valiendo: deja que lo diga el aparato, que es el comportamiento de
 * siempre para quien no quiera decidirlo.
 */
function beginPairingNamed (term, st, profile, service = null, after = null) {
  const i = L(st)
  setInput(st, {
    label: i.nameDeviceLabel,
    hint: i.nameDeviceHint,
    onSubmit: async (nombre) => {
      st.input = null
      const ok = await beginPairing(term, st, profile, service, (nombre || '').trim().slice(0, 60) || null)
      // `after` es para quien tenga que limpiar si el emparejamiento no llega a abrirse
      // (la cuenta que nació para él). Va aquí porque con el nombre de por medio ya no se
      // puede mirar el valor de retorno desde fuera.
      if (after) await after(ok)
    },
    onCancel: () => { st.input = null }
  })
  return true
}

/**
 * Abre el emparejamiento contra `profile` y salta a la pantalla del QR. Con `service`,
 * el QR es el de un SERVICIO de ese namespace (cert limitado a sus variables).
 */
async function beginPairing (term, st, profile, service = null, label = null) {
  const r = await guard(term, st, L(st).startingPairing, () => vc.startPairing({ profile, ...(service ? { service } : {}), ...(label ? { label } : {}) }))
  // `service` se pega al estado porque el daemon no lo devuelve: la pantalla del QR
  // tiene que poder decir qué se está entregando, que no es lo mismo un aparato tuyo
  // que una máquina que solo va a leer la configuración del proxy.
  if (r.ok) { st.pairing = { ...r.v, ...(service ? { service } : {}) }; st.pending = null; st.scroll.pairing = { value: 0 }; st.screen = 'pairing' }
  return r.ok
}

/**
 * UN BORRADOR QUE SE GUARDA O SE DESCARTA (dueño, 2026-09-01).
 *
 * Antes cada Enter sellaba un acta. Cambiar cuatro permisos eran cuatro actas, cuatro
 * avisos a todos los aparatos y cuatro renovaciones de certificado — absurdo, y encima
 * dejaba la cuenta pasando por estados intermedios que nadie quiso (un aparato con
 * `admin` pero todavía sin `read`, por ejemplo).
 *
 * Ahora Enter mueve un borrador LOCAL —nada firmado, nada avisado— y `G` lo aplica de
 * golpe. `applyChanges` ya tomaba una LISTA de cambios y producía UNA acta: el borrador es
 * esa lista, sin firmar, hasta que confirmas.
 *
 * Lo que se cambia va marcado con `*` y contado abajo: un borrador que no se distingue del
 * acta es peor que no tenerlo, porque firmas sin saber qué.
 */
async function onKeyCaps (term, st, key) {
  const i = L(st)
  const rows = capsRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'caps', sels.length)
  const cur = sels[Math.min(st.sel.caps || 0, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  const member = (st.members || []).find((m) => m.pub === st.capsFor?.pub)
  if (!member) {
    if (key.name === 'escape' || ch === 'b') { st.screen = 'devices'; st.capsFor = null }
    return true
  }
  const real = new Set(member.caps || [])
  if (st.capsDraft?.pub !== member.pub) st.capsDraft = { pub: member.pub, caps: [...real] }
  const draft = new Set(st.capsDraft.caps)
  const sucio = [...new Set([...draft, ...real])].some((c) => draft.has(c) !== real.has(c))

  const salir = () => { st.screen = 'devices'; st.capsFor = null; st.capsDraft = null }
  if (key.name === 'escape' || ch === 'b') {
    // SALIR CON CAMBIOS SIN GUARDAR SE PREGUNTA. Tirarlos callando es perder trabajo sin
    // decirlo, y es justo lo que un borrador no debe hacer.
    if (sucio) setConfirm(st, { text: i.capsDiscard, onYes: async () => { salir() } })
    else salir()
    return true
  }
  if (key.name === 'f5') {
    // F5 PREGUNTA IGUAL QUE ESC. Refrescar trae el acta de nuevo y el borrador deja de
    // tener con qué compararse, así que hay que tirarlo — pero tirarlo callando es perder
    // trabajo sin decirlo, que es lo mismo que Esc ya no hace.
    const refrescar = async () => { st.capsDraft = null; await refreshMembers(term, st) }
    if (sucio) setConfirm(st, { text: i.capsDiscard, onYes: refrescar })
    else await refrescar()
    return true
  }

  // GUARDAR: UNA sola acta con todo lo que hayas tocado.
  if (ch === 'g') {
    if (!sucio) { flash(st, i.capsNothing); return true }
    const cuantos = [...new Set([...draft, ...real])].filter((c) => draft.has(c) !== real.has(c)).length
    const guardar = async () => {
      const r = await guard(term, st, i.applyingCaps, () => vc.setDeviceCaps(member.pub, [...draft], activeId(st)))
      if (!r.ok) return
      applyDump(st, r.v)
      st.capsDraft = null
      await refreshMembers(term, st)
      flash(st, i.capsSaved(cuantos))
    }
    // Administrar se PREGUNTA, y se pregunta AL GUARDAR: es cuando pasa a ser verdad.
    if (draft.has('admin') && !real.has('admin')) {
      setConfirm(st, { text: i.confirmAdmin(st.capsFor.deviceId), onYes: guardar })
      return true
    }
    await guardar()
    return true
  }

  if ((key.name !== 'enter' && ch !== ' ') || !cur) return true
  // Enter solo mueve el BORRADOR: no firma, no avisa, no se puede equivocar caro.
  if (draft.has(cur.cap)) draft.delete(cur.cap); else draft.add(cur.cap)
  st.capsDraft = { pub: member.pub, caps: [...draft] }
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

  if (cur.mode === 'here') { return beginPairingNamed(term, st, activeId(st)) }

  // SERVICIO: entra a la cuenta activa, pero con un certificado que solo sirve para
  // pedir las variables de SU namespace. El nombre del ns es el que luego pide el
  // servicio al arrancar, así que se valida aquí con la misma regla que la CLI: un
  // ns con mayúsculas o espacios se enrola igual y falla el día del despliegue.
  if (cur.mode === 'service') {
    setInput(st, {
      label: i.serviceNsLabel,
      hint: i.serviceNsHint,
      onSubmit: async (raw) => {
        st.input = null
        const ns = String(raw || '').trim().toLowerCase()
        if (!/^[a-z0-9-]{1,32}$/.test(ns)) { flash(st, i.serviceNsBad, 'danger'); return }
        await beginPairing(term, st, activeId(st), ns)
      },
      onCancel: () => { st.input = null }
    })
    return true
  }

  // Cuenta nueva: se crea aquí, se ACTIVA (así aprobar/rechazar y las listas miran
  // a la misma que el QR) y recién entonces se abre el emparejamiento contra ella.
  setInput(st, {
    label: i.newAccountLabel,
    hint: i.newAccountHint,
    onSubmit: async (raw) => {
      st.input = null
      const name = raw.trim()
      if (!name) { flash(st, i.nameEmpty, 'danger'); return }
      const previa = activeId(st)
      const r = await guard(term, st, i.creatingVault, () => vc.addProfile(name))
      if (!r.ok) return
      const created = r.v?.id || (r.v?.profiles || []).find((p) => p.name === name)?.id
      if (!created) { flash(st, i.errNoReply, 'danger'); return }
      const u = await guard(term, st, i.switchingVault, () => vc.useProfile(created))
      if (!u.ok) return
      await refreshAll(term, st)
      flash(st, i.accountCreated(name))
      // Si el emparejamiento no llega a abrirse, la cuenta que se creó PARA él se va con
      // él: si no, cada intento fallido dejaba una cuenta vacía —y encima activa— que
      // luego había que ir a borrar a mano adivinando cuál era.
      beginPairingNamed(term, st, created, null, async (ok) => {
        if (!ok) await descartarCuenta(term, st, created, previa)
        else st.pairing.born = { id: created, from: previa }
      })
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
      if (r.ok) {
        flash(st, i.deviceApproved)
        st.pending = null
        // El aparato entró: la cuenta que se creó para esto ya es de alguien, así que deja
        // de estar en la lista de las que se descartan al salir.
        st.pairing = null
        st.screen = 'devices'
        // Sin lista (el volcado se perdió): se pide otra vez. El aparato ya está dentro;
        // lo único que falta es la foto, y esa se vuelve a pedir sin drama.
        if (r.v) applyDump(st, r.v)
        else await refreshDevices(term, st)
      }
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
    const born = st.pairing?.born
    const r = await guard(term, st, i.restartingPairing, () => vc.startPairing({ profile: activeId(st) }))
    if (r.ok) { st.pairing = { ...r.v, ...(born ? { born } : {}) }; st.pending = null; st.scroll.pairing = { value: 0 } }
    return true
  }
  if (key.name === 'escape' || ch === 'b') {
    // Te vas sin que nadie haya entrado, y la cuenta se creó PARA esto: se pregunta antes
    // de dejarla ahí. Es la otra mitad del mismo descuido — con «cuenta nueva» era fácil
    // acabar con tres cuentas vacías y ninguna forma de saber cuál era cuál.
    const born = st.pairing?.born
    if (born) {
      setConfirm(st, {
        text: i.confirmDiscardAccount,
        onYes: async () => { st.confirm = null; st.pairing = null; st.screen = 'devices'; await descartarCuenta(term, st, born.id, born.from) },
        onNo: async () => { st.confirm = null; st.pairing = null; st.screen = 'devices'; await refreshDevices(term, st) }
      })
      return true
    }
    st.screen = 'devices'; st.pairing = null; await refreshDevices(term, st)
  }
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
  } else if (ch === 'i') {
    promptLoadScopeVars(term, st)
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
  } else if (ch === 'v' && cur?.key) {
    await revealValue(term, st, `ns:${cur.ns}`, cur.key, cur.public)
  } else if (ch === 't' && cur?.key) {
    await toggleVisibility(term, st, cur.public, () => vc.setSecretVisibility(cur.ns, cur.key, !cur.public, activeId(st), activePwd(st)))
  } else if (ch === 'r' && cur?.key) {
    await promptRenameVariable(term, st, cur)
  } else if (key.name === 'f5') {
    await refreshSecrets(term, st)
  }
  return true
}

/**
 * RENOMBRAR: el mismo sobre con otro nombre. No pide la frase, porque lo único que hay que
 * rehacer es la firma —el nombre va DENTRO de lo firmado— y de eso se encarga la llave de
 * sellado, que trabaja con la bóveda cerrada.
 *
 * Se avisa de lo que de verdad importa y no se ve: para el servicio que la lee esto es un
 * cambio de configuración, así que se va a reiniciar. Si su código busca el nombre viejo,
 * dejará de encontrarlo — y eso no lo puede saber la bóveda.
 */
function promptRenameVariable (term, st, cur) {
  const i = L(st)
  return new Promise((listo) => {
    setInput(st, {
      label: i.renameLabel(cur.key),
      hint: i.renameHint,
      value: cur.key,
      onSubmit: async (nuevo) => {
        const nv = nuevo.trim()
        st.input = null
        if (!nv || nv === cur.key) { listo(); return }
        if (!KEY_RE.test(nv)) { flash(st, i.keyInvalid, 'danger'); listo(); return }
        const r = await guard(term, st, i.renaming, () => vc.renameSecret(cur.ns, cur.key, nv, activeId(st)))
        if (r.ok) { flash(st, i.renamed(cur.key, nv)); st.secrets = r.v }
        listo()
      },
      onCancel: () => { st.input = null; listo() }
    })
  })
}

/**
 * Hacer pública una variable es dejar que su valor SALGA de esta máquina, así que se
 * pregunta; volverla privada no expone nada y se aplica directo.
 */
/**
 * VER el valor de una variable. Es lo único que la contraseña guarda desde v5, y en la
 * máquina de la bóveda no hay otro camino: la llave de este aparato vive en este mismo
 * disco, así que si abriera sin frase una copia del disco abriría todo.
 *
 * Si el perfil no tiene contraseña se abre con la llave de la máquina y no se pregunta
 * nada — pero se dice, para que no parezca una protección que no está puesta.
 */
async function revealValue (term, st, owner, key, isPublic) {
  const i = L(st)
  const p = activeProfile(st)
  const mostrar = async (pwd) => {
    const r = await guard(term, st, i.revealing, () => vc.revealSecret(owner, key, activeId(st), pwd))
    if (r.ok) flash(st, i.revealed(key, r.v), 'ok')
  }
  if (isPublic) return mostrar(undefined)             // una pública no está cerrada
  if (!p?.protected) { flash(st, i.revealNoPwd, 'warn'); return mostrar(undefined) }
  const guardada = activePwd(st)
  if (guardada) return mostrar(guardada)
  setInput(st, {
    label: i.revealAsk,
    hint: i.revealHint,
    mask: true,
    onSubmit: async (pwd) => {
      st.input = null
      if (!pwd) return
      await mostrar(pwd)
    },
    onCancel: () => { st.input = null }
  })
}

async function toggleVisibility (term, st, wasPublic, apply) {
  const i = L(st)
  const run = async () => {
    const r = await guard(term, st, i.changingVisibility, apply)
    if (r.ok) { flash(st, wasPublic ? i.nowPrivate : i.nowPublic); st.secrets = r.v }
  }
  if (wasPublic) return run()
  // Solo se pregunta al ABRIRLA. Volverla privada es la dirección segura y se hace sin
  // confirmar: pedir permiso para cerrar algo solo entrena a decir que sí.
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
  if (ch === 'i' && target) { promptLoadVars(term, st, { pub: target.pub, where: target.deviceId }); return true }
  if (ch === 't' && cur && target) {
    await toggleVisibility(term, st, cur.public, () => vc.setDeviceSecretVisibility(target.pub, cur.key, !cur.public, activeId(st), activePwd(st)))
  } else if (ch === 'v' && cur?.key) {
    await revealValue(term, st, `dev:${target.pub}`, cur.key, cur.public)
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
 * Al crear una variable se pregunta SI ES PRIVADA. Se pregunta al crearla, y no después,
 * porque es cuando quien la escribe sabe qué es: un puerto se puede enseñar, una llave de
 * producción no.
 *
 * OJO AL SENTIDO. Antes se preguntaba lo contrario («¿que se pueda ver?») y el defecto
 * —Enter o Esc— caía en `onNo`, que era la privada, o sea la segura. Al dar la vuelta a la
 * pregunta, ese mismo defecto pasaría a ser la PÚBLICA sin que nadie lo notara: cada
 * variable nueva se entregaría sin pedir permiso. Por eso el defecto se declara aquí
 * (`defaultYes`) en vez de heredarse del manejador de teclas.
 */
function askVisibility (term, st, done) {
  const i = L(st)
  // SE DEVUELVE LA PROMESA. `onConfirmKey` hace `await f?.()` para SERIALIZAR las
  // operaciones contra el daemon —lo dice el comentario de `onInputKey`—, y soltarla aquí
  // dejaba la escritura corriendo por fuera de esa serialización: se solapaba con el
  // refresco periódico, los dos usan el mismo archivo de respuesta, el refresco lo borraba
  // antes de que la escritura lo leyera y la pantalla se quedaba en «Guardando…» para
  // siempre. El valor SÍ se había guardado, que es lo que lo hacía tan confuso.
  setConfirm(st, {
    text: i.newVarPrivateAsk,
    defaultYes: true,
    onYes: () => { st.confirm = null; return done(false) },   // privada
    onNo: () => { st.confirm = null; return done(true) }      // pública
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

/**
 * CARGAR VARIAS DE UNA VEZ (tecla `i`, de *import*, la misma palabra que en el CLI).
 *
 * Guardar las variables de un servicio una por una es, para la bóveda, un cambio de
 * configuración por variable: el servicio obedece el primero —sale y lo levanta su
 * supervisor— y arranca con media configuración mientras se teclea el resto. Cargarlas
 * juntas hace que se reinicie UNA vez, con todo puesto.
 *
 * Se acepta lo que se pueda escribir en una línea (`CLAVE=valor CLAVE2=valor2`) o la
 * RUTA de un `.env`, que es como suele llegar la configuración de un servicio.
 */
function promptLoadVars (term, st, { ns = null, pub = null, where }) {
  const i = L(st)
  setInput(st, {
    label: i.loadLabel(where),
    hint: i.loadHint,
    onSubmit: async (raw) => {
      const text = raw.trim()
      st.input = null
      if (!text) return
      let content = text
      // Sin un `=` no es una lista de variables: es la ruta de un archivo.
      if (!text.includes('=')) {
        try { content = fs.readFileSync(text, 'utf8') } catch (_) { flash(st, i.loadNoFile(text), 'danger'); return }
      }
      const { items, errors } = parseEnvInput(content)
      // Un archivo con un problema no se carga a medias: se dice qué línea y no se
      // escribe nada. Media configuración aplicada es peor que ninguna.
      if (errors.length) { flash(st, i.loadNothing + ' ' + i.envErr[errors[0].code](errors[0]), 'danger'); return }
      askVisibility(term, st, async (isPublic) => {
        const withVisibility = items.map((it) => ({ ...it, public: isPublic }))
        const r = await guard(term, st, i.loadingVars, () => (pub
          ? vc.applyDeviceSecrets(pub, withVisibility, activeId(st))
          : vc.applySecrets(ns, withVisibility, activeId(st))))
        if (r.ok) { flash(st, i.loadedVars(items.length, where)); st.secrets = r.v }
      })
    },
    onCancel: () => { st.input = null }
  })
}

/** Cargar varias en un SCOPE: primero cuál, luego el bloque. */
function promptLoadScopeVars (term, st) {
  const i = L(st)
  const existing = Object.keys(st.secrets?.ns || {})
  setInput(st, {
    label: i.nsLabel,
    hint: existing.length ? i.nsHintExisting(existing.join(', ')) : i.nsHint,
    onSubmit: (ns) => {
      const nsName = ns.trim()
      if (!NS_RE.test(nsName)) { flash(st, i.nsInvalid, 'danger'); return }
      st.input = null
      promptLoadVars(term, st, { ns: nsName, where: nsName })
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
      const nsName = ns.trim()
      if (!NS_RE.test(nsName)) { flash(st, i.nsInvalid, 'danger'); promptNewVariable(term, st); return }
      st.input = null
      setInput(st, {
        label: i.keyLabel(nsName),
        hint: i.keyHint,
        onSubmit: (key) => {
          const kv = key.trim()
          if (!KEY_RE.test(kv)) { flash(st, i.keyInvalid, 'danger'); return }
          st.input = null
          setInput(st, {
            label: i.valueLabel(nsName, kv),
            mask: true,
            hint: i.valueHint,
            onSubmit: async (value) => {
              st.input = null
              if (!value) { flash(st, i.valueEmpty, 'danger'); return }
              askVisibility(term, st, async (isPublic) => {
                const r = await guard(term, st, i.savingVar, () => vc.setSecret(nsName, kv, value, activeId(st), isPublic))
                if (r.ok) { flash(st, i.varSaved(nsName, kv)); st.secrets = r.v }
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
  else if (ch === 'n') { const f = cf.onNo; st.confirm = null; await f?.() }
  // Enter y Esc toman el CAMINO SEGURO, y cuál es lo dice quien pregunta. Sin esto el
  // defecto era siempre «no», y una pregunta formulada al revés lo volvía el peligroso.
  else if (key.name === 'escape' || key.name === 'enter' || key.name === 'ctrl-c') {
    const f = cf.defaultYes ? cf.onYes : cf.onNo
    st.confirm = null
    await f?.()
  }
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
  // El aparato señalado ahora mismo: `e variables` solo tiene sentido en un servicio (es
  // el único que las lee), y las filas seleccionables de la lista son justo los aparatos.
  const devs = mergeMembersAndCerts(st.members, st.devices?.issued || [])
  const cur = devs[Math.min(st.sel?.devices || 0, devs.length - 1)]
  return segs({
    pending: !!st.pending,
    hasDevices: (st.devices?.issued || []).length > 0,
    isService: !!cur?.cn,
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
  // Y si lo que se entrega es un SERVICIO, se dice: el papel que sale de este QR no
  // firma ni ve el contenido, solo lee las variables de ese namespace.
  if (info.service) lines.push(t.warn(i.pairService(info.service)))
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
  const version = s?.version || 'dev'
  const daemonTxt = up ? i.daemonRunning : i.daemonStopped
  lines[0] = t.bar(`dotrino-vault ${version}   daemon: ${daemonTxt}   ${vc.vaultDir()}`, cols)

  const ap = activeProfile(st)
  const apTxt = ap ? `${t.accent('●')} ${t.bold(ap.name || i.noName)} ${lockGlyph(ap)} ${t.muted('· ' + (ap.fingerprint || '—'))}` : t.muted('—')
  lines[1] = ' ' + i.activeVault + apTxt
  // El .deb instala el binario pero NO reinicia el servicio (y si se reinicia ANTES de
  // instalar, peor: el daemon se queda con el binario viejo, ya borrado, y hay dos copias
  // en RAM). `status` ya lo avisa; aquí también, que es donde uno se queda mirando.
  lines[2] = (up && s?.version && VERSION !== 'dev' && s.version !== VERSION) ? ' ' + t.warn(i.daemonStale(s.version, VERSION)) : ''
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
    // Su contraseña, SOLO en memoria y SOLO mientras la TUI esté abierta: sirve para
    // reabrir sin volver a preguntar si el daemon pierde el estado (ver
    // `reunlockSilently`). Se olvida con `k`, al quitar la contraseña y al salir.
    sessionPwd: new Map(),
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
      // ¿Se cerró sola mientras nadie miraba? Olvida su contraseña y sal de su contenido.
      await forgetAutoLocked(term, st)
      // caducar el flash a los ~4 s
      if (st.flash && Date.now() - st.flash.at > 4000) st.flash = null
      render(term, st)

      const base = (st.screen === 'pairing' || (st.screen === 'devices' && !st.input && !st.confirm)) ? 800 : 0
      // Despertar a tiempo del bloqueo automático, además del sondeo de la pantalla.
      const wake = autoLockWakeIn(st)
      const tick = base && wake ? Math.min(base, wake) : (base || wake)
      const key = await term.readKey(tick)

      if (key.name === 'resize') continue
      // Un despertar del bloqueo automático no es una tecla: ya se atendió arriba, y las
      // pantallas que NO esperan `tick` (todas menos aparatos y emparejamiento) no tienen
      // por qué verlo.
      if (key.name === 'tick' && st.screen !== 'pairing' && st.screen !== 'devices') continue
      // input/confirm se AWAITan: serializa las ops contra el daemon (ver onInputKey).
      // Ctrl-C dentro de un modal lo CANCELA (no sale); fuera de un modal, sale.
      if (st.input) { await onInputKey(st, key); continue }
      if (st.confirm) { await onConfirmKey(st, key); continue }
      if (key.name === 'ctrl-c') { running = false; continue }

      // TECLEAR ES USO. El candado se cierra a los 5 min de no usarse, y hasta ahora
      // «usar» solo contaba cuando algo pedía al daemon: podías estar media hora
      // navegando esta pantalla y se cerraba igual, que es lo contrario de lo que se
      // quería. Se avisa como mucho una vez por minuto —el plazo son cinco, así que
      // sobra— para no escribir un archivo por tecla.
      seguirAqui(st)

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
    st.sessionPwd.clear()
    for (const id of st.unlockedHere) { try { await vc.lockProfile(id) } catch (_) {} }
    term.close()
  }
}

// Solo para pruebas headless (render sin terminal real). No usar en runtime.
export const __test = { render, activeLocked, autoLockedIds, autoLockWakeIn, forgetAutoLocked, autoLockMin, refreshAll, ensureUnlocked, profileRows, deviceRows, secretRows, devVarRows, meRows, capsRows, onKeyCaps, pairModeRows, pairingBody, scrollBody, fitHelp, toggleLang, mergeMembersAndCerts, seguirAqui, resetToque: () => { ultimoToque = 0 } }
