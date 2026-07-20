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
 * Cada "bóveda" es un PERFIL (maestra propia, dir propio, dispositivos y secretos
 * propios). Las acciones operan sobre la bóveda ACTIVA; para operar otra, cámbiala
 * en la pantalla de bóvedas.
 */
import { execFile } from 'node:child_process'
import { createTerm } from './term.js'
import { qrToString } from '../qr.js'
import * as vc from '../vaultControl.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Regex de validación (mismas que el store de secretos, protocol.js).
const NS_RE = /^[a-z0-9-]{1,32}$/
const KEY_RE = /^[A-Z0-9_]{1,64}$/

// ------------------------------- utilidades --------------------------------

function humanErr (e) {
  if (e?.code === 'DAEMON_DOWN') return 'El daemon no está corriendo. Arráncalo: systemctl --user start dotrino-vault (o reinicia la TUI).'
  return e?.message || String(e)
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

// --------------------------------- pantallas -------------------------------

function profileRows (st, t) {
  const list = st.profiles?.profiles || []
  return list.map((p) => {
    const mark = p.current ? t.accent('●') : ' '
    const lk = !p.protected ? t.muted('sin clave') : (p.locked ? t.warn('🔒 bloqueada') : t.ok('🔓 abierta'))
    const name = p.current ? t.bold(p.name || '(sin nombre)') : (p.name || '(sin nombre)')
    return { text: ` ${mark} ${name}   ${t.muted(p.id)}   ${t.muted(p.fingerprint || '—')}   ${lk}`, sel: true, meta: p }
  })
}

function deviceRows (st, t) {
  const rows = []
  const pend = st.pending
  if (pend) {
    rows.push({ text: t.warn(` ⧗ PENDIENTE: ${pend.deviceId}`) + t.muted('  — pulsa A para aprobar, X para rechazar'), sel: false })
    rows.push({ text: '', sel: false })
  }
  const issued = st.devices?.issued || []
  if (!issued.length) {
    rows.push({ text: t.muted('  (sin dispositivos enrolados — pulsa E para emparejar uno)'), sel: false })
  }
  for (const d of issued) {
    const label = d.label || t.muted('(sin etiqueta)')
    const line = ` ${t.bold(d.deviceId)}  ${label}  ${t.muted('scope:' + shortScope(d.scope))}  ${t.muted('exp:' + fmtExp(d.exp))}  ${t.muted('nonce:' + (d.nonce ?? '—'))}`
    rows.push({ text: line, sel: true, meta: d })
  }
  const revoked = st.devices?.revoked || []
  if (revoked.length) {
    rows.push({ text: '', sel: false })
    rows.push({ text: t.muted(`  Revocados: ${revoked.length}`), sel: false })
  }
  return rows
}

function secretRows (st, t) {
  const ns = st.secrets || {}
  const names = Object.keys(ns).sort()
  const rows = []
  if (!names.length) {
    rows.push({ text: t.muted('  (sin scopes — pulsa N para agregar la primera variable)'), sel: false })
    return rows
  }
  for (const n of names) {
    rows.push({ text: t.accent(` ▸ ${n}`) + t.muted(`   (scope vault:secrets:${n})`), sel: true, meta: { ns: n, key: null } })
    for (const k of ns[n].slice().sort()) {
      rows.push({ text: `      ${k}   ${t.muted('••••••')}`, sel: true, meta: { ns: n, key: k } })
    }
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
  try { const v = await fn(); st.busy = null; return { ok: true, v } } catch (e) { st.busy = null; flash(st, humanErr(e), 'danger'); return { ok: false, e } }
}

async function refreshAll (term, st) {
  const r = await guard(term, st, 'Cargando…', () => vc.snapshot(activeId(st)))
  if (!r.ok) return
  const { devices, secrets, profiles } = r.v
  if (profiles) st.profiles = profiles
  if (secrets) st.secrets = secrets.ns || {}
  if (devices) {
    const issued = (devices.issued || devices.active || devices.delegations || [])
    st.devices = { issued: await Promise.all(issued.map(async (d) => ({ ...d, deviceId: d.sub ? await vc.deviceIdOf(d.sub) : '????-????' }))), revoked: devices.revoked || [] }
  }
}

async function refreshDevices (term, st) {
  const r = await guard(term, st, 'Cargando dispositivos…', () => vc.listDevices(activeId(st)))
  if (r.ok) st.devices = r.v
}
async function refreshSecrets (term, st) {
  const r = await guard(term, st, 'Cargando secretos…', () => vc.listSecrets(activeId(st)))
  if (r.ok) st.secrets = r.v
}
async function refreshProfiles (term, st) {
  const r = await guard(term, st, 'Cargando bóvedas…', () => vc.listProfiles())
  if (r.ok) st.profiles = r.v
}

/** Asegura la bóveda desbloqueada antes de EDITARLA (rename/rm/password). */
async function ensureUnlocked (term, st, p, thenFn) {
  if (!p.protected || !p.locked) return thenFn()
  setInput(st, {
    label: `Contraseña de "${p.name || p.id}"`,
    mask: true,
    hint: 'necesaria para editar la bóveda',
    onSubmit: async (pwd) => {
      st.input = null
      const r = await guard(term, st, 'Desbloqueando…', () => vc.unlockProfile(p.id, pwd))
      if (!r.ok) return
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
  // Clampa el índice guardado ANTES de aplicar el delta: si la lista encogió, la
  // primera flecha debe moverse desde la posición visible, no desde un índice viejo.
  st.sel[screen] = Math.max(0, Math.min(st.sel[screen], count - 1))
  if (key.name === 'up') st.sel[screen] = Math.max(0, st.sel[screen] - 1)
  else if (key.name === 'down') st.sel[screen] = Math.min(count - 1, st.sel[screen] + 1)
  else if (key.name === 'pageup') st.sel[screen] = Math.max(0, st.sel[screen] - 5)
  else if (key.name === 'pagedown') st.sel[screen] = Math.min(count - 1, st.sel[screen] + 5)
  else if (key.name === 'home') st.sel[screen] = 0
  else if (key.name === 'end') st.sel[screen] = count - 1
}

async function onKeyProfiles (term, st, key) {
  const rows = profileRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'profiles', sels.length)
  const cur = sels[Math.min(st.sel.profiles, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (key.name === 'enter' && cur) {
    // Entrar a la bóveda: la activa (si no lo estaba ya) y pasa a sus pestañas
    // (Dispositivos/Scopes) — así siempre es explícito de qué bóveda son los ítems.
    if (!cur.current) {
      const r = await guard(term, st, 'Cambiando de bóveda…', () => vc.useProfile(cur.id))
      if (!r.ok) return true
      flash(st, `Bóveda activa: ${cur.name || cur.id}`)
      await refreshAll(term, st)
    }
    st.screen = 'devices'
    await refreshDevices(term, st)
  } else if (ch === 'n') {
    setInput(st, {
      label: 'Nombre de la nueva bóveda',
      hint: 'crea una identidad nueva y vacía',
      onSubmit: async (name) => {
        st.input = null
        if (!name.trim()) { flash(st, 'El nombre no puede estar vacío', 'danger'); return }
        const r = await guard(term, st, 'Creando bóveda…', () => vc.addProfile(name.trim()))
        if (r.ok) { flash(st, `Bóveda creada: ${name.trim()}`); await refreshProfiles(term, st) }
      },
      onCancel: () => { st.input = null }
    })
  } else if (ch === 'r' && cur) {
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: `Nuevo nombre para "${p.name || p.id}"`,
      value: p.name || '',
      onSubmit: async (name) => {
        st.input = null
        if (!name.trim()) { flash(st, 'El nombre no puede estar vacío', 'danger'); return }
        const r = await guard(term, st, 'Renombrando…', () => vc.renameProfile(p.id, name.trim()))
        if (r.ok) { flash(st, 'Bóveda renombrada'); await refreshProfiles(term, st) }
      },
      onCancel: () => { st.input = null }
    }))
  } else if ((key.name === 'delete' || ch === 'd') && cur) {
    if ((st.profiles.profiles || []).length <= 1) { flash(st, 'No se puede borrar la única bóveda', 'danger'); return true }
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: `Escribe "${p.name || p.id}" para BORRARLA (irreversible)`,
      hint: 'se pierde su clave; sus dispositivos dejan de funcionar',
      onSubmit: async (typed) => {
        st.input = null
        if (typed.trim() !== (p.name || p.id)) { flash(st, 'Cancelado (el nombre no coincide)', 'warn'); return }
        const r = await guard(term, st, 'Borrando bóveda…', () => vc.removeProfile(p.id))
        if (r.ok) { flash(st, 'Bóveda borrada'); st.sel.profiles = 0; await refreshAll(term, st) }
      },
      onCancel: () => { st.input = null }
    }))
  } else if (ch === 'k' && cur) {
    await ensureUnlocked(term, st, cur, (p = cur) => setInput(st, {
      label: `Contraseña nueva para "${p.name || p.id}" (mín. 4)`,
      mask: true,
      onSubmit: async (pwd) => {
        st.input = null
        if (pwd.length < 4) { flash(st, 'La contraseña debe tener al menos 4 caracteres', 'danger'); return }
        setInput(st, {
          label: 'Repite la contraseña',
          mask: true,
          onSubmit: async (again) => {
            st.input = null
            if (again !== pwd) { flash(st, 'Las contraseñas no coinciden', 'danger'); return }
            const r = await guard(term, st, 'Guardando contraseña…', () => vc.setProfilePassword(p.id, pwd))
            if (r.ok) { flash(st, 'Contraseña guardada'); await refreshProfiles(term, st) }
          },
          onCancel: () => { st.input = null }
        })
      },
      onCancel: () => { st.input = null }
    }))
  } else if (ch === 'x' && cur) { // quitar contraseña
    if (!cur.protected) { flash(st, 'Esta bóveda no tiene contraseña', 'warn'); return true }
    await ensureUnlocked(term, st, cur, async (p = cur) => {
      const r = await guard(term, st, 'Quitando contraseña…', () => vc.removeProfilePassword(p.id))
      if (r.ok) { flash(st, 'Contraseña quitada'); await refreshProfiles(term, st) }
    })
  } else if (ch === 'u' && cur) {
    if (!cur.protected) { flash(st, 'Esta bóveda no tiene contraseña', 'warn'); return true }
    if (!cur.locked) { flash(st, 'Ya está desbloqueada', 'warn'); return true }
    await ensureUnlocked(term, st, cur, async () => { flash(st, 'Bóveda desbloqueada'); await refreshProfiles(term, st) })
  } else if (ch === 'l' && cur) {
    if (!cur.protected) { flash(st, 'Esta bóveda no tiene contraseña', 'warn'); return true }
    const r = await guard(term, st, 'Bloqueando…', () => vc.lockProfile(cur.id))
    if (r.ok) { flash(st, 'Bóveda bloqueada'); await refreshProfiles(term, st) }
  }
  return true
}

async function onKeyDevices (term, st, key) {
  // Sondea el dispositivo pendiente en cada tick (uno puede conectarse mientras
  // estás en esta pantalla, no solo en la de emparejamiento).
  if (key.name === 'tick') { st.pending = vc.pendingEnroll(); return true }

  const rows = deviceRows(st, term.t)
  const sels = rows.filter((r) => r.sel).map((r) => r.meta)
  moveSel(st, key, 'devices', sels.length)
  const cur = sels[Math.min(st.sel.devices, sels.length - 1)]
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null

  if (ch === 'e') {
    const r = await guard(term, st, 'Iniciando emparejamiento…', () => vc.startPairing({ profile: activeId(st) }))
    if (r.ok) { st.pairing = r.v; st.pending = null; st.screen = 'pairing' }
  } else if (ch === 'a') { // aprobar el pendiente
    if (!st.pending) { flash(st, 'No hay ningún dispositivo pendiente', 'warn'); return true }
    promptApprove(term, st)
  } else if (ch === 'x') { // rechazar el pendiente
    if (!st.pending) { flash(st, 'No hay ningún dispositivo pendiente para rechazar', 'warn'); return true }
    const r = await guard(term, st, 'Rechazando…', () => vc.rejectPending(st.pending.deviceId, activeId(st)))
    if (r.ok) { flash(st, 'Dispositivo rechazado'); st.pending = null }
  } else if ((ch === 'v' || key.name === 'delete') && cur?.nonce != null) { // revocar el enrolado seleccionado
    setConfirm(st, {
      text: `¿Revocar ${cur.deviceId}? Se le ordena autoborrarse al reconectar.`,
      onYes: async () => {
        st.confirm = null
        const r = await guard(term, st, 'Revocando…', () => vc.revokeDevice(cur.nonce, activeId(st)))
        if (r.ok) { flash(st, `Revocado ${cur.deviceId}`); st.devices = r.v; st.sel.devices = 0 }
      },
      onNo: () => { st.confirm = null }
    })
  } else if (ch === 'r') {
    await refreshDevices(term, st)
  }
  return true
}

function promptApprove (term, st) {
  setInput(st, {
    label: `Código que MUESTRA el dispositivo ${st.pending?.deviceId || ''}`,
    hint: 'el vault no lo conoce: compáralo en la otra pantalla',
    onSubmit: async (code) => {
      st.input = null
      if (!code.trim()) { flash(st, 'Falta el código', 'danger'); return }
      const r = await guard(term, st, 'Aprobando…', () => vc.approvePending(code.trim(), activeId(st)))
      if (r.ok) { flash(st, 'Dispositivo aprobado'); st.devices = r.v; st.pending = null; st.screen = 'devices' }
    },
    onCancel: () => { st.input = null }
  })
}

async function onKeyPairing (term, st, key) {
  const ch = key.name === 'char' ? key.ch.toLowerCase() : null
  if (key.name === 'tick') {
    const pend = vc.pendingEnroll()
    if (pend) st.pending = pend
    return true
  }
  if (ch === 'a' && st.pending) { promptApprove(term, st); return true }
  if (ch === 'x' && st.pending) {
    const r = await guard(term, st, 'Rechazando…', () => vc.rejectPending(st.pending.deviceId, activeId(st)))
    if (r.ok) { flash(st, 'Dispositivo rechazado'); st.pending = null }
    return true
  }
  if (ch === 'e') { // reiniciar emparejamiento
    const r = await guard(term, st, 'Reiniciando emparejamiento…', () => vc.startPairing({ profile: activeId(st) }))
    if (r.ok) { st.pairing = r.v; st.pending = null }
    return true
  }
  if (key.name === 'escape' || ch === 'b') { st.screen = 'devices'; st.pairing = null; await refreshDevices(term, st) }
  return true
}

async function onKeySecrets (term, st, key) {
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
        text: `¿Quitar la variable ${cur.ns}/${cur.key}?`,
        onYes: async () => {
          st.confirm = null
          const r = await guard(term, st, 'Quitando variable…', () => vc.deleteSecret(cur.ns, cur.key, activeId(st)))
          if (r.ok) { flash(st, 'Variable quitada'); st.secrets = r.v; st.sel.secrets = Math.max(0, st.sel.secrets - 1) }
        },
        onNo: () => { st.confirm = null }
      })
    } else {
      const count = (st.secrets?.[cur.ns] || []).length
      setConfirm(st, {
        text: `¿Quitar el scope "${cur.ns}" ENTERO (${count} variable(s))?`,
        onYes: async () => {
          st.confirm = null
          const r = await guard(term, st, 'Quitando scope…', () => vc.deleteScope(cur.ns, activeId(st)))
          if (r.ok) { flash(st, `Scope "${cur.ns}" quitado`); st.secrets = r.v; st.sel.secrets = 0 }
        },
        onNo: () => { st.confirm = null }
      })
    }
  } else if (ch === 'r') {
    await refreshSecrets(term, st)
  }
  return true
}

function promptNewVariable (term, st) {
  const existing = Object.keys(st.secrets || {})
  setInput(st, {
    label: 'Scope (namespace del servicio)',
    hint: existing.length ? `[a-z0-9-] · existen: ${existing.join(', ')}` : '[a-z0-9-], p. ej. proxy',
    onSubmit: (ns) => {
      const nsv = ns.trim()
      if (!NS_RE.test(nsv)) { flash(st, 'Scope inválido: usa [a-z0-9-]{1,32}', 'danger'); promptNewVariable(term, st); return }
      st.input = null
      setInput(st, {
        label: `Variable en "${nsv}" (MAYUSCULAS_CON_GUION_BAJO)`,
        hint: '[A-Z0-9_], p. ej. TURN_KEY_ID',
        onSubmit: (key) => {
          const kv = key.trim()
          if (!KEY_RE.test(kv)) { flash(st, 'Clave inválida: usa [A-Z0-9_]{1,64}', 'danger'); return }
          st.input = null
          setInput(st, {
            label: `Valor de ${nsv}/${kv}`,
            mask: true,
            hint: 'el valor nunca se muestra; se guarda en la bóveda',
            onSubmit: async (value) => {
              st.input = null
              if (!value) { flash(st, 'El valor no puede estar vacío', 'danger'); return }
              const r = await guard(term, st, 'Guardando variable…', () => vc.setSecret(nsv, kv, value, activeId(st)))
              if (r.ok) { flash(st, `Guardado ${nsv}/${kv}`); st.secrets = r.v }
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
  if (ch === 's' || ch === 'y') { const f = cf.onYes; st.confirm = null; await f?.() }
  else if (ch === 'n' || key.name === 'escape' || key.name === 'enter' || key.name === 'ctrl-c') { const f = cf.onNo; st.confirm = null; await f?.() }
}

// --------------------------------- render ----------------------------------

// Pestañas INTERNAS de una bóveda ya elegida: se cambian con ←→. La lista de
// bóvedas (profiles) es el nivel de arriba (se entra con Enter, no es una pestaña).
const INNER_TABS = ['devices', 'secrets']
const TAB_LABEL = { devices: 'Dispositivos', secrets: 'Scopes y variables' }

const HELP = {
  profiles: '↑↓ · Enter entrar · n nueva · r renombrar · d borrar · k clave · x quitar-clave · u desbloq · l bloq · q salir',
  devices: '←→ pestaña · ↑↓ · e emparejar · a aprobar · x rechazar · v revocar · r refrescar · Esc bóvedas · q salir',
  secrets: '←→ pestaña · ↑↓ · n nueva variable · x quitar (variable/scope) · r refrescar · Esc bóvedas · q salir',
  pairing: 'a aprobar · x rechazar · e reiniciar · Esc atrás'
}
const TITLE = {
  profiles: 'Bóvedas',
  pairing: 'Emparejar un dispositivo'
}

/** Barra de pestañas horizontal (Dispositivos | Scopes y variables) de la bóveda entrada. */
function renderTabs (st, t) {
  return INNER_TABS.map((k) => {
    const active = st.screen === k
    return active ? t.bold(t.accent('▐ ' + TAB_LABEL[k] + ' ▌')) : t.muted('  ' + TAB_LABEL[k] + '  ')
  }).join('   ') + t.muted('   (←→ cambiar)')
}

function pairingBody (st, t, cols, height) {
  const info = st.pairing
  const lines = []
  const left = Math.max(0, Math.round((info.expiresAt - Date.now()) / 60000))
  lines.push(t.muted(`Válido ~${left} min. Escanéalo o abre la URL en el dispositivo.`))
  lines.push('')
  // QR solo si entra cómodo (es "alto": ~ (módulos+8)/2 filas).
  let qr = ''
  try { qr = qrToString(info.url) } catch (_) {}
  const qrLines = qr ? qr.replace(/\n$/, '').split('\n') : []
  const qrWidth = qrLines.length ? Math.max(...qrLines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').length)) : 0
  const reserved = 8 // encabezado + URL + payload + aviso
  if (qrLines.length && qrWidth <= cols && qrLines.length <= height - reserved) {
    for (const l of qrLines) lines.push(l)
    lines.push('')
  }
  lines.push(t.bold('URL: ') + info.url)
  lines.push('')
  lines.push(t.muted('O pega este código en la pestaña #vault de profile.dotrino.com:'))
  lines.push(info.payload)
  lines.push('')
  lines.push(t.danger('⚠ Este código deja LEER tus datos y FIRMAR con tu identidad. No lo compartas.'))
  lines.push('')
  if (st.pending) lines.push(t.warn(`⧗ Se conectó: ${st.pending.deviceId} — pulsa A y escribe el código que muestra.`))
  else lines.push(t.muted('Esperando a que el dispositivo se conecte…'))
  return lines
}

function render (term, st) {
  const t = term.t
  const { cols, rows } = term.size()
  // La distribución necesita: header+contexto (5) + 1 de contenido + estado + ayuda.
  // En un terminal más chico, en vez de escribir en índices fuera de rango, avisamos.
  if (rows < 9 || cols < 24) {
    term.render([t.warn('Terminal muy pequeño'), `Agranda a ≥ 24×9 (hay ${cols}×${rows}).`])
    return
  }
  const lines = new Array(rows).fill('')

  const s = st.state
  const up = st.daemonUp
  const ver = s?.version || 'dev'
  const daemonTxt = up ? 'corriendo' : 'DETENIDO'
  lines[0] = t.bar(`dotrino-vault ${ver}   daemon: ${daemonTxt}   ${vc.vaultDir()}`, cols)

  const ap = activeProfile(st)
  const apTxt = ap ? `${t.accent('●')} ${t.bold(ap.name || '(sin nombre)')} ${lockGlyph(ap)} ${t.muted('· ' + (ap.fingerprint || '—'))}` : t.muted('—')
  lines[1] = ' Bóveda activa: ' + apTxt
  lines[2] = ''
  // Dispositivos/Scopes son pestañas de la bóveda activa (se entra desde Bóvedas);
  // el resto muestra su título simple.
  lines[3] = INNER_TABS.includes(st.screen) ? ' ' + renderTabs(st, t) : ' ' + t.title('» ' + (TITLE[st.screen] || ''))
  lines[4] = ''

  const top = 5
  const bottom = 2 // status + help
  const contentH = Math.max(1, rows - top - bottom)
  const scrollRef = st.scroll[st.screen] || (st.scroll[st.screen] = { value: 0 })

  let body = []
  if (st.screen === 'profiles') body = renderList(profileRows(st, t), st.sel.profiles, contentH, cols, t, scrollRef)
  else if (st.screen === 'devices') body = renderList(deviceRows(st, t), st.sel.devices, contentH, cols, t, scrollRef)
  else if (st.screen === 'secrets') body = renderList(secretRows(st, t), st.sel.secrets, contentH, cols, t, scrollRef)
  else if (st.screen === 'pairing') {
    const pb = pairingBody(st, t, cols, contentH)
    body = pb.slice(0, contentH)
    while (body.length < contentH) body.push('')
  }
  for (let i = 0; i < contentH; i++) lines[top + i] = body[i] ?? ''

  // línea de estado: input / confirm / flash / busy
  const statusRow = rows - 2
  if (st.busy) lines[statusRow] = ' ' + t.accent('⏳ ' + st.busy)
  else if (st.input) {
    const inp = st.input
    const shown = inp.mask ? '•'.repeat(inp.value.length) : inp.value
    const hint = inp.hint ? t.muted('  [' + inp.hint + ']') : ''
    lines[statusRow] = ' ' + t.bold(inp.label + ': ') + shown + t.accent('▏') + hint
  } else if (st.confirm) {
    lines[statusRow] = ' ' + t.warn(st.confirm.text) + t.muted('  (s / N)')
  } else if (st.flash) {
    const kind = st.flash.kind
    const style = kind === 'danger' ? t.danger : kind === 'warn' ? t.warn : t.ok
    lines[statusRow] = ' ' + style((kind === 'danger' ? '✗ ' : kind === 'warn' ? '! ' : '✓ ') + st.flash.text)
  } else lines[statusRow] = ''

  // barra de ayuda
  let help = HELP[st.screen] || ''
  if (st.input) help = 'Enter confirmar · Esc cancelar · Ctrl-U limpiar'
  else if (st.confirm) help = 's confirmar · n/Esc cancelar'
  lines[rows - 1] = t.bar(help, cols)

  term.render(lines)
}

// --------------------------- pantalla daemon caído -------------------------

async function daemonDownScreen (term, st) {
  while (true) {
    const t = term.t
    const { cols, rows } = term.size()
    const lines = new Array(Math.max(rows, 2)).fill('')
    // Contenido en orden; se coloca desde la fila 2 y se corta si no cabe (no se
    // escribe nunca en índices fijos que se salgan de un terminal pequeño).
    const content = [
      t.danger('El daemon del vault no está corriendo.'),
      '',
      'La TUI le da órdenes al daemon (custodio de tu clave). Sin él no puede',
      'crear bóvedas, listar dispositivos ni tocar secretos.',
      '',
      t.bold('S') + '  intentar arrancarlo:  ' + t.muted('systemctl --user start dotrino-vault'),
      t.bold('R') + '  volver a comprobar',
      t.bold('Q') + '  salir',
      '',
      t.muted('En desarrollo, arráncalo a mano:  node bin/dotrino-vaultd.js')
    ]
    if (st.flash) content.push('', (st.flash.kind === 'danger' ? t.danger : t.warn)(st.flash.text))
    lines[0] = t.bar('dotrino-vault   daemon: DETENIDO', cols)
    for (let i = 0; i < content.length && 2 + i < rows - 1; i++) lines[2 + i] = ' ' + content[i]
    lines[rows - 1] = t.bar('S arrancar · R comprobar · Q salir', cols)
    term.render(lines)

    const key = await term.readKey()
    const ch = key.name === 'char' ? key.ch.toLowerCase() : null
    if (ch === 'q' || key.name === 'ctrl-c') return false
    if (ch === 'r') { if (vc.daemonAlive()) return true; flash(st, 'Sigue sin responder', 'warn') }
    if (ch === 's') {
      st.busy = 'Arrancando el servicio…'; // (no re-render aquí; mensaje simple)
      flash(st, 'Arrancando…', 'warn'); term.render(lines)
      const r = await startDaemonService()
      await sleep(1500)
      if (vc.daemonAlive()) return true
      flash(st, r.ok ? 'Arrancó pero aún no responde; pulsa R' : ('No se pudo arrancar: ' + r.err), 'danger')
      st.busy = null
    }
  }
}

// ---------------------------------- loop -----------------------------------

export async function runTui () {
  const term = createTerm()
  const st = {
    screen: 'profiles', // se arranca en la lista de bóvedas: hay que ENTRAR a una
    sel: { profiles: 0, devices: 0, secrets: 0 },
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
      // ←→ cambia entre las pestañas de la bóveda entrada (Dispositivos/Scopes).
      if ((key.name === 'left' || key.name === 'right') && INNER_TABS.includes(st.screen)) {
        const i = INNER_TABS.indexOf(st.screen)
        st.screen = INNER_TABS[(i + (key.name === 'right' ? 1 : -1) + INNER_TABS.length) % INNER_TABS.length]
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
      else if (st.screen === 'pairing') running = await onKeyPairing(term, st, key)
    }
  } finally {
    term.close()
  }
}

// Solo para pruebas headless (render sin terminal real). No usar en runtime.
export const __test = { render, profileRows, deviceRows, secretRows, pairingBody }
