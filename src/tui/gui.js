/**
 * gui.js — el PUENTE entre la ventana de escritorio y la pantalla de control.
 *
 * La ventana (`desktop/`, Rust + iced) no sabe nada de la bóveda: lanza
 * `dotrino-vault gui-bridge` (el mismo binario) y le habla por stdin/stdout, una línea JSON
 * por mensaje. Este proceso corre LA MISMA sesión que la TUI —`newSession`, `handleKey`,
 * `viewModel` de `app.js`— y le manda a la ventana lo que tiene que pintar. Así la ventana
 * tiene exactamente las pantallas, los textos y las acciones de la TUI, y una acción nueva
 * aparece en las dos sin tocar la otra.
 *
 * No abre ningún puerto: el canal son las tuberías del proceso hijo, que solo ve quien lo
 * lanzó. Y como la TUI, no toca la identidad ni la red: le habla al daemon por su carpeta.
 *
 * Mensajes de la ventana (uno por línea):
 *   {"key":{"name":"char","ch":"p"}}   una tecla, con los mismos nombres que `term.js`
 *   {"select":3}                        señalar la fila 3 (entre las seleccionables)
 *   {"activate":3}                      señalarla y pulsar Enter
 *   {"tab":"secrets"}                   ir a una pestaña de la bóveda entrada
 *   {"submit":"texto"}                  responder la pregunta abierta con ese texto
 *   {"confirm":true|false}              responder la confirmación abierta
 *   {"quit":true}                       salir (cerrando lo que se abrió aquí)
 *
 * Mensajes a la ventana:
 *   {"t":"view","v":{…}}                qué pintar (ver `viewModel`/`downModel`)
 *   {"t":"bye","relaunch":bool}         se terminó; con `relaunch`, volver a lanzar el puente
 *                                       (se instaló una versión nueva)
 *
 * Los textos llevan sus estilos como tramos: `[{"t":"…","c":"muted","b":true}]`.
 */
import * as vc from '../vaultControl.js'
import { makeTheme } from './term.js'
import {
  newSession, startSession, beforeRender, tickFor, handleKey, endSession,
  viewModel, downModel, selectRow, openTab, onKeyDown
} from './app.js'

// stdout es el canal: cualquier `console.log` suelto lo rompería. Va a stderr.
console.log = (...a) => console.error(...a)

// ----------------------------- estilos → tramos ------------------------------

/** Color del tema de la TUI (`makeTheme`) → nombre que entiende la ventana. */
const COLORS = { 44: 'accent', 114: 'ok', 214: 'warn', 203: 'danger', 244: 'muted', 81: 'title' }

/** Un texto con escapes SGR → tramos `{t, c?, b?}`. */
export function spans (str) {
  const out = []
  let bold = false
  let color = null
  let buf = ''
  const flush = () => {
    if (!buf) return
    const sp = { t: buf }
    if (color) sp.c = color
    if (bold) sp.b = true
    out.push(sp)
    buf = ''
  }
  const re = /\x1b\[([0-9;]*)m/g
  const s = String(str ?? '')
  let last = 0
  let m
  while ((m = re.exec(s))) {
    buf += s.slice(last, m.index)
    last = re.lastIndex
    flush()
    const codes = m[1] === '' ? [0] : m[1].split(';').map(Number)
    for (let k = 0; k < codes.length; k++) {
      const c = codes[k]
      if (c === 0) { bold = false; color = null } else if (c === 1) bold = true
      else if (c === 38 && codes[k + 1] === 5) { color = COLORS[codes[k + 2]] || null; k += 2 }
    }
  }
  buf += s.slice(last)
  flush()
  return out
}

/** Pasa a tramos todos los textos que el modelo trae con estilos. */
function toWire (vm) {
  const v = { ...vm }
  if (v.rows) v.rows = v.rows.map((r) => ({ ...r, text: spans(r.text) }))
  if (v.body) v.body = v.body.map(spans)
  for (const k of ['title', 'notice', 'status']) {
    if (v[k] && typeof v[k] === 'object' && 'text' in v[k]) v[k] = { ...v[k], text: spans(v[k].text) }
  }
  if (v.confirm) v.confirm = { ...v.confirm, text: spans(v.confirm.text) }
  // «p emparejar» → { key: 'p', label: 'emparejar' }. La tecla es el mnemónico de la TUI, y
  // la ventana la usa como atajo de teclado y la manda al pulsar el botón.
  v.help = (v.help || []).map((seg) => {
    const sp = String(seg).indexOf(' ')
    return sp < 0 ? { key: seg, label: '' } : { key: seg.slice(0, sp), label: seg.slice(sp + 1) }
  })
  return v
}

// --------------------------------- el bucle ---------------------------------

export async function runGuiBridge ({ input = process.stdin, output = process.stdout } = {}) {
  const t = makeTheme({ color: true })
  const st = newSession()
  const queue = []
  let waiter = null

  const push = (ev) => { if (waiter) { const w = waiter; waiter = null; w(ev) } else queue.push(ev) }

  let pending = ''
  input.setEncoding('utf8')
  input.on('data', (chunk) => {
    pending += chunk
    let nl
    while ((nl = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, nl).trim()
      pending = pending.slice(nl + 1)
      if (!line) continue
      try { push(JSON.parse(line)) } catch (e) { console.error('[gui-bridge] bad message:', e.message) }
    }
  })
  // La ventana se cerró (o murió): se sale igual que con `q`, cerrando lo abierto aquí.
  input.on('end', () => push({ quit: true }))
  input.on('error', () => push({ quit: true }))

  const next = (ms) => {
    if (queue.length) return Promise.resolve(queue.shift())
    return new Promise((resolve) => {
      let timer = null
      waiter = (ev) => { if (timer) clearTimeout(timer); resolve(ev) }
      if (ms) timer = setTimeout(() => { waiter = null; resolve({ key: { name: 'tick' } }) }, ms)
    })
  }

  // Si la ventana ya no está, escribir da EPIPE: no es un fallo de la sesión, y no puede
  // tumbar el cierre ordenado (que es el que vuelve a cerrar las bóvedas).
  let gone = false
  output.on?.('error', () => { gone = true })
  let lastSent = ''
  const send = (msg) => {
    if (gone) return
    const line = JSON.stringify(msg)
    if (msg.t === 'view' && line === lastSent) return
    if (msg.t === 'view') lastSent = line
    output.write(line + '\n')
  }
  const sendView = () => send({ t: 'view', v: toWire(st.down ? downModel(st) : viewModel(st, t)) })

  // La sesión pinta también a mitad de una operación (`guard` pone «Guardando…»): el
  // «terminal» de la ventana solo avisa de que hay algo nuevo.
  const term = {
    t,
    gui: () => sendView(),
    size: () => ({ cols: 200, rows: 60 }),
    render: () => sendView(),
    readKey: async () => ({ name: 'tick' }),
    close: () => {}
  }

  /** Un mensaje de la ventana → la tecla (o las teclas) que equivale. */
  const toKeys = (ev) => {
    if (ev.key) return [ev.key]
    if (typeof ev.select === 'number') { selectRow(st, ev.select); return [] }
    if (typeof ev.activate === 'number') { selectRow(st, ev.activate); return [{ name: 'enter' }] }
    if (typeof ev.submit === 'string') {
      if (st.input) st.input.value = ev.submit
      return [{ name: 'enter' }]
    }
    if (typeof ev.confirm === 'boolean') return [{ name: 'char', ch: ev.confirm ? 'y' : 'n' }]
    return []
  }

  let relaunch = false
  let inSession = false
  try {
    while (true) {
      if (!vc.daemonAlive()) {
        // SIN SERVICIO: la pantalla de arrancarlo. Si se cae a mitad de sesión, se vuelve
        // aquí en vez de dejar una ventana que contesta errores a todo.
        st.down = true
        sendView()
        const ev = await next(3000)
        if (ev.quit) break
        if (ev.key?.name === 'tick') continue
        const keys = toKeys(ev)
        let r = null
        for (const k of keys) r = await onKeyDown(st, k, sendView)
        if (r === false) break
        continue
      }
      if (st.down || !inSession) {
        st.down = false
        await startSession(term, st)
        inSession = true
      }
      await beforeRender(term, st)
      sendView()
      const ev = await next(tickFor(st) || 2000)
      if (ev.quit) break
      if (ev.tab) { await openTab(term, st, ev.tab); continue }
      let running = true
      for (const k of toKeys(ev)) {
        // Un tick sin pantalla que lo espere no hace nada; solo sirve para repintar.
        running = await handleKey(term, st, k)
        if (!running) break
      }
      if (!running) { relaunch = !!st.relaunch; break }
    }
  } finally {
    await endSession(st)
    send({ t: 'bye', relaunch })
    // La entrada sigue abierta si quien salió fue la propia sesión (`q`, o tras actualizar):
    // sin soltarla, el proceso se quedaba vivo esperando líneas que ya nadie iba a leer.
    input.pause()
    input.destroy?.()
  }
}
