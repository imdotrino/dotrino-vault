/**
 * term.js — toolkit de terminal a pantalla completa, SIN dependencias.
 *
 * Dibuja con escapes ANSI y lee el teclado en raw mode (mismo enfoque que el
 * lector de contraseña de la CLI, `ctl.js`). No usamos librerías de terceros: el
 * vault custodia la maestra y su superficie de dependencias se mantiene mínima
 * (regla de cadena de suministro, CONVENCIONES §1.1).
 *
 * API:
 *   const term = createTerm()
 *   term.size() -> { cols, rows }
 *   await term.readKey() -> { name, ch? }   (up/down/left/right/enter/backspace/
 *                                            escape/tab/char/ctrl-c/…/resize)
 *   term.render(lines)   // lines: string[]; posiciona, recorta y limpia el resto
 *   term.close()         // restaura el terminal SIEMPRE (idempotente)
 *   term.t              // helpers de estilo/ancho (ver `theme`)
 */

import { StringDecoder } from 'node:string_decoder'

const ESC = '\x1b'
const CSI = ESC + '['

const supportsColor = () =>
  process.stdout.isTTY && process.env.NO_COLOR == null && process.env.TERM !== 'dumb'

// -------- ancho visible (ignora escapes ANSI, cuenta emojis/CJK como 2) --------

const ANSI_RE = /\x1b\[[0-9;?]*[A-Za-z]/g
export const stripAnsi = (s) => String(s).replace(ANSI_RE, '')

function charWidth (cp) {
  if (cp === 0) return 0
  if (cp < 32 || (cp >= 0x7f && cp < 0xa0)) return 0
  if (cp >= 0x300 && cp <= 0x36f) return 0 // combinantes
  if (cp === 0x200d || cp === 0xfe0f || cp === 0xfe0e) return 0 // ZWJ + selectores de variación
  if (
    (cp >= 0x1100 && cp <= 0x115f) ||
    (cp >= 0x231a && cp <= 0x231b) || // ⌚⌛
    (cp >= 0x23e9 && cp <= 0x23fa) || // ⏩…⏺ (incluye ⏳ reloj de arena)
    (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) ||
    (cp >= 0xac00 && cp <= 0xd7a3) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) ||
    (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) ||
    (cp >= 0x1f000 && cp <= 0x1faff) ||
    (cp >= 0x2600 && cp <= 0x27bf) // símbolos misc + dingbats (✓ ✗ ⚠ …)
  ) return 2
  return 1
}

/** Ancho visible de una string (sin contar escapes ANSI). */
export function widthOf (s) {
  let w = 0
  for (const ch of stripAnsi(s)) w += charWidth(ch.codePointAt(0))
  return w
}

/** Recorta a `max` columnas visibles, preservando escapes y cerrando color. */
export function trunc (s, max) {
  if (max <= 0) return ''
  let out = ''
  let w = 0
  let hadStyle = false
  let i = 0
  const str = String(s)
  while (i < str.length) {
    if (str[i] === '\x1b') {
      const m = str.slice(i).match(/^\x1b\[[0-9;?]*[A-Za-z]/)
      if (m) { out += m[0]; hadStyle = true; i += m[0].length; continue }
    }
    const cp = str.codePointAt(i)
    const ch = String.fromCodePoint(cp)
    const cw = charWidth(cp)
    if (w + cw > max) { out += hadStyle ? CSI + '0m' : ''; return out }
    out += ch; w += cw; i += ch.length
  }
  return out
}

/** Rellena con espacios hasta `width` columnas visibles (para barras sólidas). */
export function padEnd (s, width) {
  const w = widthOf(s)
  return w >= width ? trunc(s, width) : s + ' '.repeat(width - w)
}

// ------------------------------- tema/estilos -------------------------------

export function makeTheme () {
  const on = supportsColor()
  const sgr = (...c) => (on ? CSI + c.join(';') + 'm' : '')
  const R = on ? CSI + '0m' : ''
  const wrap = (open) => (s) => on ? open + s + R : s
  return {
    on,
    reset: R,
    bold: wrap(sgr(1)),
    dim: wrap(sgr(2)),
    accent: wrap(sgr(38, 5, 44)), // cian
    ok: wrap(sgr(38, 5, 114)), // verde
    warn: wrap(sgr(38, 5, 214)), // ámbar
    danger: wrap(sgr(38, 5, 203)), // rojo
    muted: wrap(sgr(38, 5, 244)), // gris
    title: wrap(sgr(1) + sgr(38, 5, 81)),
    /**
     * Barra sólida a todo lo ancho (header/ayuda). Se le quita el color interno:
     * un `\x1b[0m` intermedio cortaría el fondo a media línea.
     */
    bar: (text, cols) => {
      const body = padEnd(' ' + stripAnsi(text), cols) // padEnd RECORTA si excede (ancho visible)
      return on ? sgr(48, 5, 236) + sgr(38, 5, 252) + body + R : body
    },
    /**
     * Fila seleccionada de una lista: fondo uniforme a todo lo ancho. Se quita el
     * color interno del texto para que ningún reset intermedio corte el resaltado.
     */
    sel: (text, cols) => {
      const body = padEnd(stripAnsi(text), cols)
      return on ? sgr(48, 5, 24) + sgr(38, 5, 231) + body + R : CSI + '7m' + body + CSI + '0m'
    }
  }
}

// --------------------------------- teclado ----------------------------------

function parseChunk (s, push) {
  let i = 0
  const arrow = { A: 'up', B: 'down', C: 'right', D: 'left', H: 'home', F: 'end' }
  while (i < s.length) {
    const c = s[i]
    if (c === '\x1b') {
      const n = s[i + 1]
      if ((n === '[' || n === 'O')) {
        const third = s[i + 2]
        if (arrow[third]) { push({ name: arrow[third] }); i += 3; continue }
        if (/[0-9]/.test(third)) {
          let j = i + 2; let num = ''
          while (j < s.length && /[0-9;]/.test(s[j])) { num += s[j]; j++ }
          const fin = s[j]
          const seq = { 3: 'delete', 5: 'pageup', 6: 'pagedown', 1: 'home', 4: 'end' }
          if (fin === '~' && seq[num]) { push({ name: seq[num] }); i = j + 1; continue }
          i = (fin ? j + 1 : s.length); continue
        }
        i += 3; continue
      }
      push({ name: 'escape' }); i += 1; continue
    }
    if (c === '\r' || c === '\n') { push({ name: 'enter' }); i += 1; if (c === '\r' && s[i] === '\n') i += 1; continue }
    if (c === '\x7f' || c === '\b') { push({ name: 'backspace' }); i += 1; continue }
    if (c === '\t') { push({ name: 'tab' }); i += 1; continue }
    if (c === '\x03') { push({ name: 'ctrl-c' }); i += 1; continue }
    if (c === '\x04') { push({ name: 'ctrl-d' }); i += 1; continue }
    if (c === '\x15') { push({ name: 'ctrl-u' }); i += 1; continue }
    if (c === '\x17') { push({ name: 'ctrl-w' }); i += 1; continue }
    if (c.charCodeAt(0) < 32) { i += 1; continue }
    const cp = s.codePointAt(i)
    const ch = String.fromCodePoint(cp)
    push({ name: 'char', ch }); i += ch.length
  }
}

// -------------------------------- terminal ----------------------------------

export function createTerm () {
  const out = process.stdout
  const inp = process.stdin
  const t = makeTheme()

  // Cola de teclas + notificador. Las teclas SIEMPRE se encolan (no se pierden
  // aunque venza un tick): `readKey(ms)` drena la cola o despierta por timeout.
  const queue = []
  let notify = null
  const push = (k) => { queue.push(k); if (notify) { const n = notify; notify = null; n() } }

  // Entrada de teclado robusta ante fragmentación (SSH / ptys lentas):
  //  · StringDecoder reensambla caracteres UTF-8 multibyte partidos entre chunks.
  //  · Una secuencia de escape incompleta al final del chunk se GUARDA y se
  //    antepone al siguiente; un ESC solitario se emite tras un breve timeout.
  const decoder = new StringDecoder('utf8')
  let pendingEsc = ''
  let escTimer = null
  const clearEscTimer = () => { if (escTimer) { clearTimeout(escTimer); escTimer = null } }
  // Devuelve el índice donde empieza una secuencia de escape INCOMPLETA al final
  // de `s` (para retenerla), o -1 si no hay nada que retener.
  const incompleteTailStart = (s) => {
    const k = s.lastIndexOf('\x1b')
    if (k < 0) return -1
    const tail = s.slice(k)
    if (tail === '\x1b') return k // ESC pelado
    if (tail[1] === '[') return /[A-Za-z~]/.test(tail.slice(2)) ? -1 : k // CSI sin byte final
    if (tail[1] === 'O') return tail.length >= 3 ? -1 : k // SS3 sin byte final
    return -1 // ESC + otra cosa: que lo maneje parseChunk ya mismo
  }
  const handleInput = (str) => {
    clearEscTimer()
    let s = pendingEsc + str
    pendingEsc = ''
    const hold = incompleteTailStart(s)
    if (hold >= 0) { pendingEsc = s.slice(hold); s = s.slice(0, hold) }
    if (s) parseChunk(s, push)
    if (pendingEsc) {
      // Si nada más llega pronto, era un ESC de verdad (tecla Escape).
      escTimer = setTimeout(() => { escTimer = null; if (pendingEsc) { pendingEsc = ''; push({ name: 'escape' }) } }, 50)
      escTimer.unref?.()
    }
  }

  const onData = (buf) => handleInput(decoder.write(buf))
  const onResize = () => push({ name: 'resize' })

  let closed = false
  const write = (s) => { try { out.write(s) } catch (_) {} }

  function open () {
    write(CSI + '?1049h') // pantalla alterna
    write(CSI + '?25l') // ocultar cursor
    write(CSI + '2J' + CSI + 'H')
    if (inp.isTTY) inp.setRawMode(true)
    inp.resume()
    inp.on('data', onData)
    out.on('resize', onResize)
  }

  function close () {
    if (closed) return
    closed = true
    clearEscTimer()
    try { inp.off('data', onData) } catch (_) {}
    try { out.off('resize', onResize) } catch (_) {}
    if (inp.isTTY) { try { inp.setRawMode(false) } catch (_) {} }
    try { inp.pause() } catch (_) {}
    write(CSI + '?25h') // mostrar cursor
    write(CSI + '?1049l') // salir de pantalla alterna
  }

  // Red de seguridad: restaurar el terminal pase lo que pase (salida normal,
  // señales de terminación y cierre del terminal —SIGHUP—). En raw mode Ctrl-C
  // llega como \x03 y lo maneja el loop; el manejador de SIGINT es un respaldo.
  const onExit = () => close()
  process.on('exit', onExit)
  const onKill = (sig, code) => { close(); process.exit(code) }
  process.on('SIGTERM', () => onKill('SIGTERM', 0))
  process.on('SIGHUP', () => onKill('SIGHUP', 129))
  process.on('SIGINT', () => onKill('SIGINT', 130))

  open()

  return {
    t,
    size () { return { cols: out.columns || 80, rows: out.rows || 24 } },
    /**
     * Espera la próxima tecla. Con `ms`, despierta también por timeout devolviendo
     * `{ name: 'tick' }` (para refrescar pantallas que esperan un evento externo).
     */
    async readKey (ms = 0) {
      if (queue.length) return queue.shift()
      let timer = null
      await new Promise((res) => {
        notify = res
        if (ms > 0) timer = setTimeout(() => { if (notify) { notify = null; res() } }, ms)
      })
      if (timer) clearTimeout(timer)
      return queue.length ? queue.shift() : { name: 'tick' }
    },
    /** Dibuja `lines` desde arriba; recorta al ancho y limpia lo que sobre. */
    render (lines) {
      const { cols } = this.size()
      let s = CSI + 'H'
      for (let i = 0; i < lines.length; i++) {
        s += CSI + (i + 1) + ';1H' + trunc(lines[i] ?? '', cols) + t.reset + CSI + 'K'
      }
      s += CSI + 'J' // limpia de la última línea hacia abajo
      write(s)
    },
    close
  }
}
