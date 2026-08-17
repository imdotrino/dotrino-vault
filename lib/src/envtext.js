/**
 * Lector de `.env` — el formato en el que la gente YA tiene la configuración de un
 * servicio, y por lo tanto la forma natural de cargarla entera de una vez.
 *
 * Existe aquí, en la lib pura, porque lo usan los tres sitios desde los que se cargan
 * variables: el CLI (`secret import`), la TUI y la consola remota (pegar el bloque en
 * la web). Tres lectores distintos serían tres formatos distintos.
 *
 * POR QUÉ ESTO IMPORTA MÁS DE LO QUE PARECE: cada variable guardada suelta es, para la
 * bóveda, un cambio de configuración, y el servicio obedece el primero —sale y lo
 * levanta su supervisor— mientras el dueño sigue tecleando las demás. Cargarlas juntas
 * es lo que hace que el servicio se reinicie UNA vez, con todo puesto.
 *
 * Los errores salen como CÓDIGOS, no como frases: quien llama los traduce (el CLI en
 * español, la consola en los dos idiomas).
 */
import { isValidVarKey } from './protocol.js'

/**
 * `CLAVE=valor` — la clave no lleva espacios ni `=`; el valor puede llevar de todo. Se
 * toleran los espacios alrededor del `=` porque un `.env` escrito a mano los trae, y
 * rechazar un archivo entero por eso sería quisquilloso sin ganar nada.
 */
export const PAIR_RE = /^([^=\s]+)\s*=\s*([\s\S]*)$/

/**
 * @param {string} text
 * @returns {{items: Array<{op:'set', key:string, value:string}>,
 *            errors: Array<{code:'shape'|'dup'|'key'|'novalue'|'empty', line?:number, key?:string, first?:number}>}}
 */
export function parseEnvText (text) {
  /** @type {Array<{op:'set', key:string, value:string}>} */
  const items = []
  /** @type {Array<{code:'shape'|'dup'|'key'|'novalue'|'empty', line?:number, key?:string, first?:number}>} */
  const errors = []
  const seen = new Map()
  const lines = String(text || '').split(/\r?\n/)

  lines.forEach((raw, idx) => {
    const line = idx + 1
    const trimmed = raw.trim()
    // Línea vacía o comentario entero. Un `#` a MITAD de línea NO se corta: una
    // contraseña puede llevarlo, y recortar el valor ahí lo estropea en silencio —que
    // en un secreto significa un servicio que no levanta y nadie sabe por qué.
    if (!trimmed || trimmed.startsWith('#')) return
    const m = PAIR_RE.exec(trimmed.replace(/^export\s+/, ''))
    if (!m) return errors.push({ code: 'shape', line })

    const key = m[1]
    const value = unquote(m[2].trim())
    if (!isValidVarKey(key)) return errors.push({ code: 'key', line, key })
    if (!value) return errors.push({ code: 'novalue', line, key })
    // Repetida = casi siempre un pegado a medias. Adivinar cuál de las dos quería el
    // dueño no es asunto de un lector de configuración.
    if (seen.has(key)) return errors.push({ code: 'dup', line, key, first: seen.get(key) })
    seen.set(key, line)
    items.push({ op: 'set', key, value })
  })

  if (!items.length && !errors.length) errors.push({ code: 'empty' })
  return { items, errors }
}

/**
 * Lo mismo, pero aceptando que todo venga en UNA línea (`K=v K2=v2`), que es lo que se
 * puede escribir en un campo de una sola línea como el de la TUI. Un valor con espacios
 * va entre comillas, igual que en la shell.
 */
export function parseEnvInput (text) {
  const s = String(text || '')
  return parseEnvText(/\r?\n/.test(s) ? s : tokenize(s).join('\n'))
}

/** Parte por espacios, pero no dentro de comillas. */
function tokenize (line) {
  const out = []
  let cur = ''
  let quote = null
  for (const ch of line) {
    if (quote) { cur += ch; if (ch === quote) quote = null; continue }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; continue }
    if (/\s/.test(ch)) { if (cur) { out.push(cur); cur = '' } ; continue }
    cur += ch
  }
  if (cur) out.push(cur)
  return out
}

/** Quita las comillas de FUERA: un `.env` las usa cuando el valor lleva espacios. */
function unquote (v) {
  const q = v[0]
  if (v.length > 1 && (q === '"' || q === "'") && v.endsWith(q)) return v.slice(1, -1)
  return v
}
