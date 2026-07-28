/**
 * invite.js — la invitación de emparejamiento: cómo se escribe y cómo se lee.
 *
 * Un emparejamiento viaja de dos maneras, y cada una quiere una codificación
 * distinta:
 *
 *   · **El QR / el enlace** → JSON CRUDO (`j`). Nadie lo lee con los ojos y cada
 *     carácter cuenta: el base64 infla el payload un 33 % y eso son módulos de más
 *     en el QR (~8 columnas y 4 filas de terminal). Va crudo.
 *   · **El código que se copia y se pega** → base64url (`b`). Ahí sí lo manipula
 *     una persona: una sola palabra sin comillas, llaves ni espacios, que sobrevive
 *     a un doble clic, a un chat y a un campo de texto.
 *
 * Para que el lector no tenga que ADIVINAR cuál de las dos le llegó, el payload
 * empieza por una **marca de formato** de un carácter (`j` o `b`). Sin marca se
 * asume el formato viejo (base64url, y si no, JSON), solo por compatibilidad con
 * los enlaces que ya salieron.
 *
 * GOTCHA que justifica la mitad de este archivo: el JSON crudo lleva `{`, `}` y
 * `"`, que **no son legales en una URI**. Al abrir el enlace, el navegador los
 * percent-codifica (`%22`…), así que lo que llega a `location.hash` NO es el JSON
 * que se emitió. Medido en un navegador real (2026-07-28). Por eso se
 * `decodeURIComponent` antes de parsear: sin eso, el QR daba «ese código no vale».
 */

export const FMT_JSON = 'j'
export const FMT_B64 = 'b'

const b64urlEncode = (s) => {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  const raw = typeof btoa === 'function' ? btoa(bin) : Buffer.from(s, 'utf8').toString('base64')
  return raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const b64urlDecode = (s) => {
  const b = s.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b + '='.repeat((4 - b.length % 4) % 4)
  if (typeof atob === 'function') {
    const bin = atob(pad)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  }
  return Buffer.from(pad, 'base64').toString('utf8')
}

/** El payload marcado, listo para meter en el `#fragment` o para copiar y pegar. */
export function encodeInvite (qr, fmt = FMT_B64) {
  const json = JSON.stringify(qr)
  return fmt === FMT_JSON ? FMT_JSON + json : FMT_B64 + b64urlEncode(json)
}

/** Una URL sin percent-encodear rompe el `#`: el fragmento se corta ahí. */
const cutFragment = (text) => {
  const i = text.indexOf('#vault=')
  return i >= 0 ? text.slice(i + 7) : text
}

/**
 * Lee una invitación venga como venga: URL con `#vault=…`, el código suelto, con
 * marca de formato o sin ella (formatos viejos). Devuelve el objeto del QR o
 * `null` — nunca lanza, porque del otro lado hay alguien pegando texto a mano.
 */
export function parseInvite (text) {
  if (!text) return null
  const payload = cutFragment(String(text).trim())
  if (!payload) return null

  const parse = (s) => { try { const o = JSON.parse(s); return (o && typeof o === 'object') ? o : null } catch { return null } }
  // El navegador percent-codifica el JSON del fragmento; deshacerlo es un no-op si
  // no lo tocó. Si el texto trae un `%` suelto, `decodeURIComponent` lanza: se usa
  // el original.
  const undoUrl = (s) => { try { return decodeURIComponent(s) } catch { return s } }

  const marca = payload[0]
  const resto = payload.slice(1)
  if (marca === FMT_JSON) return parse(undoUrl(resto)) || parse(resto)
  if (marca === FMT_B64) { try { return parse(b64urlDecode(resto)) } catch { return null } }

  // --- sin marca: formatos anteriores a la marca de formato (compatibilidad) ---
  const crudo = undoUrl(payload)
  if (crudo.trimStart().startsWith('{')) return parse(crudo)
  try { return parse(b64urlDecode(payload)) } catch { return null }
}

export default { encodeInvite, parseInvite, FMT_JSON, FMT_B64 }
