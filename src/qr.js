/**
 * qr.js — render de un QR en la terminal con bloques Unicode.
 *
 * Usa el encoder QR `qrcode-generator` (MIT, Kazuhiko Arase) VENDORIZADO en
 * `vendor/qrcode-generator.cjs`: JS puro, sin red ni telemetría, y se empaqueta
 * dentro del binario SEA (regla de privacidad del ecosistema: nada de JS de
 * terceros cargado en runtime, todo va embebido). No reimplementamos el QR a mano.
 *
 * Render con medio bloque por carácter: un QR es "alto", así que dibujamos dos
 * filas de módulos por línea de texto con ▀▄█/espacio.
 */
// Import estático del encoder vendorizado (UMD/CJS). Así esbuild lo INLINE-a en
// el binario SEA y en dev funciona por el interop ESM↔CJS de Node.
import qrcodeMod from '../vendor/qrcode-generator.cjs'

const qrcode = typeof qrcodeMod === 'function' ? qrcodeMod : qrcodeMod.default

/**
 * Devuelve una string con el QR en bloques Unicode, lista para imprimir.
 * @param {string} text  Contenido a codificar (modo byte / UTF-8).
 * @param {number} [quiet=2]  Quiet zone en módulos.
 */
export function qrToString (text, quiet = 2) {
  // typeNumber 0 = autoseleccionar la versión mínima; EC level 'L' (más capacidad).
  const qr = qrcode(0, 'L')
  qr.addData(text) // 'Byte' por defecto para datos no numéricos/alfanuméricos
  qr.make()

  const n = qr.getModuleCount()
  const N = n + quiet * 2
  const dark = (r, c) => {
    const rr = r - quiet; const cc = c - quiet
    if (rr < 0 || cc < 0 || rr >= n || cc >= n) return false
    return qr.isDark(rr, cc)
  }

  let out = ''
  for (let r = 0; r < N; r += 2) {
    for (let c = 0; c < N; c++) {
      const top = dark(r, c)
      const bot = r + 1 < N ? dark(r + 1, c) : false
      // En terminal de fondo claro: módulo oscuro = carácter "lleno".
      if (top && bot) out += '█'
      else if (top && !bot) out += '▀'
      else if (!top && bot) out += '▄'
      else out += ' '
    }
    out += '\n'
  }
  return out
}
