/**
 * qr.js — genera un QR como SVG en el cliente con la librería estándar del
 * ecosistema (`qrcode-generator`, la misma que usa el vault para su QR de
 * emparejamiento y `dotrino-qrgenerator`). Sin JS de terceros en runtime: dibuja
 * los módulos como <rect> en un SVG, negro sobre blanco con zona de silencio, así
 * es escaneable con cualquier tema (el fondo blanco no depende del tema oscuro).
 */
import qrcode from 'qrcode-generator'

// UTF-8 para el modo byte (el payload lleva un JWK con caracteres variados).
try { qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'] } catch {}

/**
 * Devuelve un string SVG que codifica `text`.
 * @param {string} text          contenido a codificar
 * @param {object} [opts]
 * @param {'L'|'M'|'Q'|'H'} [opts.ecc='L']  nivel de corrección de errores
 * @param {number} [opts.margin=4]          zona de silencio en módulos (mín. 4)
 */
export function qrSvg (text, { ecc = 'L', margin = 4 } = {}) {
  const qr = qrcode(0, ecc) // versión 0 = automática según el tamaño del dato
  qr.addData(text)
  qr.make()
  const n = qr.getModuleCount()
  const dim = n + margin * 2
  let rects = ''
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) rects += `<rect x="${c + margin}" y="${r + margin}" width="1" height="1"/>`
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" ` +
    `shape-rendering="crispEdges" role="img" aria-label="QR"><rect width="${dim}" height="${dim}" ` +
    `fill="#fff"/><g fill="#000">${rects}</g></svg>`
}
