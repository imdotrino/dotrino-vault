/**
 * El QR del emparejamiento, ESCANEADO de verdad.
 *
 * Los demás tests comprueban que la invitación es corta y que se lee de vuelta. Este
 * cierra el círculo por donde se rompe en la vida real: se genera el QR, se pinta a
 * píxeles y se DECODIFICA con un lector (jsQR, el mismo que usa la consola web para
 * leer con la cámara). Si el QR no fuera legible —zona de silencio de menos, versión
 * mal elegida, un carácter que el modo byte no aguanta—, aquí se ve, y no en un
 * teléfono a medio emparejar.
 *
 * jsQR vive en las dependencias de la web (`web/node_modules`); si no están
 * instaladas, el test se salta en vez de fallar.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { inviteUrl, parseInvite } from '../lib/src/invite.js'
import qrcodeMod from '../vendor/qrcode-generator.cjs'

const qrcode = typeof qrcodeMod === 'function' ? qrcodeMod : qrcodeMod.default
const require = createRequire(import.meta.url)

let jsQR = null
try { jsQR = require('../web/node_modules/jsqr/dist/jsQR.js') } catch (_) { /* web sin instalar */ }
if (jsQR && jsQR.default) jsQR = jsQR.default

/** Pinta el QR a un bitmap RGBA, como lo vería una cámara. */
function rasterize (text, { scale = 4, quiet = 4 } = {}) {
  const qr = qrcode(0, 'L')
  qr.addData(text)
  qr.make()
  const n = qr.getModuleCount()
  const side = (n + quiet * 2) * scale
  const data = new Uint8ClampedArray(side * side * 4).fill(255)
  for (let y = 0; y < side; y++) {
    for (let x = 0; x < side; x++) {
      const mr = Math.floor(y / scale) - quiet
      const mc = Math.floor(x / scale) - quiet
      const dark = mr >= 0 && mc >= 0 && mr < n && mc < n && qr.isDark(mr, mc)
      if (!dark) continue
      const i = (y * side + x) * 4
      data[i] = data[i + 1] = data[i + 2] = 0
    }
  }
  return { data, side, modules: n }
}

async function invitation () {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('')
  return {
    v: 2,
    iss: JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey)),
    proxy: 'wss://proxy.dotrino.com',
    token: hex(12),
    sn: hex(12),
    m: 'join',
    acct: 'Perfil 1'
  }
}

test('un lector de QR saca la invitación entera del código', { skip: !jsQR && 'jsQR no instalado (npm i en web/)' }, async () => {
  for (let i = 0; i < 5; i++) {
    const qr = await invitation()
    const url = inviteUrl(qr)
    const { data, side } = rasterize(url)
    const decoded = jsQR(data, side, side)
    assert.ok(decoded, 'el lector no encontró ningún QR')
    assert.equal(decoded.data, url, 'el lector sacó otra cosa de la que se codificó')
    assert.deepEqual(parseInvite(decoded.data), qr, 'lo escaneado no reconstruye la invitación')
  }
})

test('sigue leyéndose con el QR pequeño (2 píxeles por módulo)', { skip: !jsQR && 'jsQR no instalado (npm i en web/)' }, async () => {
  const qr = await invitation()
  const url = inviteUrl(qr)
  const { data, side, modules } = rasterize(url, { scale: 2 })
  const decoded = jsQR(data, side, side)
  assert.ok(decoded, `no se leyó a 2 px/módulo (${modules} módulos)`)
  assert.equal(decoded.data, url)
})
