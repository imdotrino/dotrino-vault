/**
 * `join` TIENE QUE TRAGAR LA INVITACIÓN QUE `pair` EMITE HOY.
 *
 * Esto estaba roto de punta a punta y no había prueba que lo dijera: los dos caminos de
 * `join` —el comando y `DOTRINO_JOIN` del despliegue— exigían `qr.iss`, y la invitación
 * CORTA no lo lleva. La llave dejó de viajar cuando el QR se acortó (`lib/src/invite.js`):
 * ahora va una CITA del proxio (`conn`) que el aparato canjea.
 *
 * O sea que el multivault entero —una segunda bóveda entrando en tu cuenta— no se podía
 * montar: `pair` imprimía una invitación que `join` rechazaba.
 *
 * Se prueba contra la invitación DE VERDAD, la que produce `encodeInvite`, no una a mano.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeInvite, parseInvite, inviteUrl } from '../lib/src/invite.js'

/** La regla, tal cual la aplican `ctl.js#cmdJoin` y `daemon.js#bootstrapJoin`. */
const sirve = (qr) => !!(qr?.sn && (qr?.conn || qr?.iss))

test('la invitación CORTA (la de hoy) vale para join', () => {
  // Como la emite `pair`: cita del proxio + nonce de sesión, sin la llave.
  const corta = parseInvite(encodeInvite({ v: 2, conn: 'C5W4FF', sn: 'a1b2c3d4e5f6a1b2', m: 'join', proxy: 'wss://proxy.dotrino.com' }))
  assert.equal(corta.iss, undefined, 'la corta NO lleva la llave: ese era el malentendido')
  assert.ok(corta.conn && corta.sn)
  assert.equal(sirve(corta), true, 'y aun así vale: `enrollDevice` canjea la cita')
})

test('la invitación LARGA sigue valiendo (las ya emitidas no se rompen)', () => {
  const iss = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43), key_ops: ['verify'], ext: true })
  const larga = parseInvite(encodeInvite({ v: 2, iss, proxy: 'wss://proxy.dotrino.com', token: 'ab'.repeat(8), sn: 'cd'.repeat(8), m: 'join' }))
  assert.ok(larga.iss && larga.sn)
  assert.equal(sirve(larga), true)
})

test('lo que NO alcanza se sigue rechazando', () => {
  assert.equal(sirve(null), false)
  assert.equal(sirve({}), false)
  assert.equal(sirve({ sn: 'x' }), false, 'sin cita ni llave no hay a quién ir')
  assert.equal(sirve({ conn: 'C5W4FF' }), false, 'sin nonce de sesión no hay emparejamiento')
})

test('y el enlace que se pega en el navegador se entiende igual', () => {
  const qr = { v: 2, conn: 'C5W4FF', sn: 'a1b2c3d4e5f6a1b2', m: 'join', proxy: 'wss://proxy.dotrino.com' }
  const url = inviteUrl(qr)
  assert.ok(url.startsWith('https://vault.dotrino.com/d#v='))
  assert.equal(sirve(parseInvite(url)), true, 'se pega la línea entera, con https y todo')
})
