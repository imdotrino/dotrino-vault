/**
 * `lib/src/revocation.js` — cuándo la bóveda le dice a un aparato que ya no es de casa.
 *
 * Lo que se prueba aquí es la frontera, que tiene dos lados y los dos duelen:
 *
 *   · si se avisa de MENOS, el aparato quitado se queda enseñando una cuenta que ya no
 *     existe (no hay otra forma de que se entere: solo lo borra el aviso FIRMADO);
 *   · si se avisa de MÁS, un aparato de casa con el papel viejo se borra solo — que es lo
 *     que pasó al dar «administra»: cambiar permisos obliga a renovar, renovar retira el
 *     certificado anterior, y ese «retirado» se leía como «estás fuera».
 *
 * El árbitro es EL ACTA, y solo el acta.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { shouldNotifyRevoked, isStalePaper, STALE_PAPER } from '../lib/src/revocation.js'

const MASTER = 'MPUB'
const DEV = 'DPUB'
const base = { reason: 'revoked', pubkey: DEV, master: MASTER, certIss: MASTER }

test('fuera del acta: se le avisa, y da igual por qué falló el papel', () => {
  for (const reason of STALE_PAPER) {
    assert.equal(shouldNotifyRevoked({ ...base, reason, members: [{ pub: MASTER }] }), true, reason)
  }
})

/**
 * EL CASO QUE SE ROMPIÓ ANTES. Un certificado retirado no es una expulsión: renovar retira
 * el anterior, y cambiar permisos obliga a renovar.
 */
test('sigue en el acta: NO se le avisa, aunque su certificado esté retirado o vencido', () => {
  const members = [{ pub: MASTER }, { pub: DEV }]
  for (const reason of STALE_PAPER) {
    assert.equal(shouldNotifyRevoked({ ...base, reason, members }), false, reason)
  }
})

/**
 * EL CASO QUE SE ARREGLA. Al aparato al que quitaron hace meses ya no le queda rastro en
 * las delegaciones (las revocaciones caducan, los certificados vencidos se olvidan), así
 * que buscarlo ahí no encontraba nada y no se le mandaba nada. El acta sí lo sabe: no está.
 */
test('quitado hace tanto que ya no queda rastro de su certificado: igual se le avisa', () => {
  assert.equal(shouldNotifyRevoked({
    ...base, reason: 'expired', members: [{ pub: MASTER }], knownRevoked: false
  }), true)
})

test('un papel que no firmamos nosotros no es asunto nuestro', () => {
  assert.equal(shouldNotifyRevoked({ ...base, certIss: 'OTRA-MAESTRA', members: [{ pub: MASTER }] }), false)
})

test('la maestra no se echa a sí misma', () => {
  assert.equal(shouldNotifyRevoked({ ...base, pubkey: MASTER, members: [] }), false)
})

test('motivos que no son «tu papel ya no sirve» no avisan de nada', () => {
  // Estos fallan ANTES de comprobar la firma del aparato: no hay prueba de que quien
  // escribe sea quien dice ser, así que no hay a quién avisar.
  for (const reason of ['shape', 'bad-signature', 'bad-action-signature', 'cert-device-mismatch', 'untrusted-issuer', 'no-cert']) {
    assert.equal(isStalePaper(reason), false, reason)
    assert.equal(shouldNotifyRevoked({ ...base, reason, members: [] }), false, reason)
  }
})

test('sin acta (bóveda vieja): solo se avisa a quien conste revocado', () => {
  assert.equal(shouldNotifyRevoked({ ...base, members: null, knownRevoked: true }), true)
  assert.equal(shouldNotifyRevoked({ ...base, members: null, knownRevoked: false }), false)
})

test('sin llave del aparato no hay a quién avisar', () => {
  assert.equal(shouldNotifyRevoked({ ...base, pubkey: null, members: [] }), false)
  assert.equal(shouldNotifyRevoked({ ...base, pubkey: '', members: [] }), false)
})
