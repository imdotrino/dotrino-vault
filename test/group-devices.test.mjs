/**
 * UN APARATO, UNA FILA. El daemon lleva la cuenta por CERTIFICADO (correcto: revocar es
 * revocar un papel), pero renovar emite uno nuevo cada 30 días — así que sin agrupar, un
 * aparato de un año sale doce veces, y los certificados ya retirados seguían contando
 * como dispositivos enrolados. Es lo que el dueño vio: «sigo viendo dos dispositivos».
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { groupCertsByDevice } from '../src/vaultControl.js'

const cert = (sub, nonce, days, extra = {}) => ({ sub, nonce, exp: Date.now() + days * 864e5, label: 'pc-local', ...extra })

test('las renovaciones del mismo aparato son UNA fila, con todos sus nonces', () => {
  const r = groupCertsByDevice([cert('K1', 'viejo', 5), cert('K1', 'nuevo', 30)], [])
  assert.equal(r.length, 1, 'un aparato, una fila')
  assert.equal(r[0].nonce, 'nuevo', 'se queda el certificado más nuevo')
  assert.deepEqual(new Set(r[0].nonces), new Set(['viejo', 'nuevo']), 'y se guardan todos, que es lo que hace falta para retirarlo entero')
})

test('un certificado revocado ya no cuenta como dispositivo enrolado', () => {
  // Exactamente el caso del dueño: dos certs, el viejo revocado, y salían dos aparatos.
  const r = groupCertsByDevice([cert('K1', 'viejo', 5), cert('K1', 'nuevo', 30)], [{ nonce: 'viejo' }])
  assert.equal(r.length, 1)
  assert.deepEqual(r[0].nonces, ['nuevo'], 'el revocado no viaja: revocarlo otra vez no tiene sentido')

  // Y si TODOS sus certificados están revocados, el aparato desaparece de la lista.
  assert.equal(groupCertsByDevice([cert('K1', 'a', 5)], [{ nonce: 'a' }]).length, 0)
  assert.equal(groupCertsByDevice([cert('K1', 'a', 5, { revokedAt: Date.now() })], []).length, 0, 'también por la marca del propio registro')
})

test('aparatos distintos siguen siendo filas distintas', () => {
  const r = groupCertsByDevice([cert('K1', 'a', 30), cert('K2', 'b', 30)], [])
  assert.equal(r.length, 2)
})

test('sin `sub` no se fusiona nada (un cert suelto es su propia fila)', () => {
  const r = groupCertsByDevice([cert(null, 'a', 30), cert(null, 'b', 30)], [])
  assert.equal(r.length, 2, 'agrupar por una llave que no existe los juntaría a todos')
})

test('revoked puede venir como lista de cadenas o de objetos', () => {
  assert.equal(groupCertsByDevice([cert('K1', 'a', 5)], ['a']).length, 0)
  assert.equal(groupCertsByDevice([cert('K1', 'a', 5)], [{ nonce: 'a' }]).length, 0)
})
