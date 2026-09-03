/**
 * TIMBRAR UNA VEZ Y ESPERAR LO QUE DURA EL PEDIDO.
 *
 * Un cajón con aprobación hace sonar el teléfono en CADA petición. Con el reintento a
 * cinco segundos, un fallo posterior a la aprobación volvía a pedir enseguida y el dueño
 * veía dos avisos del mismo cajón: aprobaba el primero para nada. Pasó de verdad con
 * `aws-admin`, que tenía una variable en claro y fallaba SIEMPRE después de aprobar.
 *
 * La regla que esto fija: un reintento no llega nunca antes de que venza el pedido que ya
 * está sonando — y si el intento ya se pasó la ventana entera esperando, no se le suma
 * otra, que eso sería un cuelgue.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { retryDelay, APPROVAL_TIMEOUT_MS } from '../lib/src/service.js'

const AHORA = 1_000_000

test('si timbró, el reintento espera a que venza el pedido', () => {
  // Timbró y falló dos segundos después: queda casi toda la ventana viva.
  const espera = retryDelay(5000, AHORA - 2000, APPROVAL_TIMEOUT_MS, AHORA)
  assert.equal(espera, APPROVAL_TIMEOUT_MS - 2000)
  assert.ok(espera > 5000, 'no puede quedarse en el reintento corto de siempre')
})

test('si el pedido ya venció, no se le suma otra ventana', () => {
  const espera = retryDelay(5000, AHORA - APPROVAL_TIMEOUT_MS, APPROVAL_TIMEOUT_MS, AHORA)
  assert.equal(espera, 5000, 'vuelve al backoff normal')
})

test('un intento que tardó MÁS que la ventana tampoco espera de más', () => {
  const espera = retryDelay(5000, AHORA - APPROVAL_TIMEOUT_MS * 2, APPROVAL_TIMEOUT_MS, AHORA)
  assert.equal(espera, 5000)
})

test('sin aprobación de por medio, manda el backoff', () => {
  assert.equal(retryDelay(5000, 0, APPROVAL_TIMEOUT_MS, AHORA), 5000)
  assert.equal(retryDelay(60000, 0, APPROVAL_TIMEOUT_MS, AHORA), 60000)
})

test('el backoff gana si ya es más largo que lo que queda del pedido', () => {
  const espera = retryDelay(60000, AHORA - (APPROVAL_TIMEOUT_MS - 30000), APPROVAL_TIMEOUT_MS, AHORA)
  assert.equal(espera, 60000, 'nunca acorta un backoff ya crecido')
})
