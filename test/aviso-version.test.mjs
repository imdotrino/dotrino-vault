/**
 * QUIÉN DECIDE QUE LA BÓVEDA SE ACTUALICE (§15, regla del dueño del 2026-09-20).
 *
 * La bóveda es la pieza sensible: quien le cuele una actualización se lleva la maestra, y
 * eso no se rota — se pierde la cuenta. Así que no se actualiza sola **mientras haya quien
 * apruebe**, igual que ya pasa con las claves privadas.
 *
 * Y la otra mitad de la regla, que es la que evita la trampa: si NO hay ningún aparato con
 * `aprueba`, esperar un sí que nadie puede dar la condenaría a no actualizarse nunca. Sin
 * aprobadores, se actualiza sola.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { isNewer } from '../src/update.js'

/** La decisión, tal como la toma el daemon. */
const pideraPermiso = (aprobadores) => aprobadores.length > 0

test('con aprobadores, la bóveda NO se actualiza sola', () => {
  assert.equal(pideraPermiso([{ id: 'AB12-CD34', label: 'teléfono' }]), true)
})

test('sin aprobadores se actualiza sola: nadie puede decir que sí', () => {
  assert.equal(pideraPermiso([]), false,
    'esperar una aprobación imposible la deja sin actualizar para siempre')
})

/**
 * Y lo de siempre con las versiones: comparar tres números, no texto. `0.99.0` no es más
 * nueva que `0.100.0`, y creerlo deja una máquina atrás convencida de estar al día.
 */
test('99 no es mayor que 100', () => {
  assert.equal(isNewer('0.100.0', '0.99.0'), true)
  assert.equal(isNewer('0.99.0', '0.100.0'), false)
  assert.equal(isNewer('0.123.1', '0.123.0'), true)
})
