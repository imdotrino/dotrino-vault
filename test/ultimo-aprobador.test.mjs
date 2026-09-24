/**
 * LA LIMPIEZA QUE SE LLEVA AL ÚLTIMO APROBADOR SE DICE ALTO (2026-09-24).
 *
 * El 2026-09-22 la limpieza de aparatos muertos quitó al único teléfono con `aprueba` de la
 * cuenta Dotrino. Quitarlo era correcto (su papel ya no podía firmar nada), pero pasó en
 * silencio: dos días de pedidos rechazados sin que nadie supiera por qué.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { lastApproverGone } from '../src/approvals.js'

test('había aprobadores, la limpieza se llevó el último: se dice cuál', () => {
  assert.deepEqual(lastApproverGone(['TEL'], [], ['TEL', 'CLI']), ['TEL'])
})

test('queda alguno que aprueba: no hay nada que avisar', () => {
  assert.deepEqual(lastApproverGone(['TEL', 'NUEVO'], ['NUEVO'], ['TEL']), [])
})

test('una cuenta que nunca tuvo aprobadores es legítima (todo desatendido): no se avisa', () => {
  assert.deepEqual(lastApproverGone([], [], ['CLI']), [])
})

test('sin aprobadores ahora pero no por la limpieza (se quitó a mano antes): no se le atribuye', () => {
  assert.deepEqual(lastApproverGone(['TEL'], [], ['CLI']), [])
})
