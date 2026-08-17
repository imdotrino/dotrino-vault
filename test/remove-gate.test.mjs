/**
 * Freno D12: la bóveda no borra una cuenta que ELLA manda si quedan otros miembros.
 * Solo aplica cuando el vault es master —que es el caso que puede pasar (D5: la
 * intención es justo esa)—; en cualquier otro, borrar sigue siendo libre.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { assertCanRemove } from '../src/manager.js'

test('master con otros miembros: NO se puede borrar', () => {
  let e = null
  try { assertCanRemove({ isMaster: true, memberCount: 3, name: 'Personal' }) } catch (err) { e = err }
  assert.ok(e, 'tenía que frenar')
  assert.equal(e.code, 'MASTER_WITH_MEMBERS')
  assert.match(e.message, /Personal/)
  assert.match(e.message, /2 more device/) // los OTROS, no el total
})

test('master solo (es el único miembro): se borra sin más', () => {
  assert.equal(assertCanRemove({ isMaster: true, memberCount: 1, name: 'x' }), true)
})

test('cuenta sin acta todavía (cero miembros): se borra', () => {
  assert.equal(assertCanRemove({ isMaster: false, memberCount: 0, name: 'x' }), true)
  assert.equal(assertCanRemove({ isMaster: true, memberCount: 0, name: 'x' }), true)
})

test('NO es master: el freno no aplica aunque haya muchos miembros', () => {
  // Manda otro dispositivo: borrar aquí se lleva la llave de esta bóveda y su copia,
  // pero la cuenta sigue viva donde vive el master.
  assert.equal(assertCanRemove({ isMaster: false, memberCount: 5, name: 'x' }), true)
})
