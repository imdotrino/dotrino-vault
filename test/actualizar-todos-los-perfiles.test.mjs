/**
 * EL AJUSTE DE ACTUALIZACIÓN ES DE LA BÓVEDA, NO DE UN PERFIL (`src/updateApproval.js`,
 * dueño 2026-10-08): basta que un perfil tenga quien apruebe, se pide en todos, el primer sí
 * decide, y los pedidos que sobran se retiran.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { approversOfAll, firstYes } from '../src/updateApproval.js'

const perfil = (id, approvers) => ({ id, name: 'Perfil ' + id, vault: { approvers: async () => approvers } })
const pedido = () => {
  let settle
  const p = { withdrawn: false, answer: new Promise((r) => { settle = r }), withdraw () { p.withdrawn = true; settle(false) } }
  p.say = settle
  return p
}

test('los aprobadores de todos los perfiles, cada uno con el suyo', async () => {
  const todos = await approversOfAll([
    perfil('a', [{ id: 'AA11-BB22', label: 'tel', pub: 'P1', notifiedAt: 5 }]),
    perfil('b', []),
    perfil('c', [{ id: 'CC33-DD44', label: '', pub: 'P2', notifiedAt: null }])
  ])
  assert.deepEqual(todos.map((x) => [x.profile, x.profileId, x.id, x.notifiedAt]), [['Perfil a', 'a', 'AA11-BB22', 5], ['Perfil c', 'c', 'CC33-DD44', null]])
  assert.deepEqual(await approversOfAll([perfil('b', [])]), [], 'nadie aprueba en ninguno')
})

test('si un perfil no se puede leer, no hay lista a medias: se lanza', async () => {
  const roto = { id: 'x', name: 'Roto', vault: { approvers: async () => { throw new Error('record unreadable') } } }
  await assert.rejects(approversOfAll([perfil('a', [{ id: 'AA11-BB22' }]), roto]), (e) => e.code === 'approvers-unreadable' && /Roto/.test(e.message))
})

test('el primer sí basta, y los demás pedidos se retiran', async () => {
  const a = pedido(); const b = pedido(); const c = pedido()
  const r = firstYes([a, b, c])
  b.say(true)
  assert.equal(await r, true)
  assert.deepEqual([a.withdrawn, b.withdrawn, c.withdrawn], [true, false, true])
})

test('un no de un perfil no decide por los demás; es no cuando todos dijeron que no', async () => {
  const a = pedido(); const b = pedido()
  const r = firstYes([a, b])
  let resuelto = null
  r.then((v) => { resuelto = v })
  a.say(false)
  await new Promise((x) => setImmediate(x))
  assert.equal(resuelto, null, 'sigue esperando al otro perfil')
  b.say(false)
  assert.equal(await r, false)
  const d = pedido(); const e = pedido()
  const r2 = firstYes([d, e])
  d.say(false); e.say(true)
  assert.equal(await r2, true, 'un no antes no impide el sí de otro')
})

test('sin a quién pedir es no (quien llama decide antes si hacía falta pedir)', async () => {
  assert.equal(await firstYes([]), false)
})

// --- EL PEDIDO SE HACE UNA VEZ POR VERSIÓN ------------------------------------------------
// (dueño, 2026-10-08: «dura un día, pero se hace una sola vez; no se reintenta al siguiente
// día; se asume negado si no se hizo en 24 horas; se dispara nuevamente en la siguiente
// actualización».)
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { readAsked, writeAsked, clearAsked, shouldAsk, resultOfNo, ASKED_FILE } from '../src/updateApproval.js'
import { isNewer } from '../src/update.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'asked-'))
const DIA = 24 * 60 * 60 * 1000

test('nunca se preguntó: se pregunta', () => {
  assert.equal(readAsked(tmp()), null)
  assert.equal(shouldAsk(null, '0.147.0', isNewer), true)
})

test('tras denegar o vencer NO se repite por esa versión, y sí con una más nueva', () => {
  for (const result of ['denied', 'expired', 'pending']) {
    const asked = { version: '0.147.0', askedAt: 1, result }
    assert.equal(shouldAsk(asked, '0.147.0', isNewer), false, `${result}: la misma no se repite`)
    assert.equal(shouldAsk(asked, '0.146.9', isNewer), false, 'ni una anterior')
    assert.equal(shouldAsk(asked, '0.147.1', isNewer), true, 'una más nueva sí')
    assert.equal(shouldAsk(asked, '0.148.0', isNewer), true)
  }
})

test('sobrevive al reinicio: lo preguntado se lee del disco, cifrado, también a medias', () => {
  const dir = tmp()
  writeAsked(dir, { version: '0.147.0', askedAt: 1000, result: 'pending' })
  assert.ok(!fs.readFileSync(path.join(dir, ASKED_FILE), 'utf8').includes('0.147.0'), 'cifrado en reposo')
  // «Otro proceso» lo lee: un pedido a medias cuenta como ya preguntado.
  const leido = readAsked(dir)
  assert.deepEqual(leido, { version: '0.147.0', askedAt: 1000, result: 'pending' })
  assert.equal(shouldAsk(leido, '0.147.0', isNewer), false)
  writeAsked(dir, { ...leido, result: 'expired' })
  assert.equal(readAsked(dir).result, 'expired')
  clearAsked(dir)
  assert.equal(readAsked(dir), null, 'instalada: se olvida')
})

test('un archivo ilegible no es «nunca se preguntó»: se lanza', () => {
  const dir = tmp()
  writeAsked(dir, { version: '0.147.0', askedAt: 1, result: 'denied' })
  fs.writeFileSync(path.join(dir, ASKED_FILE), 'basura')
  assert.throws(() => readAsked(dir), (e) => e.code === 'asked-unreadable')
  assert.throws(() => writeAsked(dir, { version: '0.147.0', askedAt: 1, result: 'maybe' }), (e) => e.code === 'bad-asked')
})

test('un no a tiempo es una denegación; al cumplirse el día, un vencimiento', () => {
  assert.equal(resultOfNo(0, DIA, 5 * 60 * 1000), 'denied')
  assert.equal(resultOfNo(0, DIA, DIA), 'expired')
  assert.equal(resultOfNo(0, DIA, DIA + 5000), 'expired')
})
