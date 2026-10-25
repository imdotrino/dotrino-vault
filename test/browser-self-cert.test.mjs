/**
 * LA BÓVEDA DEL NAVEGADOR NO FIRMA SOLA.
 *
 * La consola de la pestaña administra su bóveda con un papel que la llave del perfil se
 * firma a sí misma. Se rehacía cada minuto aunque nada cambiara: una firma desatendida cada
 * sesenta segundos, y cada una retiraba la anterior en el registro de papeles. Regla del
 * dueño (2026-10-25): se vuelve a firmar solo cuando el acta o los permisos cambian.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { selfCertIssuer } from '../lib/src/browser.js'

const ME = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' })

function fakeIdentity (acta) {
  const state = { acta, signed: 0 }
  return {
    state,
    profileActa: async () => (state.acta ? { acta: state.acta } : null),
    signDelegation: async (sub, scope) => { state.signed++; return { cert: { sub, scope, n: state.signed } } }
  }
}

test('con la misma acta no se vuelve a firmar', async () => {
  const id = fakeIdentity({ seq: 3, members: [{ pub: ME, caps: ['admin'] }] })
  const next = selfCertIssuer({ identity: id, master: ME })
  const a = await next()
  const b = await next()
  const c = await next()
  assert.equal(id.state.signed, 1)
  assert.equal(a, b)
  assert.equal(b, c)
})

test('un acta nueva o un permiso distinto sí firman otra vez', async () => {
  const id = fakeIdentity({ seq: 3, members: [{ pub: ME, caps: ['admin'] }] })
  const next = selfCertIssuer({ identity: id, master: ME })
  await next()
  id.state.acta = { seq: 4, members: [{ pub: ME, caps: ['admin'] }] }
  await next()
  assert.equal(id.state.signed, 2)
  id.state.acta = { seq: 4, members: [{ pub: ME, caps: ['admin', 'sign'] }] }
  await next()
  assert.equal(id.state.signed, 3)
})

test('sin acta, o sin permisos en ella, no hay papel y no se firma', async () => {
  const id = fakeIdentity(null)
  const next = selfCertIssuer({ identity: id, master: ME })
  assert.equal(await next(), null)
  id.state.acta = { seq: 1, members: [] }
  assert.equal(await next(), null)
  assert.equal(id.state.signed, 0)
})
