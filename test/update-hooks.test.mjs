/**
 * LOS GANCHOS DE ACTUALIZACIÓN DE UN AGENTE (`vaultUpdateHooks`, lib/src/service.js): los
 * tres que usa `watchSelfUpdateNpm`, armados una vez. Con dobles: lo que hacen por el cable
 * lo cubre `secrets.e2e.test.mjs`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { vaultUpdateHooks } from '../lib/src/service.js'

const conn = { proxyUrl: 'wss://x', masterPubkey: 'M', device: { publickey: 'D' }, cert: { c: 1 } }
const falla = (code) => async () => { throw Object.assign(new Error(code), { code }) }

test('mayUpdate pregunta con el producto y la conexión, y devuelve si se puede', async () => {
  const visto = []
  const h = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _ask: async (o) => { visto.push(o); return { ok: true, asked: true } } })
  assert.equal(await h.mayUpdate({ version: '1.1.0', from: '1.0.0' }), true)
  assert.deepEqual([visto[0].product, visto[0].version, visto[0].from, visto[0].masterPubkey, visto[0].cert], ['@dotrino/x', '1.1.0', '1.0.0', 'M', { c: 1 }])
  const no = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _ask: async () => ({ ok: false, asked: true }) })
  assert.equal(await no.mayUpdate({ version: '1.1.0' }), false, 'denegado es no')
  const solo = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _ask: async () => ({ ok: true, asked: false }) })
  assert.equal(await solo.mayUpdate({ version: '1.1.0' }), true, 'nadie aprueba: adelante')
})

test('la bóveda no contesta: LANZA (no se pudo preguntar); el pedido vence: es no', async () => {
  const mudo = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _ask: falla('vault-no-reply') })
  await assert.rejects(mudo.mayUpdate({ version: '1.1.0' }), (e) => e.code === 'vault-no-reply')
  const vencido = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _ask: falla('unanswered') })
  assert.equal(await vencido.mayUpdate({ version: '1.1.0' }), false)
})

test('onUpdated y onNeedsRoot avisan a la bóveda y dejan pasar el error', async () => {
  const dichos = []
  const h = vaultUpdateHooks({ product: '@dotrino/x', dir: '/d', _done: async (o) => { dichos.push(['done', o.product, o.version, o.from, o.dir]) }, _root: async (o) => { dichos.push(['root', o.product, o.version, o.from, o.dir]) } })
  await h.onUpdated({ version: '1.1.0', from: '1.0.0' })
  await h.onNeedsRoot({ version: '1.2.0', from: '1.1.0' })
  assert.deepEqual(dichos, [['done', '@dotrino/x', '1.1.0', '1.0.0', '/d'], ['root', '@dotrino/x', '1.2.0', '1.1.0', '/d']])
  const roto = vaultUpdateHooks({ product: '@dotrino/x', ...conn, _done: falla('vault-no-reply'), _root: falla('vault-no-reply') })
  await assert.rejects(roto.onUpdated({ version: '1.1.0' }), (e) => e.code === 'vault-no-reply')
  await assert.rejects(roto.onNeedsRoot({ version: '1.1.0' }), (e) => e.code === 'vault-no-reply')
})

test('sin producto no hay ganchos', () => {
  assert.throws(() => vaultUpdateHooks({ ...conn }), /needs product/)
})
