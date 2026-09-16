// Sincronizar por partes con @dotrino/store: huellas, índices, entradas por id y lápidas.
// Las reglas son las de `@dotrino/store/core`; esto comprueba que la bóveda las atiende.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { PAGE_BYTES } from '@dotrino/store/core'
import { openThreadStore, STORE_READ_METHODS } from '../src/threadStore.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'thread-sync-'))
const bytes = (v) => Buffer.byteLength(JSON.stringify(v))

// Vector compartido con @dotrino/store (test/vault-sync.spec.ts): si cambia uno, cambian los dos.
test('the digest matches the vector shared with the store page', async () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  m.importThreads({ threads: { t: [{ id: 'b', ts: 2 }, { id: 'a', ts: 1 }] } })
  assert.equal((await m.getThreadDigests()).t.digest, '01599daf8046b8f94a7198d1ecbbf0a2665c246d9187f8d2bdf562cc78bf512e')
  assert.deepEqual(Object.keys(await m.getThreadDigests({ keys: ['t', 'nope'] })), ['t'])
  for (const name of ['getThreadDigests', 'getThreadIndexes', 'getEntries']) assert.ok(STORE_READ_METHODS.has(name), name)
  assert.ok(!STORE_READ_METHODS.has('importThreads') && !STORE_READ_METHODS.has('mergeOpens'))
  fs.rmSync(d, { recursive: true, force: true })
})

test('a thread keeps more than 1000 entries (it used to drop the oldest in silence)', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  const buyers = Array.from({ length: 2500 }, (_, i) => ({ id: `b${i}`, ts: i + 1 }))
  m.importThreads({ threads: { 'facturero.buyers': buyers } })
  assert.equal(m.listThread({ threadKey: 'facturero.buyers' }).length, 2500)
  fs.rmSync(d, { recursive: true, force: true })
})

test('indexes and entries come in pages under the byte budget and cover everything', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  const xml = 'x'.repeat(11_000) // lo que ocupa una factura de facturero
  const threads = {}
  for (let day = 1; day <= 3; day++) threads[`inv.${day}`] = Array.from({ length: 60 }, (_, i) => ({ id: `${day}-${i}`, ts: i + 1, xml }))
  m.importThreads({ threads })
  m.removeMessage({ threadKey: 'inv.2', id: '2-0' })

  const keys = Object.keys(threads)
  const rows = {}
  let cursor = null
  let pages = 0
  do {
    const page = m.getThreadIndexes({ keys, cursor, maxBytes: 1024 })
    assert.ok(bytes(page.indexes) <= 1024 + 512, 'index page within budget')
    for (const [k, idx] of Object.entries(page.indexes)) {
      rows[k] = rows[k] || { items: 0, tombs: [] }
      rows[k].items += idx.items.length
      rows[k].tombs.push(...idx.tombs)
    }
    cursor = page.next
    pages++
  } while (cursor)
  assert.ok(pages >= 2, `several index pages (${pages})`)
  assert.deepEqual([rows['inv.1'].items, rows['inv.2'].items, rows['inv.3'].items], [60, 59, 60])
  assert.equal(rows['inv.2'].tombs.length, 1)
  assert.deepEqual(rows['inv.2'].tombs[0].slice(0, 2), ['2-0', 1])

  let refs = { 'inv.1': threads['inv.1'].map((e) => e.id), 'inv.3': threads['inv.3'].map((e) => e.id) }
  let got = 0
  let calls = 0
  while (refs) {
    const page = m.getEntries({ refs })
    assert.ok(bytes(page.threads) <= PAGE_BYTES + 1024, 'entries page within budget')
    for (const list of Object.values(page.threads)) got += list.length
    refs = page.rest
    calls++
  }
  assert.equal(got, 120)
  assert.ok(calls >= 4, `more than one entries page (${calls})`)
  assert.throws(() => m.getThreadIndexes({ keys: 'inv.1' }), /keys must be a list/)
  fs.rmSync(d, { recursive: true, force: true })
})

test('tombs travel both ways and a deleted entry does not come back', () => {
  const d = tmp()
  const { methods: m, raw } = openThreadStore(d)
  m.importThreads({ threads: { p: [{ id: 'p1', ts: 3 }, { id: 'p2', ts: 4 }] } })

  // Un aparato borró p1 sin conexión y ahora lo cuenta.
  m.importThreads({ threads: {}, tombs: { p: [['p1', 3, Date.now()]] } })
  assert.deepEqual(m.listThread({ threadKey: 'p' }).map((e) => e.id), ['p2'])

  // Otro aparato, que todavía tenía p1, lo sube: no entra.
  m.importThreads({ threads: { p: [{ id: 'p1', ts: 3 }] } })
  assert.deepEqual(m.listThread({ threadKey: 'p' }).map((e) => e.id), ['p2'])

  // Pero una edición POSTERIOR al borrado sí entra.
  m.importThreads({ threads: { p: [{ id: 'p1', ts: 8 }] } })
  assert.deepEqual(m.listThread({ threadKey: 'p' }).map((e) => `${e.id}@${e.ts}`).sort(), ['p1@8', 'p2@4'])

  // Borrar aquí deja lápida con el ts de lo borrado, y sobrevive a reabrir el archivo.
  m.removeThread({ threadKey: 'p' })
  assert.deepEqual(Object.keys(raw().tombs.p).sort(), ['p1', 'p2'])
  const again = openThreadStore(d).methods
  assert.deepEqual(again.getThreadIndexes({ keys: ['p'] }).indexes.p.tombs.map((r) => r.slice(0, 2)).sort(), [['p1', 8], ['p2', 4]])
  fs.rmSync(d, { recursive: true, force: true })
})

test('upsert lets the writer win a tie; merge keeps what was there', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  m.importThreads({ threads: { t: [{ id: 'a', ts: 5, v: 'old' }] } })
  m.importThreads({ threads: { t: [{ id: 'a', ts: 5, v: 'copy' }] }, mode: 'merge' })
  assert.equal(m.listThread({ threadKey: 't' })[0].v, 'old')
  m.importThreads({ threads: { t: [{ id: 'a', ts: 5, v: 'written' }] }, mode: 'upsert' })
  assert.equal(m.listThread({ threadKey: 't' })[0].v, 'written')
  assert.throws(() => m.importThreads({ threads: {}, mode: 'bogus' }), /unknown import mode/)
  fs.rmSync(d, { recursive: true, force: true })
})

test('opens merge by keeping the larger count and the later time', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  m.recordOpen({ appId: 'a.dotrino.com' })
  const merged = m.mergeOpens({ opens: { 'a.dotrino.com': { count: 5, ts: 1 }, 'b.dotrino.com': { count: 2, ts: 7 } } })
  assert.equal(merged['a.dotrino.com'].count, 5)
  assert.ok(merged['a.dotrino.com'].ts > 1)
  assert.deepEqual(merged['b.dotrino.com'], { count: 2, ts: 7 })
  assert.deepEqual(m.mergeOpens({ opens: { 'b.dotrino.com': { count: 1, ts: 2 } } }), merged)
  fs.rmSync(d, { recursive: true, force: true })
})

test('a thread key named __proto__ is refused, not written into the prototype', () => {
  const d = tmp()
  const { methods: m, raw } = openThreadStore(d)
  assert.throws(() => m.appendMessage({ threadKey: '__proto__', entry: { id: 'x' } }), /threadKey required/)
  m.importThreads({ threads: JSON.parse('{"__proto__":[{"id":"x","ts":1}]}') })
  assert.equal(Object.getPrototypeOf(raw().threads), Object.prototype)
  assert.deepEqual(m.listThread({ threadKey: '__proto__' }), [])
  fs.rmSync(d, { recursive: true, force: true })
})
