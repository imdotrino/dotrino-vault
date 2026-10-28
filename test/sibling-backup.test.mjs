/**
 * EL RESPALDO DE LAS APPS SE COPIA SOLO ENTRE BÓVEDAS (dueño, 2026-10-28), con el tope de 25 MB
 * que borra lo más viejo de la app que más ocupa. Dos bóvedas en memoria y un cable que entrega
 * en orden, como el proxio.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { openThreadStore } from '../lib/src/core/threadStore.js'
import { createSiblingBackup } from '../lib/src/core/siblingBackup.js'
import { memoryDisk } from '../lib/src/core/disk.js'

function pair () {
  const queue = []
  const make = (name) => {
    const threads = openThreadStore(memoryDisk())
    const node = { name, threads }
    node.backup = createSiblingBackup({
      threads,
      siblings: async () => [name === 'pc' ? 'nube' : 'pc'],
      send: async (to, body) => { queue.push({ to, from: name, body: JSON.parse(JSON.stringify(body)) }) },
      log: () => {}
    })
    return node
  }
  const nodes = { pc: make('pc'), nube: make('nube') }
  const drain = async () => {
    let n = 0
    while (queue.length) {
      if (++n > 200) throw new Error('the sibling backup does not settle')
      const m = queue.shift()
      await nodes[m.to].backup.handle(m.from, m.body)
    }
    return n
  }
  return { ...nodes, drain }
}

const write = (node, k, id, ts, owner, extra = {}) => node.threads.methods.importThreads({ threads: { [k]: [{ id, ts, ...extra }] }, owners: { [k]: owner }, mode: 'upsert' })

test('lo que una tiene y la otra no llega a las dos, y se calla', async () => {
  const { pc, nube, drain } = pair()
  write(pc, 'chat', 'm1', 1, 'messenger.dotrino.com', { text: 'hola' })
  write(nube, 'facturero.invoices', 'f1', 2, 'facturero.dotrino.com')
  await pc.backup.announce('start')
  await drain()
  for (const n of [pc, nube]) {
    const raw = n.threads.raw()
    assert.deepEqual(Object.keys(raw.threads).sort(), ['chat', 'facturero.invoices'], n.name)
    assert.equal(raw.owners.chat, 'messenger.dotrino.com')
  }
  // Ya iguales: anunciar otra vez no mueve nada más que el estado.
  await nube.backup.announce('again')
  assert.equal(await drain(), 1)
})

test('lo borrado en una se borra en la otra; lo editado después, gana', async () => {
  const { pc, nube, drain } = pair()
  write(pc, 'chat', 'm1', 1, 'messenger.dotrino.com')
  write(pc, 'chat', 'm2', 1, 'messenger.dotrino.com')
  await pc.backup.announce('start'); await drain()
  nube.threads.methods.removeMessage({ threadKey: 'chat', id: 'm1' })
  write(pc, 'chat', 'm2', 5, 'messenger.dotrino.com', { text: 'editado' })
  await nube.backup.announce('change'); await drain()
  await pc.backup.announce('change'); await drain()
  for (const n of [pc, nube]) assert.deepEqual(n.threads.raw().threads.chat.map((e) => [e.id, e.ts]), [['m2', 5]], n.name)
})

test('pasado el tope, las dos borran lo mismo y no lo devuelven', async () => {
  const { pc, nube, drain } = pair()
  const big = 'x'.repeat(1024 * 1024)
  for (let i = 0; i < 26; i++) write(pc, 'file:chat', 'p' + i, i + 1, 'messenger.dotrino.com', { big })
  write(pc, 'facturero.invoices', 'f1', 0, 'facturero.dotrino.com')
  const raw = pc.threads.raw()
  assert.ok(raw.floors['file:chat'] >= 1, 'subió el suelo')
  assert.ok(raw.threads['facturero.invoices'], 'la factura, más vieja, se queda')
  await pc.backup.announce('start'); await drain()
  assert.deepEqual(nube.threads.raw().threads['file:chat'].map((e) => e.id), raw.threads['file:chat'].map((e) => e.id))
  assert.deepEqual(nube.threads.raw().floors, raw.floors)
  // Un aparato viejo que sube lo que la bóveda ya borró: no entra.
  const r = pc.threads.methods.importThreads({ threads: { 'file:chat': [{ id: 'p0', ts: 1, big }] }, mode: 'merge' })
  assert.deepEqual(r.changed, [])
})
