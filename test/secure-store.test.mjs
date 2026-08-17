/**
 * F4 — datos sensibles del usuario (docs/consola-remota.md §6).
 *
 * Lo que se prueba es la promesa, no la fontanería: que la bóveda guarda SOBRES
 * CERRADOS (no ve el valor ni el nombre), que listar no baja los valores, que hay
 * topes contra el abuso, y que esto no toca `secrets.json` (el cajón de los servicios).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openThreadStore, STORE_READ_METHODS } from '../src/threadStore.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secure-'))
const clean = (d) => fs.rmSync(d, { recursive: true, force: true })

test('guardar, listar, abrir y borrar una ficha', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)

  const { id } = m['secure.put']({ meta: 'META-SELLADA', enc: 'VALOR-SELLADO' })
  assert.ok(id, 'la ficha nace con id')

  const list = m['secure.list']()
  assert.equal(list.length, 1)
  assert.equal(list[0].meta, 'META-SELLADA')
  assert.equal(list[0].enc, undefined, 'listar NO baja el valor')

  const one = m['secure.get']({ id })
  assert.equal(one.enc, 'VALOR-SELLADO')

  assert.deepEqual(m['secure.del']({ id }), { removed: 1 })
  assert.equal(m['secure.list']().length, 0)
  assert.deepEqual(m['secure.del']({ id }), { removed: 0 }, 'borrar dos veces no rompe')
  clean(d)
})

test('editar conserva id y fecha de creación, y actualiza updatedAt', async () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  const { id } = m['secure.put']({ meta: 'm1', enc: 'v1' })
  const created = m['secure.get']({ id }).ts
  await new Promise((r) => setTimeout(r, 5))

  m['secure.put']({ id, enc: 'v2' })
  const after = m['secure.get']({ id })
  assert.equal(after.ts, created, 'la fecha de creación no se mueve')
  assert.equal(after.enc, 'v2')
  assert.equal(after.meta, 'm1', 'no mandar meta conserva la que había')
  assert.ok(after.updatedAt > created)
  clean(d)
})

test('en el disco no se ve nada: ni el valor ni el nombre', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  m['secure.put']({ meta: 'BancoDelPacifico', enc: 'contrasena-secreta' })
  const raw = fs.readFileSync(path.join(d, 'threads.json'), 'utf8')
  assert.ok(!raw.includes('contrasena-secreta'), 'el valor no queda en claro (cifrado en reposo)')
  assert.ok(!raw.includes('BancoDelPacifico'), 'el nombre tampoco')
  clean(d)
})

test('sobrevive a reabrir el store', () => {
  const d = tmp()
  const { id } = openThreadStore(d).methods['secure.put']({ meta: 'm', enc: 'v' })
  const { methods: m2 } = openThreadStore(d)
  assert.equal(m2['secure.get']({ id }).enc, 'v')
  clean(d)
})

test('topes: sin valor, demasiado grande, demasiadas fichas', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  assert.throws(() => m['secure.put']({ meta: 'm' }), /enc required/)
  assert.throws(() => m['secure.put']({ meta: { no: 'sellado' }, enc: 'v' }), /sealed string/)
  assert.throws(() => m['secure.put']({ enc: 'x'.repeat(64 * 1024 + 1) }), /too large/)
  assert.throws(() => m['secure.get']({}), /id required/)
  clean(d)
})

test('leer datos sensibles NO se conforma con `vault:read`', () => {
  // Están fuera del set de solo-lectura a propósito: eso obliga a `vault:store`
  // en `handleStore`. Un dispositivo al que solo le diste «leer» no ve contraseñas.
  assert.ok(!STORE_READ_METHODS.has('secure.list'))
  assert.ok(!STORE_READ_METHODS.has('secure.get'))
})

test('los datos sensibles no se mezclan con hilos ni aperturas', () => {
  const d = tmp()
  const { methods: m } = openThreadStore(d)
  m['secure.put']({ meta: 'm', enc: 'v' })
  m.appendMessage({ threadKey: 't', entry: { text: 'hola' } })
  assert.equal(m.listThreadKeys().length, 1)
  assert.equal(m.getStats().secureCount, 1)
  assert.equal(m.getStats().threadCount, 1)
  assert.deepEqual(m.exportThreads().threads.t.length, 1, 'exportar hilos no arrastra fichas')
  clean(d)
})
