/**
 * UN EMPUJÓN ATRASADO NO PISA UN DATO MÁS NUEVO.
 *
 * Lo preguntó el dueño el 2026-09-03: *«estos sobres gana el más nuevo, en el caso de el
 * vault apagado y que la replica tenga cambios por ejemplo»*.
 *
 * La decisión de v1 es que **un replicador NO acepta escrituras** —reparte, no decide—, así
 * que no puede tener cambios propios y ese caso no existe. Pero el reemplazo entero seguía
 * estando mal por otro camino que sí ocurre: una bóveda restaurada de un respaldo empuja un
 * paquete donde UN dato está más atrasado que el que el replicador ya tiene. El `seq` del
 * acta no lo caza —el acta puede ir por delante mientras un dato va por detrás—, así que la
 * comparación tiene que ser POR DATO.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { mergeBundle } from '../src/replica.js'

const e = (gen, ct) => ({ gen, e: { iv: 'iv', ct } })

test('gana la generación más alta, dato a dato', () => {
  const tengo = { entries: { telefono: e(5, 'nuevo'), nombre: e(2, 'ana') }, wraps: [{ gen: 5, wrap: 'w5' }] }
  const llega = { entries: { telefono: e(3, 'viejo'), correo: e(1, 'a@b') }, wraps: [{ gen: 3, wrap: 'w3' }] }
  const r = mergeBundle(tengo, llega)

  assert.equal(r.entries.telefono.e.ct, 'nuevo', 'un empujón atrasado NO pisa lo más nuevo')
  assert.equal(r.entries.nombre.e.ct, 'ana', 'lo que no viene en el empujón se conserva')
  assert.equal(r.entries.correo.e.ct, 'a@b', 'y lo que viene nuevo entra')
})

test('las envolturas se suman: son de aparatos distintos y ninguna estorba', () => {
  const r = mergeBundle(
    { entries: {}, wraps: [{ gen: 1, wrap: 'a' }, { gen: 2, wrap: 'b' }] },
    { entries: {}, wraps: [{ gen: 2, wrap: 'b' }, { gen: 3, wrap: 'c' }] })
  assert.deepEqual(r.wraps.map((w) => w.gen), [1, 2, 3])
})

/**
 * EL EMPATE SE ROMPE IGUAL EN TODAS PARTES. Dos aparatos escribiendo el mismo dato con la
 * misma generación, sin verse, es normal. Lo que no puede pasar es que dos replicadores
 * que reciban lo mismo en distinto orden acaben distintos: no es justicia, es determinismo.
 */
test('un empate se rompe igual, venga en el orden que venga', () => {
  const a = { entries: { x: e(4, 'aaa') }, wraps: [] }
  const b = { entries: { x: e(4, 'bbb') }, wraps: [] }
  assert.equal(mergeBundle(a, b).entries.x.e.ct, 'aaa')
  assert.equal(mergeBundle(b, a).entries.x.e.ct, 'aaa', 'el orden de llegada no cambia el resultado')
})

test('un paquete que falta no borra el que hay', () => {
  const tengo = { entries: { x: e(1, 'x') }, wraps: [] }
  assert.equal(mergeBundle(tengo, null), tengo)
  assert.deepEqual(mergeBundle(null, tengo), tengo)
})
