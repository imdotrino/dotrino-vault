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

/**
 * LA FORMA DE `wraps` LA FIJAN OTROS DOS ARCHIVOS, y esta prueba tiene que usar la suya.
 *
 * Es `{ ns: [...], dev: [...] }`: así lo emite `src/secretsStore.js` (`sealedBundleFor`) y
 * así lo lee `lib/src/service.js`, que recorre `wraps.ns` y `wraps.dev`. Esta prueba lo
 * escribía como una LISTA plana, igual que el código que probaba, así que los dos estaban
 * de acuerdo en algo que producción no hacía: pasaba en verde mientras cada empujón sobre
 * un sobre ya guardado moría con «not iterable». Una prueba que copia la suposición del
 * código no prueba nada.
 */
const w = (...gens) => ({ ns: gens.map((gen) => ({ gen, wrap: 'w' + gen })), dev: [] })

test('gana la generación más alta, dato a dato', () => {
  const tengo = { entries: { telefono: e(5, 'nuevo'), nombre: e(2, 'ana') }, wraps: w(5) }
  const llega = { entries: { telefono: e(3, 'viejo'), correo: e(1, 'a@b') }, wraps: w(3) }
  const r = mergeBundle(tengo, llega)

  assert.equal(r.entries.telefono.e.ct, 'nuevo', 'un empujón atrasado NO pisa lo más nuevo')
  assert.equal(r.entries.nombre.e.ct, 'ana', 'lo que no viene en el empujón se conserva')
  assert.equal(r.entries.correo.e.ct, 'a@b', 'y lo que viene nuevo entra')
})

test('las envolturas se suman: son de aparatos distintos y ninguna estorba', () => {
  const r = mergeBundle({ entries: {}, wraps: w(1, 2) }, { entries: {}, wraps: w(2, 3) })
  assert.deepEqual(r.wraps.ns.map((x) => x.gen), [1, 2, 3])
  assert.deepEqual(r.wraps.dev, [], 'el otro lado se conserva, aunque esté vacío')
  // Y la VIGENTE sale de la lista mezclada, no del empujón: si saliera de `nuevo`, aquí
  // quedaría la 3 cuando el que llega trae la 3 y el que está tiene la 2 — pero al revés
  // (empujón atrasado) quedaría una MENOR que la que ya había.
  assert.equal(r.ns.gen, 3)
  assert.equal(mergeBundle({ entries: {}, wraps: w(5) }, { entries: {}, wraps: w(2) }).ns.gen, 5,
    'un empujón atrasado no rebaja la envoltura vigente')
})

/**
 * Y NO REVIENTA CON LA FORMA DE VERDAD. Es el fallo que se vio en el replicador de Cepi:
 * `[replica] push: (viejo.wraps || []) is not iterable`, en cada actualización de un sobre
 * que ya existía. El primer guardado nunca pasa por aquí (`if (!viejo) return nuevo`), así
 * que el error solo aparece cuando el replicador ya lleva tiempo puesto.
 */
test('mezclar dos paquetes de verdad no lanza', () => {
  const real = { entries: { x: e(1, 'x') }, ns: { gen: 1, wrap: 'w1' }, dev: null, wraps: { ns: [{ gen: 1, wrap: 'w1' }], dev: [] } }
  const otro = { entries: { x: e(2, 'y') }, ns: { gen: 2, wrap: 'w2' }, dev: null, wraps: { ns: [{ gen: 2, wrap: 'w2' }], dev: [] } }
  const r = mergeBundle(real, otro)
  assert.deepEqual(r.wraps.ns.map((x) => x.gen), [1, 2])
  assert.equal(r.entries.x.e.ct, 'y')
})

/**
 * EL EMPATE SE ROMPE IGUAL EN TODAS PARTES. Dos aparatos escribiendo el mismo dato con la
 * misma generación, sin verse, es normal. Lo que no puede pasar es que dos replicadores
 * que reciban lo mismo en distinto orden acaben distintos: no es justicia, es determinismo.
 */
test('un empate se rompe igual, venga en el orden que venga', () => {
  const a = { entries: { x: e(4, 'aaa') }, wraps: w() }
  const b = { entries: { x: e(4, 'bbb') }, wraps: w() }
  assert.equal(mergeBundle(a, b).entries.x.e.ct, 'aaa')
  assert.equal(mergeBundle(b, a).entries.x.e.ct, 'aaa', 'el orden de llegada no cambia el resultado')
})

test('un paquete que falta no borra el que hay', () => {
  const tengo = { entries: { x: e(1, 'x') }, wraps: w() }
  assert.equal(mergeBundle(tengo, null), tengo)
  assert.deepEqual(mergeBundle(null, tengo), tengo)
})
