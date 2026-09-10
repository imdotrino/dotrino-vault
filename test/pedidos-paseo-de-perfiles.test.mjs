/**
 * EL PEDIDO ES DE UN PERFIL, Y HAY QUE ENCONTRARLO SIN DAR VUELTAS.
 *
 * El timbre del teléfono no dice a qué cuenta llamó (viaja por FCM y ahí no se mete nada
 * que identifique al dueño), así que con varios perfiles que aprueban la pantalla de
 * Pedidos tiene que MIRAR en cada uno. Antes se rendía en cuanto había más de uno y te
 * dejaba en el que estuviera abierto —el último que usaste— diciendo «nadie está pidiendo
 * nada», que es falso y no da ninguna pista de dónde estaba el pedido.
 *
 * Lo que se prueba aquí es lo que no se puede probar en el navegador sin dos cuentas
 * emparejadas: que el paseo TERMINA. Cada perfil se mira una vez, se para en el primero
 * que tiene algo, y si ninguno tiene se vuelve a la cuenta desde la que se entró.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { walkStep } from '../web/src/approvals-walk.js'

const APRUEBAN = ['p1', 'p2', 'p3']

test('el pedido está en el perfil abierto: no se mueve de aquí', () => {
  const r = walkStep({ aqui: 'p2', from: 'p2', tried: [], approvers: APRUEBAN, hasPending: true })
  assert.equal(r.go, null)
  assert.equal(r.back, null)
  assert.equal(r.done, true)
  assert.equal(r.nothingAnywhere, false)
})

test('no hay nada aquí: va al siguiente que aprueba y se apunta el que ya miró', () => {
  const r = walkStep({ aqui: 'p1', from: 'p1', tried: [], approvers: APRUEBAN, hasPending: false })
  assert.equal(r.go, 'p2')
  assert.deepEqual(r.tried, ['p1'])
})

test('EL PASEO TERMINA: nunca se vuelve a mirar un perfil ya mirado', () => {
  let estado = { aqui: 'p1', from: 'p1', tried: [] }
  const visitados = []
  for (let i = 0; i < 10; i++) {
    const r = walkStep({ ...estado, approvers: APRUEBAN, hasPending: false })
    if (!r.go) { estado = { ...estado, fin: r }; break }
    assert.ok(!visitados.includes(r.go), `${r.go} se iba a mirar dos veces`)
    visitados.push(r.go)
    estado = { aqui: r.go, from: estado.from, tried: r.tried }
  }
  assert.deepEqual(visitados, ['p2', 'p3'], 'mira los otros dos y para')
  assert.equal(estado.fin.go, null, 'no queda ninguno por mirar')
})

test('ninguno tenía nada: se vuelve a la cuenta desde la que se entró, y se dice', () => {
  const r = walkStep({ aqui: 'p3', from: 'p1', tried: ['p1', 'p2'], approvers: APRUEBAN, hasPending: false })
  assert.equal(r.go, null)
  assert.equal(r.back, 'p1', 'dejarte en la última cuenta que se miró sería un efecto secundario de mirar')
  assert.equal(r.nothingAnywhere, true, 'hay que decir que no había nada EN NINGUNO')
})

test('un solo perfil: no hay paseo ni cartel de «en ninguno»', () => {
  const r = walkStep({ aqui: 'p1', from: 'p1', tried: [], approvers: ['p1'], hasPending: false })
  assert.equal(r.go, null)
  assert.equal(r.back, null)
  assert.equal(r.nothingAnywhere, false, 'con una sola cuenta, «en ninguno» sobra y confunde')
})

test('el perfil abierto NO aprueba: se va al que sí, y no se cuenta como mirado dos veces', () => {
  const r = walkStep({ aqui: 'px', from: 'px', tried: [], approvers: ['p1', 'p2'], hasPending: false })
  assert.equal(r.go, 'p1')
  const r2 = walkStep({ aqui: 'p1', from: 'px', tried: r.tried, approvers: ['p1', 'p2'], hasPending: false })
  assert.equal(r2.go, 'p2')
  const r3 = walkStep({ aqui: 'p2', from: 'px', tried: r2.tried, approvers: ['p1', 'p2'], hasPending: false })
  assert.equal(r3.go, null)
  assert.equal(r3.back, 'px')
})

/**
 * EL BUCLE QUE SE ESCAPÓ, y por qué esta prueba no existía antes.
 *
 * La primera versión probaba una vuelta del paseo, no lo que pasa DESPUÉS de terminarla: al
 * volver a la cuenta desde la que se entró —que es una recarga más— el paseo veía su marca
 * borrada, se creía nuevo y volvía a salir al otro perfil, que a su vez acababa
 * devolviéndote aquí. La pantalla rotaba entre cuentas para siempre. El dueño lo vio en su
 * teléfono a los diez minutos de desplegarlo.
 *
 * Se prueba el ciclo COMPLETO, incluida la vuelta a casa, y con el freno del arranque.
 */
test('tras volver a casa NO se empieza otro paseo (el ping-pong infinito)', () => {
  const APRUEBAN2 = ['p1', 'p2']
  // Vuelta 1: en p1 no hay nada → sale a p2.
  const r1 = walkStep({ aqui: 'p1', from: 'p1', tried: [], approvers: APRUEBAN2, hasPending: false })
  assert.equal(r1.go, 'p2')
  // Vuelta 2: en p2 tampoco → no queda ninguno, vuelve a p1 (y hay que decirlo).
  const r2 = walkStep({ aqui: 'p2', from: 'p1', tried: r1.tried, approvers: APRUEBAN2, hasPending: false })
  assert.equal(r2.go, null)
  assert.equal(r2.back, 'p1')
  assert.equal(r2.nothingAnywhere, true)
  // Vuelta 3 — LA QUE FALTABA. Ya en casa y sin memoria del paseo (se borró al volver), lo
  // único que queda es la marca de «vengo de terminar uno». Con ella no se mueve; sin ella,
  // volvería a salir a p2 y ahí está el ping-pong.
  const r3 = walkStep({ aqui: 'p1', from: 'p1', tried: [], approvers: APRUEBAN2, hasPending: false, justFinished: true })
  assert.equal(r3.go, null, 'este es el bucle: no puede volver a salir')
  assert.equal(r3.back, null)
  assert.equal(r3.done, true)
  assert.equal(r3.nothingAnywhere, true, 'y al llegar hay que decir que no había nada en ninguno')

  // Sin la marca sí volvería a salir: es exactamente lo que pasaba, y queda escrito para que
  // nadie la quite creyendo que sobra.
  const sinFreno = walkStep({ aqui: 'p1', from: 'p1', tried: [], approvers: APRUEBAN2, hasPending: false })
  assert.equal(sinFreno.go, 'p2')
})

test('la marca de «recién terminado» manda sobre todo lo demás', () => {
  // Incluso con perfiles por mirar y un pedido delante: si venimos de cerrar un paseo, no se
  // anda. Mirar lo que hay aquí es de la pantalla; moverse, no.
  const r = walkStep({ aqui: 'p1', from: 'p2', tried: [], approvers: ['p1', 'p2', 'p3'], hasPending: false, justFinished: true })
  assert.equal(r.go, null)
  assert.equal(r.back, null)
})

test('sin perfil abierto que reconocer, el paseo no se mueve', () => {
  // `aqui` null y la lista de mirados que no puede crecer: sin este freno saldría al primer
  // perfil que aprueba en cada recarga, para siempre.
  const r = walkStep({ aqui: null, from: null, tried: [], approvers: ['p1', 'p2'], hasPending: false })
  assert.equal(r.go, null)
  assert.equal(r.back, null)
  assert.equal(r.done, true)
})
