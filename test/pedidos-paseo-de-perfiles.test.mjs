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
