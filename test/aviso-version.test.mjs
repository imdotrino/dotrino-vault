/**
 * QUIÉN DECIDE QUE LA BÓVEDA SE ACTUALICE (§15, regla del dueño del 2026-09-20).
 *
 * La bóveda es la pieza sensible: quien le cuele una actualización se lleva la maestra, y
 * eso no se rota — se pierde la cuenta. Así que no se actualiza sola **mientras haya quien
 * apruebe**, igual que ya pasa con las claves privadas.
 *
 * Y la otra mitad de la regla, que es la que evita la trampa: si NO hay ningún aparato con
 * `aprueba`, esperar un sí que nadie puede dar la condenaría a no actualizarse nunca. Sin
 * aprobadores, se actualiza sola.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { isNewer } from '../src/update.js'

/** La decisión, tal como la toma el daemon. */
const pideraPermiso = (aprobadores) => aprobadores.length > 0

test('con aprobadores, la bóveda NO se actualiza sola', () => {
  assert.equal(pideraPermiso([{ id: 'AB12-CD34', label: 'teléfono' }]), true)
})

test('sin aprobadores se actualiza sola: nadie puede decir que sí', () => {
  assert.equal(pideraPermiso([]), false,
    'esperar una aprobación imposible la deja sin actualizar para siempre')
})

/**
 * Y lo de siempre con las versiones: comparar tres números, no texto. `0.99.0` no es más
 * nueva que `0.100.0`, y creerlo deja una máquina atrás convencida de estar al día.
 */
test('99 no es mayor que 100', () => {
  assert.equal(isNewer('0.100.0', '0.99.0'), true)
  assert.equal(isNewer('0.99.0', '0.100.0'), false)
  assert.equal(isNewer('0.123.1', '0.123.0'), true)
})

/**
 * EL PLAZO DE UN PEDIDO LO PONE QUIEN PIDE (dueño, 2026-09-20).
 *
 * Cinco minutos es lo correcto para un COMANDO: hay un proceso esperando y aprobar media
 * hora después entregaría claves a algo cuyo contexto ya cambió. Una ACTUALIZACIÓN no se
 * parece en nada — no hay nadie esperando, y caducar no protege de nada: solo significa que
 * mañana se vuelve a pedir y se vuelve a perder, porque mirar el teléfono puede tardar
 * horas. Un pedido que nunca llega a tiempo es una función que no existe.
 */
import { createApprovals, PENDING_TTL_MS, UPDATE_TTL_MS } from '../src/approvals.js'

test('un comando caduca en cinco minutos; una actualización aguanta el día', () => {
  let t = 1_000_000
  const mesa = createApprovals({ now: () => t })

  mesa.request({ ns: 'proxy', device: 'K1', deviceId: 'AB12-CD34' })
  mesa.request({ ns: 'update', device: 'K2', deviceId: 'EF56-7890', ttlMs: UPDATE_TTL_MS })
  assert.equal(mesa.list().length, 2)

  // Seis minutos después: el del comando se fue, el de la actualización sigue.
  t += 6 * 60_000
  const vivos = mesa.list()
  assert.deepEqual(vivos.map((p) => p.ns), ['update'], 'se llevó por delante el de la actualización')

  // Tres horas mirando el teléfono, que es lo normal: sigue ahí.
  t += 3 * 60 * 60_000
  assert.equal(mesa.list().length, 1, 'caducó mientras el dueño no miraba: eso es no tener la función')

  // Pasado el día sí se va, y la bóveda vuelve a pedirlo en su repaso diario.
  t += UPDATE_TTL_MS
  assert.equal(mesa.list().length, 0)
})

test('sin decir nada, el plazo sigue siendo el de siempre', () => {
  let t = 0
  const mesa = createApprovals({ now: () => t })
  const p = mesa.request({ ns: 'proxy', device: 'K1', deviceId: 'AB12-CD34' })
  assert.equal(p.exp, PENDING_TTL_MS, 'cambiar el plazo de uno no puede cambiar el de todos')
})

test('pedir otra vez reemplaza el anterior: una lista, no una cola de avisos', () => {
  let t = 0
  const mesa = createApprovals({ now: () => t })
  mesa.request({ ns: 'update', device: 'K2', deviceId: 'EF56-7890', ttlMs: UPDATE_TTL_MS })
  t += 24 * 60 * 60_000
  mesa.request({ ns: 'update', device: 'K2', deviceId: 'EF56-7890', ttlMs: UPDATE_TTL_MS })
  assert.equal(mesa.list().length, 1)
})
