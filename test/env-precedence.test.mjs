/**
 * PRECEDENCIA: el vault manda sobre el `.env` y sobre el entorno.
 *
 * Esta regla nació al revés (`override = false`): lo que ya estuviera en
 * `process.env` —o sea, cualquier `.env` cargado antes— GANABA, y el valor del
 * vault se descartaba en silencio. Eso rompía la razón de ser del vault como
 * fuente de verdad: al rotar una llave, un `.env` rancio olvidado en un VPS
 * seguía mandando y el servicio arrancaba con la credencial vieja sin quejarse.
 *
 * Se prueba aquí y no en el e2e porque es una regla de precedencia pura: no
 * necesita ni vault ni proxy, y un test que no necesita red es un test que se
 * corre siempre.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { applyEnv } from '../lib/src/env.js'

/** Corre `fn` con un entorno restaurado al salir (los tests no se pisan entre sí). */
function conEntorno (vars, fn) {
  const previo = new Map()
  for (const [k, v] of Object.entries(vars)) {
    previo.set(k, k in process.env ? process.env[k] : undefined)
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try { return fn() } finally {
    for (const [k, v] of previo) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

test('el valor del vault PISA el del entorno (el .env ya cargado)', () => {
  conEntorno({ TURN_KEY_ID: 'la-vieja-del-env', DOTRINO_ENV_OVERRIDE: undefined }, () => {
    const r = applyEnv({ TURN_KEY_ID: 'la-nueva-del-vault' })
    assert.equal(process.env.TURN_KEY_ID, 'la-nueva-del-vault')
    assert.deepEqual(r.injected, ['TURN_KEY_ID'])
    assert.deepEqual(r.skipped, [])
  })
})

test('reporta lo que pisó: es la señal de que hay un .env rancio', () => {
  conEntorno({ A: 'vieja', B: undefined, C: 'igual', DOTRINO_ENV_OVERRIDE: undefined }, () => {
    const r = applyEnv({ A: 'nueva', B: 'nueva', C: 'igual' })
    // A tenía otro valor → pisada. B no existía → solo inyectada.
    // C ya tenía el MISMO valor → inyectada, pero no cuenta como pisada: avisar
    // de eso sería ruido, no hay nada viejo que limpiar.
    assert.deepEqual(r.overridden, ['A'])
    assert.deepEqual(r.injected.sort(), ['A', 'B', 'C'])
  })
})

test('DOTRINO_ENV_OVERRIDE=0 devuelve la precedencia clásica (escotilla de depuración)', () => {
  conEntorno({ TURN_KEY_ID: 'la-del-env', DOTRINO_ENV_OVERRIDE: '0' }, () => {
    const r = applyEnv({ TURN_KEY_ID: 'la-del-vault' })
    assert.equal(process.env.TURN_KEY_ID, 'la-del-env')
    assert.deepEqual(r.skipped, ['TURN_KEY_ID'])
    assert.deepEqual(r.injected, [])
  })
})

test('la escotilla es EXACTAMENTE "0": cualquier otro valor deja mandando al vault', () => {
  // Un `DOTRINO_ENV_OVERRIDE=false` o `=no` significaría, leído en voz alta, lo
  // mismo que "0" — y no lo es. Se fija el comportamiento para que quede claro
  // que la escotilla es angosta a propósito: la regla es que el vault manda.
  for (const valor of ['false', 'no', '', '1']) {
    conEntorno({ K: 'del-env', DOTRINO_ENV_OVERRIDE: valor }, () => {
      applyEnv({ K: 'del-vault' })
      assert.equal(process.env.K, 'del-vault', `con DOTRINO_ENV_OVERRIDE=${JSON.stringify(valor)}`)
    })
  }
})

test('el parámetro explícito gana sobre la variable de entorno', () => {
  conEntorno({ K: 'del-env', DOTRINO_ENV_OVERRIDE: '0' }, () => {
    applyEnv({ K: 'del-vault' }, true)
    assert.equal(process.env.K, 'del-vault')
  })
})

test('los valores se vuelcan como string (process.env no guarda otra cosa)', () => {
  conEntorno({ N: undefined, DOTRINO_ENV_OVERRIDE: undefined }, () => {
    applyEnv({ N: 4001 })
    assert.equal(process.env.N, '4001')
  })
})

test('un bundle vacío o nulo no rompe', () => {
  assert.deepEqual(applyEnv(null).injected, [])
  assert.deepEqual(applyEnv({}).injected, [])
})
