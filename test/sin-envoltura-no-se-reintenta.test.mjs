/**
 * UN SOBRE QUE FALTA NO SE ARREGLA REINTENTANDO.
 *
 * Un aparato que entra al acta DESPUÉS de escrita una variable no tiene envoltura de ella,
 * y no puede tenerla: envolver exige abrir la llave del cajón, y eso solo pasa cuando el
 * dueño abre la bóveda. Es un estado legítimo, no un tropiezo.
 *
 * Hasta el 2026-09-01 se trataba como transitorio, y salía este bucle: el agente pide → la
 * bóveda pide aprobación → el teléfono timbra → el dueño aprueba → la bóveda contesta un
 * bundle que el agente NO puede abrir → el agente reintenta → el teléfono timbra otra vez.
 * El dueño, textual: «sigo aprobando y aprobando».
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { isFinal } from '../lib/src/service.js'

test('sin envoltura en el cajón NO se reintenta: se corta', () => {
  // Se juzga por el CÓDIGO, no por la frase: traducir o reescribir el mensaje no puede
  // volver a encender el bucle en silencio.
  assert.equal(isFinal({ code: 'no-wrapping', message: 'cualquier cosa' }), true)
  assert.equal(isFinal({ code: 'no-wrapping', message: '' }), true)
})

test('lo que sí es transitorio se sigue reintentando', () => {
  assert.equal(isFinal(new Error('could not connect to the proxy wss://…: timeout')), false)
  assert.equal(isFinal(new Error('the vault did not reply')), false)
  assert.equal(isFinal({}), false, 'un error sin nada no se toma por definitivo')
})

test('y lo que exige que alguien haga algo tampoco se reintenta', () => {
  for (const m of ['service not enrolled: run enrollService() first', 'invalid ns',
    'unauthorized: revoked', 'unauthorized: denied — the "aws" request was denied from AB12-CD34']) {
    assert.equal(isFinal(new Error(m)), true, m)
  }
})
