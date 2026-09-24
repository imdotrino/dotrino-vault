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

/**
 * UN VALOR EN CLARO TAMPOCO SE ARREGLA REINTENTANDO.
 *
 * Desde el 2026-09-02 toda variable viaja sellada, también las públicas. Una guardada
 * antes de eso llega en claro y el agente rechaza el bundle entero — con razón. Lo que
 * estaba mal era tratarlo como transitorio: el cajón `aws-admin` volvía a pedir cada
 * cinco segundos y el teléfono timbraba en cada vuelta, aunque el dueño aprobara todas.
 * Sellarla exige abrir la bóveda y volver a escribirla; ninguna espera lo hace.
 */
test('un valor en claro NO se reintenta: se corta', () => {
  assert.equal(isFinal({ code: 'plaintext-var', message: 'cualquier cosa' }), true)
  assert.equal(isFinal({ code: 'plaintext-var', message: '' }), true)
})

/**
 * NADIE PUEDE APROBAR: TAMPOCO SE ARREGLA REINTENTANDO (2026-09-24).
 *
 * La limpieza de aparatos muertos se llevó al único teléfono con `aprueba` de la cuenta, y
 * `dotrino-env` se quedó reintentando cada minuto sin decir nada. La bóveda contestaba con
 * `code: 'no-approver'` y el mensaje de qué hacer, pero el cliente perdía el `code` al
 * convertir la respuesta en Error.
 */
test('sin nadie que apruebe se corta, y se decide por el code', () => {
  assert.equal(isFinal({ code: 'no-approver', message: 'approval: nobody in the record can approve' }), true)
  assert.equal(isFinal({ code: 'no-approver', message: '' }), true)
})

test('el code de la bóveda llega hasta arriba (fetchSecrets no lo pierde)', async () => {
  const src = (await import('node:fs')).readFileSync(new URL('../lib/src/service.js', import.meta.url), 'utf8')
  assert.equal((src.match(/throw new Error\(res\.error\)|reject\(new Error\(p\.error\)\)/g) || []).length, 0,
    'un vault.error se convierte con vaultError(), que conserva el code')
})
