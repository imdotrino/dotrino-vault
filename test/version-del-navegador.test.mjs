/**
 * LA VERSIÓN QUE ANUNCIA LA BÓVEDA DEL NAVEGADOR es la del paquete.
 *
 * El navegador no puede leer el `package.json`, así que `@dotrino/vault` la lleva escrita
 * en `lib/src/core/libVersion.js` y con ella se anuncia la pestaña y la extensión
 * (`@dotrino/compat`). Una versión anunciada que no es la que corre es peor que ninguna:
 * esta prueba para el release si alguien sube una y no la otra.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { LIB_VERSION } from '../lib/src/core/libVersion.js'

test('la bóveda del navegador anuncia la versión del paquete', () => {
  const { version } = JSON.parse(fs.readFileSync(new URL('../lib/package.json', import.meta.url), 'utf8'))
  assert.equal(LIB_VERSION, version, 'lib/src/core/libVersion.js no dice la versión de lib/package.json')
})
