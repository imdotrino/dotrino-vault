/**
 * El cajón de variables (`src/secretsStore.js`), sin red ni identidad.
 *
 * Lo que se prueba es la promesa, no la fontanería:
 *
 *   · los DOS cajones se mezclan al entregarse, y el del aparato gana;
 *   · una variable nace PRIVADA, y rotarle el valor no la vuelve visible;
 *   · lo que ya existía antes de que hubiera visibilidad entra como privado —lo
 *     contrario habría expuesto secretos viejos con solo actualizar el binario.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openSecretsStore } from '../src/secretsStore.js'
import { readJson, writeJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secrets-store-'))
const PUB = 'PUB-DEL-PROXY'

test('los dos cajones se entregan MEZCLADOS y manda el del aparato', () => {
  const dir = tmp()
  const s = openSecretsStore(dir)
  s.set('proxy', 'TURN_KEY_ID', 'la-del-scope')
  s.set('proxy', 'DB_URL', 'postgres://compartida')
  s.setDevice(PUB, 'PORT', '8443')
  s.setDevice(PUB, 'TURN_KEY_ID', 'la-de-esta-maquina')

  assert.deepEqual(s.get('proxy', PUB), {
    TURN_KEY_ID: 'la-de-esta-maquina',
    DB_URL: 'postgres://compartida',
    PORT: '8443'
  })
  // Sin aparato, solo lo compartido: es lo que hay antes de saber quién pregunta.
  assert.deepEqual(s.get('proxy'), { TURN_KEY_ID: 'la-del-scope', DB_URL: 'postgres://compartida' })
  // Y lo de un aparato no se le entrega a otro.
  assert.deepEqual(s.get('proxy', 'OTRA-LLAVE'), s.get('proxy'))
})

test('nace privada; rotar el valor no la vuelve visible, y se puede cambiar sin el valor', () => {
  const dir = tmp()
  const s = openSecretsStore(dir)
  s.set('web', 'API_KEY', 'sk-1')
  assert.deepEqual(s.list().web, [{ key: 'API_KEY', public: false }])
  assert.deepEqual(s.publicOf('web'), {}, 'una privada no sale nunca')

  s.set('web', 'PUBLIC_URL', 'https://ejemplo.com', true)
  assert.deepEqual(s.publicOf('web'), { PUBLIC_URL: 'https://ejemplo.com' })

  // Rotar el valor sin decir nada CONSERVA la visibilidad: si no, rotar una llave la
  // expondría por olvido, que es la peor forma de exponerla.
  s.set('web', 'PUBLIC_URL', 'https://otro.com')
  assert.deepEqual(s.publicOf('web'), { PUBLIC_URL: 'https://otro.com' })
  s.set('web', 'API_KEY', 'sk-2')
  assert.deepEqual(s.list().web.find((x) => x.key === 'API_KEY'), { key: 'API_KEY', public: false })

  // Y se puede tapar/destapar sin conocer el valor (quien la marca casi nunca lo tiene).
  assert.equal(s.setVisibility('web', 'PUBLIC_URL', false), true)
  assert.deepEqual(s.publicOf('web'), {})
  assert.equal(s.setVisibility('web', 'NO_EXISTE', true), false, 'lo que no está no se marca')
  assert.equal(s.get('web').PUBLIC_URL, 'https://otro.com', 'y el valor siguió intacto')

  s.setDevice(PUB, 'PORT', '8443', true)
  assert.deepEqual(s.publicOfDevice(PUB), { PORT: '8443' })
  assert.equal(s.setDeviceVisibility(PUB, 'PORT', false), true)
  assert.deepEqual(s.publicOfDevice(PUB), {})
  assert.deepEqual(s.listDevices()[PUB], [{ key: 'PORT', public: false }])
})

test('lo guardado antes de que existiera la visibilidad entra como PRIVADO', () => {
  const dir = tmp()
  // Un `secrets.json` de los de antes: valores sueltos, sin marca de nada.
  const viejo = { schemaVersion: 2, ns: { proxy: { TURN_KEY_ID: 'k-123' } }, dev: { [PUB]: { PORT: '8443' } } }
  const file = path.join(dir, 'secrets.json')
  fs.mkdirSync(dir, { recursive: true })
  const atRest = atRestFor(dir)
  writeJson(file, viejo, atRest)

  const s = openSecretsStore(dir)
  assert.equal(s.get('proxy').TURN_KEY_ID, 'k-123', 'no se pierde nada')
  assert.equal(s.get('proxy', PUB).PORT, '8443')
  assert.deepEqual(s.publicOf('proxy'), {}, 'y NADA se vuelve visible por actualizar')
  assert.deepEqual(s.publicOfDevice(PUB), {})
  assert.equal(readJson(file, null, atRest).schemaVersion, 3)
})

test('un aparato que se va se lleva sus variables; el scope ni se entera', () => {
  const dir = tmp()
  const s = openSecretsStore(dir)
  s.set('proxy', 'TURN_KEY_ID', 'compartida')
  s.setDevice(PUB, 'PORT', '8443')

  assert.equal(s.forgetDevice(PUB), 1)
  assert.deepEqual(s.listDevices(), {})
  assert.deepEqual(s.get('proxy', PUB), { TURN_KEY_ID: 'compartida' })
  assert.equal(s.forgetDevice('NUNCA-EXISTIO'), 0)
})

test('las claves y los valores se validan igual en los dos cajones', () => {
  const dir = tmp()
  const s = openSecretsStore(dir)
  for (const mal of ['minusculas', 'CON-GUION', '', 'X'.repeat(65)]) {
    assert.throws(() => s.set('proxy', mal, 'v'), /invalid key/)
    assert.throws(() => s.setDevice(PUB, mal, 'v'), /invalid key/)
  }
  assert.throws(() => s.set('proxy', 'K', ''), /non-empty/)
  assert.throws(() => s.set('MAL NS', 'K', 'v'), /invalid namespace/)
  assert.throws(() => s.setDevice('', 'K', 'v'), /device required/)
})
