/**
 * De dónde sale la clave que cifra el disco (`lib/src/kek.js`).
 *
 * Lo que se prueba aquí no es criptografía: son las tres formas de perder la maestra.
 *   1. Que un perfil existente cambie de clave sin querer (no debe: sin `atrest.json`,
 *      la clave es EXACTAMENTE la de antes).
 *   2. Que editar `atrest.json` a mano estrene una DEK nueva y deje los datos ilegibles.
 *   3. Que un KMS caído nos haga caer a la clave débil sin decir nada.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  machineKey, kekFor, atRestFor, encryptText, decryptText, isEncrypted,
  rekeyDir, readConfig, writeConfig, probe
} from '../src/atrest.js'
import { clearCache } from '../lib/src/kek.js'

const FAKE_KMS = fileURLToPath(new URL('./fixtures/fake-kms.mjs', import.meta.url))
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kek-'))
const rm = (...d) => d.forEach((x) => fs.rmSync(x, { recursive: true, force: true }))

/** Config del proveedor `command` apuntando al KMS de mentira. */
const kmsConfig = (extraEnv = null) => ({
  provider: 'command',
  label: 'KMS de prueba',
  wrap: { cmd: process.execPath, args: [FAKE_KMS, 'wrap'] },
  unwrap: { cmd: process.execPath, args: [FAKE_KMS, 'unwrap'] },
  ...(extraEnv || {})
})

test('sin atrest.json nada cambia: la clave es la de siempre', () => {
  const d = tmp()
  assert.equal(readConfig(d).provider, 'machine')
  assert.deepEqual(kekFor(d), machineKey(d), 'un perfil existente no puede cambiar de clave al actualizar')
  rm(d)
})

test('con un KMS: la clave se envuelve, y la misma vuelve en el siguiente arranque', () => {
  const d = tmp()
  writeConfig(d, kmsConfig())
  const k1 = kekFor(d)
  assert.equal(k1.length, 32)
  assert.ok(fs.existsSync(path.join(d, 'atrest.kek')), 'la DEK envuelta queda en el disco')

  // El envoltorio no puede contener la clave en claro.
  const wrapped = fs.readFileSync(path.join(d, 'atrest.kek'), 'utf8')
  assert.ok(!wrapped.includes(k1.toString('base64')), 'la DEK no puede verse dentro de su envoltorio')

  clearCache() // simula reiniciar el proceso
  assert.deepEqual(kekFor(d), k1, 'al arrancar otra vez, la misma clave')
  assert.notDeepEqual(k1, machineKey(d), 'y no es la de la máquina')
  rm(d)
})

test('SIN el KMS no se abre — y NO se cae a la clave de la máquina', () => {
  const d = tmp()
  writeConfig(d, kmsConfig())
  kekFor(d)
  clearCache()

  process.env.FAKE_KMS_DOWN = '1'
  try {
    assert.throws(() => kekFor(d), (e) => e.code === 'kek-unavailable',
      'un KMS caído tiene que reventar, no degradar en silencio')
  } finally { delete process.env.FAKE_KMS_DOWN }
  rm(d)
})

test('otro KMS no abre nuestra DEK', () => {
  const d = tmp()
  writeConfig(d, kmsConfig())
  kekFor(d)
  clearCache()

  process.env.FAKE_KMS_KEY = '11'.repeat(32)
  try {
    assert.throws(() => kekFor(d), (e) => e.code === 'kek-unavailable')
  } finally { delete process.env.FAKE_KMS_KEY }
  rm(d)
})

test('editar atrest.json A MANO sobre datos ya cifrados NO estrena una DEK: avisa', () => {
  const d = tmp()
  // Un perfil normal, cifrado con la clave de la máquina.
  fs.writeFileSync(path.join(d, 'identity.json'), encryptText('{"maestra":"secreta"}', kekFor(d)))

  // Alguien cambia el proveedor a mano, que es el error que borraría la cuenta.
  writeConfig(d, kmsConfig())
  clearCache()
  assert.throws(() => kekFor(d), (e) => e.code === 'kek-needs-rekey',
    'estrenar una DEK sobre datos cifrados los dejaría ilegibles para siempre')
  assert.ok(!fs.existsSync(path.join(d, 'atrest.kek')), 'y no se escribe ninguna DEK nueva')
  rm(d)
})

test('rekey machine → KMS: los datos se siguen leyendo, y la clave vieja ya no vale', () => {
  const d = tmp()
  const secreto = '{"maestra":"no-se-puede-perder"}'
  fs.writeFileSync(path.join(d, 'identity.json'), encryptText(secreto, kekFor(d)))
  fs.writeFileSync(path.join(d, 'vault.json'), encryptText('{"arbol":1}', kekFor(d)))
  const claveVieja = machineKey(d)

  const r = rekeyDir(d, kmsConfig())
  assert.equal(r.from, 'machine'); assert.equal(r.to, 'command')
  assert.deepEqual(r.files.sort(), ['identity.json', 'vault.json'])
  assert.equal(r.backups.length, 2, 'deja copia de cada original')

  // Se lee igual, con el proveedor nuevo.
  assert.equal(atRestFor(d).decrypt(fs.readFileSync(path.join(d, 'identity.json'), 'utf8')), secreto)
  // Y ya no se abre con la clave de la máquina.
  assert.throws(() => decryptText(fs.readFileSync(path.join(d, 'identity.json'), 'utf8'), claveVieja))
  assert.equal(readConfig(d).provider, 'command')
  rm(d)
})

test('rekey de vuelta al proveedor machine: se puede deshacer', () => {
  const d = tmp()
  const secreto = '{"maestra":"ida-y-vuelta"}'
  writeConfig(d, kmsConfig())
  fs.writeFileSync(path.join(d, 'identity.json'), encryptText(secreto, kekFor(d)))

  rekeyDir(d, { provider: 'machine' })
  assert.equal(readConfig(d).provider, 'machine')
  assert.ok(!fs.existsSync(path.join(d, 'atrest.kek')), 'el envoltorio sobrante se retira')
  assert.equal(decryptText(fs.readFileSync(path.join(d, 'identity.json'), 'utf8'), machineKey(d)), secreto)
  rm(d)
})

test('si el KMS se cae A MITAD del rekey, no se toca ni un archivo', () => {
  const d = tmp()
  const secreto = '{"maestra":"intacta"}'
  const antes = encryptText(secreto, kekFor(d))
  fs.writeFileSync(path.join(d, 'identity.json'), antes)

  process.env.FAKE_KMS_DOWN = '1'
  try {
    assert.throws(() => rekeyDir(d, kmsConfig()), (e) => e.code === 'kek-unavailable')
  } finally { delete process.env.FAKE_KMS_DOWN }

  assert.equal(fs.readFileSync(path.join(d, 'identity.json'), 'utf8'), antes, 'el original, byte a byte')
  assert.equal(readConfig(d).provider, 'machine', 'y la config sigue siendo la vieja')
  rm(d)
})

test('probe: dice si el KMS responde, sin tocar los datos', () => {
  const d = tmp()
  assert.equal(probe(d).provider, 'machine')

  writeConfig(d, kmsConfig())
  assert.equal(probe(d).ok, true)
  assert.ok(!fs.existsSync(path.join(d, 'atrest.kek')), 'probar no estrena ninguna clave')

  process.env.FAKE_KMS_DOWN = '1'
  try { assert.throws(() => probe(d), (e) => e.code === 'kek-unavailable') } finally { delete process.env.FAKE_KMS_DOWN }
  rm(d)
})

/**
 * La clave es POR PERFIL, no por bóveda: cada perfil vive en su propio directorio
 * (`<vault>/p/<id>`) y lleva ahí su `atrest.json`. En la misma máquina, un perfil puede
 * ir con KMS y el de al lado con la clave de siempre — y ninguno de los dos puede abrir
 * los datos del otro.
 */
test('dos perfiles de la misma bóveda, uno con KMS y otro sin él', () => {
  const raiz = tmp()
  const uno = path.join(raiz, 'p', 'perfil-kms')
  const dos = path.join(raiz, 'p', 'perfil-normal')
  fs.mkdirSync(uno, { recursive: true }); fs.mkdirSync(dos, { recursive: true })

  writeConfig(uno, kmsConfig())
  // `dos` no lleva atrest.json a propósito: es el perfil que no se tocó.

  fs.writeFileSync(path.join(uno, 'identity.json'), encryptText('{"quien":"KMS"}', kekFor(uno)))
  fs.writeFileSync(path.join(dos, 'identity.json'), encryptText('{"quien":"MAQUINA"}', kekFor(dos)))

  assert.equal(readConfig(uno).provider, 'command')
  assert.equal(readConfig(dos).provider, 'machine')
  assert.notDeepEqual(kekFor(uno), kekFor(dos), 'cada perfil, su clave')

  // Cada uno se lee con la suya, y ninguno con la del otro.
  assert.equal(atRestFor(uno).decrypt(fs.readFileSync(path.join(uno, 'identity.json'), 'utf8')), '{"quien":"KMS"}')
  assert.equal(atRestFor(dos).decrypt(fs.readFileSync(path.join(dos, 'identity.json'), 'utf8')), '{"quien":"MAQUINA"}')
  assert.throws(() => decryptText(fs.readFileSync(path.join(uno, 'identity.json'), 'utf8'), kekFor(dos)))
  assert.throws(() => decryptText(fs.readFileSync(path.join(dos, 'identity.json'), 'utf8'), kekFor(uno)))

  // Y tumbar el KMS deja mudo SOLO al perfil que depende de él.
  clearCache()
  process.env.FAKE_KMS_DOWN = '1'
  try {
    assert.throws(() => kekFor(uno), (e) => e.code === 'kek-unavailable')
    assert.equal(atRestFor(dos).decrypt(fs.readFileSync(path.join(dos, 'identity.json'), 'utf8')), '{"quien":"MAQUINA"}',
      'el perfil sin KMS sigue abriendo con normalidad')
  } finally { delete process.env.FAKE_KMS_DOWN }
  rm(raiz)
})

test('rekey de un perfil no toca al de al lado', () => {
  const raiz = tmp()
  const uno = path.join(raiz, 'p', 'a'); const dos = path.join(raiz, 'p', 'b')
  fs.mkdirSync(uno, { recursive: true }); fs.mkdirSync(dos, { recursive: true })
  fs.writeFileSync(path.join(uno, 'identity.json'), encryptText('{"a":1}', kekFor(uno)))
  const intacto = encryptText('{"b":2}', kekFor(dos))
  fs.writeFileSync(path.join(dos, 'identity.json'), intacto)

  rekeyDir(uno, kmsConfig())

  assert.equal(readConfig(uno).provider, 'command')
  assert.equal(readConfig(dos).provider, 'machine', 'el vecino no cambia de proveedor')
  assert.equal(fs.readFileSync(path.join(dos, 'identity.json'), 'utf8'), intacto, 'ni de bytes')
  rm(raiz)
})

test('los stores del vault funcionan igual con la clave de un KMS', async () => {
  const { openStore } = await import('../src/store.js')
  const d = tmp()
  writeConfig(d, kmsConfig())

  openStore(d).setSetting('nota', 'CONTENIDO')
  const raw = fs.readFileSync(path.join(d, 'vault.json'), 'utf8')
  assert.ok(isEncrypted(raw))
  assert.ok(!raw.includes('CONTENIDO'))

  clearCache()
  assert.equal(openStore(d).getSetting('nota'), 'CONTENIDO')
  rm(d)
})
