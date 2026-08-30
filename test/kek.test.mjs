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

/** Lo mínimo que el store necesita para firmar sus entradas: una llave y `signData`. */
async function identidadDePrueba () {
  const { makeDeviceKey, signWithDevice } = await import('@dotrino/identity/capabilities')
  const k = await makeDeviceKey()
  return {
    me: { publickey: k.publickey },
    signData: async (data) => ({ ...(await signWithDevice({ privateJwk: k.privateJwk, data })), publickey: k.publickey })
  }
}


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

/**
 * NACER con el KMS, que es lo único que da raíz de verdad (dueño, 2026-08-30).
 *
 * Migrar un perfil existente NO equivale: su maestra ya se escribió bajo la clave vieja,
 * y una copia del disco anterior la sigue abriendo para siempre. Lo que importa aquí es
 * que la config quede puesta ANTES de que exista un solo byte del perfil.
 */
test('un perfil puede nacer con el KMS: la config está antes que ningún dato', async () => {
  const { openProfiles } = await import('../src/profiles.js')
  const root = tmp()
  const p = openProfiles(root)
  const creado = p.add('con-kms', { kek: kmsConfig() })
  const d = p.dirOf(creado.id)

  assert.equal(readConfig(d).provider, 'command', 'nace con el proveedor puesto')
  // Lo único que puede haber en el directorio recién creado es la config: la maestra
  // todavía no existe, así que cuando se genere ya nacerá bajo la clave del KMS.
  assert.deepEqual(fs.readdirSync(d).sort(), ['atrest.json'])

  // Y la clave que usará es la del KMS, no la de la máquina.
  assert.notDeepEqual(kekFor(d), machineKey(d))
  rm(root)
})

/**
 * La OTRA forma de tener un aparato con KMS: el sitio que nace vacío esperando adoptar
 * la cuenta que trae un aparato (`pair --adopt`). Es la que importa para pasar una
 * cuenta existente, porque los perfiles son independientes y una cuenta ajena solo
 * entra por adopción — nunca «creando un perfil y enrolándolo».
 */
test('un sitio para ADOPTAR también nace con el KMS', async () => {
  const { openProfiles } = await import('../src/profiles.js')
  const root = tmp()
  const p = openProfiles(root)
  const creado = p.add('a la espera', { adopt: true, kek: kmsConfig() })
  const d = p.dirOf(creado.id)

  assert.equal(readConfig(d).provider, 'command')
  assert.equal(p.get(creado.id).adopt, true, 'sigue marcado para adoptar')
  // La llave de miembro se genera DESPUÉS, al preparar la adopción: cuando llegue, la
  // config ya está puesta y nace bajo la clave del KMS.
  assert.deepEqual(fs.readdirSync(d).sort(), ['atrest.json'])
  rm(root)
})

test('si el KMS no responde, el perfil NO se crea a medias', async () => {
  const { openProfiles } = await import('../src/profiles.js')
  const root = tmp()
  const p = openProfiles(root)

  process.env.FAKE_KMS_DOWN = '1'
  try {
    assert.throws(() => p.add('fallido', { kek: kmsConfig() }), (e) => e.code === 'kek-unavailable')
  } finally { delete process.env.FAKE_KMS_DOWN }

  assert.equal(p.list().length, 0, 'no queda un perfil registrado')
  const pDir = path.join(root, 'p')
  const restos = fs.existsSync(pDir) ? fs.readdirSync(pDir) : []
  assert.deepEqual(restos, [], 'ni un directorio a medio crear')
  rm(root)
})

test('los stores del vault funcionan igual con la clave de un KMS', async () => {
  const { openStore } = await import('../src/store.js')
  const d = tmp()
  writeConfig(d, kmsConfig())
  const id = await identidadDePrueba()

  await (await openStore(d, { identity: id })).setSetting('nota', 'CONTENIDO')
  // El estado vive ahora en el REGISTRO, una línea cifrada por operación.
  const { writerFile } = await import('../lib/src/oplog.js')
  const raw = fs.readFileSync(path.join(d, 'log', writerFile(id.me.publickey)), 'utf8')
  assert.ok(isEncrypted(raw.trim()))
  assert.ok(!raw.includes('CONTENIDO'))

  clearCache()
  assert.equal((await openStore(d, { identity: id })).getSetting('nota'), 'CONTENIDO')
  rm(d)
})

/**
 * EL FALLO DE DOCKER, que costó una cuenta entera de mentira y podría haber costado una
 * de verdad: en una imagen Alpine no hay `/etc/machine-id`, así que el material se cae al
 * `hostname` — y en Docker el hostname es el ID DEL CONTENEDOR. Con los datos en un
 * volumen (o un EBS), el ciclo normal de `docker rm` + volver a levantar cambiaba la clave
 * y dejaba la cuenta ilegible PARA SIEMPRE, con un «unable to authenticate data» por toda
 * explicación.
 *
 * Ahora se guarda una huella de quién escribió, y si no coincide se para y se explica.
 */
test('si la máquina cambió, se para y lo DICE en vez de fallar en las tripas de AES', async () => {
  const { assertSameMachine } = await import('../lib/src/kek.js')
  const d = tmp()

  assertSameMachine(d, 'maquina-uno', false)          // primera vez: anota la huella
  assert.ok(fs.existsSync(path.join(d, 'atrest.machine')))
  assertSameMachine(d, 'maquina-uno', true)           // la misma: pasa

  // Otra máquina (otro contenedor) Y con datos ya cifrados: se para.
  assert.throws(() => assertSameMachine(d, 'maquina-dos', true), (e) => {
    assert.equal(e.code, 'kek-machine-changed')
    assert.match(e.message, /container id changing/, 'el mensaje tiene que nombrar la causa más probable')
    assert.match(e.message, /Nothing was modified/)
    return true
  })
  rm(d)
})

test('sin datos todavía, cambiar de máquina NO estorba', async () => {
  const { assertSameMachine } = await import('../lib/src/kek.js')
  const d = tmp()
  // Un volumen vacío estrenado en otro contenedor es un caso legítimo: se deja pasar.
  assert.doesNotThrow(() => {
    assertSameMachine(d, 'uno', false)
    assertSameMachine(d, 'dos', false)
  })
  rm(d)
})
