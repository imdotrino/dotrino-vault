/**
 * Cifrado en reposo ligado a la máquina: que el archivo copiado a otro equipo no sirva, y
 * que la migración no toque el original si algo falla.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { machineKey, atRestFor, migrateFile, isEncrypted, encryptText, decryptText } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'atrest-'))

/** Lo mínimo que el store necesita para firmar sus entradas: una llave y `signData`. */
async function identidadDePrueba () {
  const { makeDeviceKey, signWithDevice } = await import('@dotrino/identity/capabilities')
  const k = await makeDeviceKey()
  return {
    me: { publickey: k.publickey },
    signData: async (data) => ({ ...(await signWithDevice({ privateJwk: k.privateJwk, data })), publickey: k.publickey })
  }
}


test('lo cifrado se vuelve a leer, y con otra clave no', () => {
  const a = tmp(); const b = tmp()
  const blob = encryptText('{"maestra":"secreta"}', machineKey(a))
  assert.ok(isEncrypted(blob))
  assert.ok(!blob.includes('secreta'), 'el contenido no se ve')
  assert.equal(decryptText(blob, machineKey(a)), '{"maestra":"secreta"}')
  // Otro directorio = otro salt = otra clave: copiar el archivo no basta.
  assert.throws(() => decryptText(blob, machineKey(b)))
  fs.rmSync(a, { recursive: true, force: true }); fs.rmSync(b, { recursive: true, force: true })
})

test('la contraseña del perfil cambia la clave', () => {
  const d = tmp()
  const blob = encryptText('x', machineKey(d, 'clave'))
  assert.throws(() => decryptText(blob, machineKey(d)), 'sin la contraseña no abre')
  assert.equal(decryptText(blob, machineKey(d, 'clave')), 'x')
  fs.rmSync(d, { recursive: true, force: true })
})

test('migrar un archivo en claro: queda cifrado y se puede leer', () => {
  const d = tmp()
  const f = path.join(d, 'identity.json')
  fs.writeFileSync(f, '{"hola":"mundo"}')
  assert.equal(migrateFile(f, machineKey(d)), 'migrado')
  const raw = fs.readFileSync(f, 'utf8')
  assert.ok(isEncrypted(raw))
  assert.ok(!raw.includes('mundo'))
  assert.equal(migrateFile(f, machineKey(d)), 'ya-cifrado', 'migrar dos veces no rompe nada')

  const ar = atRestFor(d)
  assert.equal(ar.decrypt(raw), '{"hola":"mundo"}')
  assert.equal(ar.decrypt('{"en":"claro"}'), '{"en":"claro"}', 'lo que ya está en claro se lee igual')
  fs.rmSync(d, { recursive: true, force: true })
})

test('sin archivo no hay nada que migrar', () => {
  const d = tmp()
  assert.equal(migrateFile(path.join(d, 'no-existe.json'), machineKey(d)), 'sin-archivo')
  fs.rmSync(d, { recursive: true, force: true })
})

/**
 * La brecha que esto cierra: el contenido del USUARIO (árbol, hilos, perfil) y los
 * SECRETOS de servicios se escribían en claro; solo la maestra iba cifrada. Cada store
 * cifra ahora con la misma clave ligada a la máquina, y un archivo de una instalación
 * anterior se lee igual y queda cifrado al abrirlo.
 */
test('los stores del vault escriben CIFRADO, y migran lo que venía en claro', async () => {
  const { openStore } = await import('../src/store.js')
  const { openThreadStore } = await import('../src/threadStore.js')
  const { openSecretsStore } = await import('../src/secretsStore.js')
  const d = tmp()

  // Una instalación anterior: los tres archivos, en claro.
  fs.writeFileSync(path.join(d, 'vault.json'), JSON.stringify({ schemaVersion: 1, tree: { id: 'root', children: [] }, settings: { nota: 'ARBOL' } }))
  fs.writeFileSync(path.join(d, 'threads.json'), JSON.stringify({ v: 1, threads: { k: [{ id: '1', ts: 1, texto: 'HILO' }] }, opens: {} }))
  fs.writeFileSync(path.join(d, 'secrets.json'), JSON.stringify({ schemaVersion: 1, ns: { proxy: { TURN_KEY_ID: 'TOKEN' } } }))

  // Abrir basta para migrar: no se le pide nada al usuario.
  // El store MIGRA lo que había en `vault.json` al registro y aparta el archivo viejo:
  // no se conservan dos verdades para lo mismo.
  const idPrueba = await identidadDePrueba()
  const st = await openStore(d, { identity: idPrueba })
  assert.equal(st.getSetting('nota'), 'ARBOL')
  assert.equal(st.migrados, 1, 'se trajo el ajuste que había')
  assert.ok(!fs.existsSync(path.join(d, 'vault.json')), 'el archivo viejo se aparta')
  assert.equal(openThreadStore(d).methods.listThread({ threadKey: 'k' })[0].texto, 'HILO')
  // Un v1 en claro se lee igual: el store lo sube a v3 y sigue sirviendo sin sellar
  // (sellar exige la contraseña, y abrir no debe pedirla).
  assert.equal(openSecretsStore(d).bundleFor('proxy').entries.TURN_KEY_ID.v, 'TOKEN')

  for (const [f, secreto] of [['threads.json', 'HILO'], ['secrets.json', 'TOKEN']]) {
    const raw = fs.readFileSync(path.join(d, f), 'utf8')
    assert.ok(isEncrypted(raw), f + ' tiene que quedar cifrado')
    assert.ok(!raw.includes(secreto), f + ' no puede dejar el contenido a la vista')
  }
  // `vault.json` ya no existe: su contenido vive en el REGISTRO, cifrado línea a línea.
  const { writerFile } = await import('../lib/src/oplog.js')
  const registro = fs.readFileSync(path.join(d, 'log', writerFile(idPrueba.me.publickey)), 'utf8')
  assert.ok(isEncrypted(registro.trim()), 'el registro va cifrado')
  assert.ok(!registro.includes('ARBOL'), 'y no deja el ajuste a la vista')
  fs.rmSync(d, { recursive: true, force: true })
})

test('el salt viaja con los datos: mover un perfil sin él los dejaría ilegibles', async () => {
  const { openSecretsStore } = await import('../src/secretsStore.js')
  const source = tmp(); const target = tmp()
  // Pública: así no hace falta sellador ni contraseña, que aquí no es lo que se prueba.
  await openSecretsStore(source).set('proxy', 'TURN_KEY_ID', 'TOKEN', true)

  // Migración legacy → dir del perfil, tal como la hace profiles.js.
  for (const f of ['secrets.json', 'atrest.salt']) fs.renameSync(path.join(source, f), path.join(target, f))
  assert.equal(openSecretsStore(target).bundleFor('proxy').entries.TURN_KEY_ID.v, 'TOKEN')

  fs.rmSync(source, { recursive: true, force: true }); fs.rmSync(target, { recursive: true, force: true })
})
