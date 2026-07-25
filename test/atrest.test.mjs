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
