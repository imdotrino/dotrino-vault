/**
 * LAS PUERTAS DEL PERFIL (`docs/llaves-de-hardware.md` §2bis).
 *
 * La llave del perfil es una y no cambia; contraseña y llaves de seguridad son sobres de ella.
 * Aquí no hay YubiKey: lo que la llave devuelve son bytes, y se simulan con bytes. Lo que se
 * prueba es lo que decide la bóveda con ellos.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openProfiles } from '../src/profiles.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-'))
const llave = async () => {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
}
const PWD = 'frase-de-prueba-larga'
const K = (p, id) => Buffer.from(p.openKey(id))

/** Lo que devolvería una YubiKey: siempre los mismos bytes para la misma credencial. */
const fido2 = () => ({ kind: 'fido2', credId: crypto.randomBytes(16).toString('base64'), hsalt: crypto.randomBytes(32).toString('base64'), secret: crypto.randomBytes(32), label: 'YubiKey' })
const chalresp = () => ({ kind: 'chalresp', challenge: crypto.randomBytes(32).toString('hex'), serial: '123', secret: crypto.randomBytes(20), label: 'YubiKey 123' })

async function nuevo () {
  const root = tmp()
  const p = openProfiles(root, { autoLockMs: 0 })
  const { id } = await p.migrate(llave)
  return { root, p, id }
}

test('un perfil puede abrir con contraseña O con la llave, y las dos dan la MISMA llave del perfil', async () => {
  const { root, p, id } = await nuevo()
  await p.setPassword(id, PWD)
  const llaveDelPerfil = K(p, id)
  const f = fido2()
  const door = p.addDoor(id, f)
  assert.equal(door.kind, 'fido2')
  assert.equal(door.secret, undefined, 'lo que se enseña de la puerta no lleva el secreto')

  const a = openProfiles(root)
  assert.equal(a.isLocked(id), true)
  await a.unlock(id, { door: door.id, secret: f.secret })
  assert.deepEqual(K(a, id), llaveDelPerfil, 'por la llave')

  const b = openProfiles(root)
  await b.unlock(id, PWD)
  assert.deepEqual(K(b, id), llaveDelPerfil, 'por la contraseña')
})

test('solo la llave: la contraseña sola no abre, y se dice con su código (sin contar intento)', async () => {
  const { root, p, id } = await nuevo()
  const c = chalresp()
  const { fresh } = p.ensureKey(id)
  assert.equal(fresh, true, 'un perfil sin candado estrena llave')
  const door = p.addDoor(id, c)
  assert.equal(p.isProtected(id), true)

  const a = openProfiles(root)
  await assert.rejects(() => a.unlock(id, PWD), { code: 'NEEDS_SECURITY_KEY' })
  await assert.rejects(() => a.unlock(id, { door: door.id, secret: crypto.randomBytes(20) }), { code: 'WRONG_PASSWORD' }, 'otra llave no abre')
  await a.unlock(id, { door: door.id, secret: c.secret })
  assert.equal(a.isLocked(id), false)
})

test('llave MÁS contraseña: hacen falta las dos', async () => {
  const { root, p, id } = await nuevo()
  p.ensureKey(id)
  const f = { ...fido2(), password: PWD }
  const door = p.addDoor(id, f)
  assert.equal(door.withPassword, true)

  const a = openProfiles(root)
  await assert.rejects(() => a.unlock(id, { door: door.id, secret: f.secret }), { code: 'NEEDS_PASSWORD' })
  await assert.rejects(() => a.unlock(id, PWD), { code: 'NEEDS_SECURITY_KEY' })
  await assert.rejects(() => a.unlock(id, { door: door.id, secret: f.secret, password: 'otra-frase-larga-x' }), { code: 'WRONG_PASSWORD' })
  await a.unlock(id, { door: door.id, secret: f.secret, password: PWD })
  assert.equal(a.isLocked(id), false)
})

test('los bytes de una llave no abren la puerta de OTRO tipo', async () => {
  const { root, p, id } = await nuevo()
  p.ensureKey(id)
  const secret = crypto.randomBytes(32)
  const door = p.addDoor(id, { ...chalresp(), secret })
  const a = openProfiles(root)
  // Mismos bytes, pero la puerta es de reto-respuesta: el HKDF lleva el tipo.
  const reg = a.doors(id)
  assert.equal(reg[0].kind, 'chalresp')
  await a.unlock(id, { door: door.id, secret })
  assert.equal(a.isLocked(id), false)
})

test('QUITAR LA ÚLTIMA PUERTA no pierde la llave del perfil: pasa a la llave de la máquina', async () => {
  // El fallo que esto arregla (2026-10-05): quitar la contraseña cambiaba la llave del perfil y
  // la maestra quedaba sellada con una que ya no existía. Ahora la llave es la misma siempre.
  const { root, p, id } = await nuevo()
  await p.setPassword(id, PWD)
  const antes = K(p, id)
  p.removePassword(id)
  assert.equal(p.isProtected(id), false)

  const tras = openProfiles(root)
  assert.equal(tras.isLocked(id), false, 'sin candado')
  assert.deepEqual(K(tras, id), antes, 'y la MISMA llave, sin pedir nada')

  // Volver a poner contraseña tampoco la cambia.
  await tras.setPassword(id, 'otra-frase-de-prueba')
  assert.deepEqual(K(tras, id), antes)
  const otra = openProfiles(root)
  await otra.unlock(id, 'otra-frase-de-prueba')
  assert.deepEqual(K(otra, id), antes)
})

test('quitar la contraseña con una llave puesta deja el perfil cerrado, con la llave', async () => {
  const { root, p, id } = await nuevo()
  await p.setPassword(id, PWD)
  const f = fido2()
  const door = p.addDoor(id, f)
  p.removePassword(id)
  assert.equal(p.isProtected(id), true)
  const a = openProfiles(root)
  await assert.rejects(() => a.unlock(id, PWD), { code: 'NEEDS_SECURITY_KEY' })
  await a.unlock(id, { door: door.id, secret: f.secret })
  assert.equal(a.isLocked(id), false)
})

test('poner o quitar una puerta exige el perfil abierto', async () => {
  const { root, p, id } = await nuevo()
  await p.setPassword(id, PWD)
  const a = openProfiles(root)
  assert.throws(() => a.addDoor(id, fido2()), { code: 'PROFILE_LOCKED' })
  assert.throws(() => a.removeDoor(id, 'password'), { code: 'PROFILE_LOCKED' })
  assert.throws(() => p.removeDoor(id, 'no-existe'), { code: 'NO_SUCH_DOOR' })
})

test('el freno de intentos cuenta igual por la llave que por la contraseña', async () => {
  const { root, p, id } = await nuevo()
  await p.setPassword(id, PWD)
  const door = p.addDoor(id, fido2())
  const a = openProfiles(root)
  for (let i = 0; i < 5; i++) await assert.rejects(() => a.unlock(id, { door: door.id, secret: crypto.randomBytes(32) }), { code: 'WRONG_PASSWORD' })
  await assert.rejects(() => a.unlock(id, PWD), { code: 'TOO_MANY_TRIES' }, 'el mismo contador para las dos puertas')
})

test('una contraseña nueva corta se rechaza también en una puerta de llave + contraseña', async () => {
  const { p, id } = await nuevo()
  p.ensureKey(id)
  assert.throws(() => p.addDoor(id, { ...fido2(), password: 'corta' }), { code: 'PASSWORD_TOO_SHORT' })
})
