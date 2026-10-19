/**
 * LA SEGUNDA CONTRASEÑA: la del admin (`docs/abrir-a-distancia.md`).
 *
 * Dos puertas al mismo sitio. La llave del perfil sale de `scrypt(principal, p.kdf.salt)` y
 * es lo que destapa la maestra; una segunda contraseña no puede derivar una llave distinta,
 * así que lo que se guarda es **una copia de esa llave** cifrada con lo que sale de la
 * secundaria. Revocarla es borrar ese sobre.
 *
 * Y las tres propiedades que la hacen valer menos que la principal, que son las que fija
 * esta suite: no vale en la máquina, comparte el freno, y se quita en un segundo.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { openProfiles, SCRYPT } from '../src/profiles.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pwadmin-'))
const PRINCIPAL = 'la-del-dueño'
const ADMIN = 'la-del-admin'

/** El molino, tal cual lo hará el navegador: con los parámetros que publica la bóveda. */
const molino = (password, params) =>
  new Uint8Array(crypto.scryptSync(String(password), Buffer.from(params.salt, 'base64'),
    params.len, { N: params.N, r: params.r, p: params.p }))

/** El registro no acuña llaves: se las pide a quien llama. Basta una pública de verdad. */
const llave = async () => {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
}

async function cuenta () {
  const root = tmp()
  const P = openProfiles(root, { autoLockMs: 0 })
  const { id } = await P.migrate(llave)
  await P.setPassword(id, PRINCIPAL)
  await P.unlock(id, PRINCIPAL)
  return { root, P, id }
}

test('poner la del admin exige el perfil abierto', async () => {
  const { P, id } = await cuenta()
  P.lock(id)
  assert.throws(() => P.setSecondary(id, new Uint8Array(32)), /open the profile first/)
})

test('abre, y deja EXACTAMENTE la misma llave que la principal', async () => {
  const { P, id } = await cuenta()
  const llaveConPrincipal = Buffer.from(P.openKey(id))

  // Se pone: la bóveda publica el salt y el admin deriva. Aquí se hace en dos pasos igual
  // que en producción — primero un salt cualquiera, luego el que la bóveda guardó.
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  const params = P.secondaryParams(id)
  assert.ok(params?.salt, 'la bóveda tiene que decir con qué derivar')
  P.setSecondary(id, molino(ADMIN, params))

  P.lock(id)
  assert.equal(P.isLocked(id), true)

  await P.openWithSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  assert.equal(P.isLocked(id), false)
  assert.deepEqual(Buffer.from(P.openKey(id)), llaveConPrincipal,
    'es la MISMA llave: si no, no destaparía la maestra')
})

test('la del admin NO vale en la máquina', async () => {
  const { P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  P.setSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  P.lock(id)

  await assert.rejects(() => P.unlock(id, ADMIN), (e) => e.code === 'WRONG_PASSWORD',
    'tecleada delante de la máquina no abre: eso es lo que la hace dos factores')
  assert.equal(P.isLocked(id), true)
})

test('y la principal no abre por el camino del admin', async () => {
  const { P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  P.setSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  P.lock(id)
  await assert.rejects(() => P.openWithSecondary(id, molino(PRINCIPAL, P.secondaryParams(id))),
    (e) => e.code === 'WRONG_PASSWORD')
})

/**
 * EL MISMO CONTADOR. Si cada puerta llevara el suyo, probar por una no frenaría la otra y
 * el freno valdría la mitad.
 */
test('las dos puertas comparten el freno', async () => {
  const { P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  P.setSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  P.lock(id)

  const mala = molino('no-es', P.secondaryParams(id))
  for (let i = 0; i < 5; i++) {
    await assert.rejects(() => P.openWithSecondary(id, mala), (e) => e.code === 'WRONG_PASSWORD')
  }
  // El sexto intento ya frena — y frena TAMBIÉN el camino local, que es el punto.
  await assert.rejects(() => P.unlock(id, 'tampoco'), (e) => e.code === 'TOO_MANY_TRIES')
})

test('revocarla es borrar el sobre, y no toca la principal', async () => {
  const { P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  P.setSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  const params = P.secondaryParams(id)

  assert.equal(P.hasSecondary(id), true)
  assert.deepEqual(P.clearSecondary(id), { ok: true, had: true })
  assert.equal(P.hasSecondary(id), false)
  assert.equal(P.secondaryParams(id), null, 'sin sobre, abrir a distancia no está disponible')

  P.lock(id)
  await assert.rejects(() => P.openWithSecondary(id, molino(ADMIN, params)), (e) => e.code === 'NO_SECONDARY')
  await P.unlock(id, PRINCIPAL)
  assert.equal(P.isLocked(id), false, 'la principal sigue intacta')
})

/**
 * LOS PARÁMETROS SON PÚBLICOS Y VIAJAN. Un salt no es un secreto y ya vive en el disco
 * junto a los datos; se mandan para que el navegador derive con los MISMOS números. Si aquí
 * se cambia uno y allá no, la contraseña deja de funcionar sin que nada diga por qué.
 */
test('los parámetros del molino son los mismos que usa la bóveda', async () => {
  const { P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  const params = P.secondaryParams(id)
  assert.equal(params.N, SCRYPT.N)
  assert.equal(params.r, SCRYPT.r)
  assert.equal(params.p, SCRYPT.p)
  assert.equal(params.len, 32)
  assert.ok(Buffer.from(params.salt, 'base64').length >= 16)
})

test('el sobre guarda la llave CIFRADA, no en claro', async () => {
  const { root, P, id } = await cuenta()
  P.setSecondary(id, molino(ADMIN, { salt: Buffer.alloc(32).toString('base64'), ...SCRYPT }))
  P.setSecondary(id, molino(ADMIN, P.secondaryParams(id)))
  const llave = Buffer.from(P.openKey(id)).toString('base64')

  const crudo = fs.readFileSync(path.join(root, 'profiles.json'), 'utf8')
  assert.ok(!crudo.includes(llave), 'la llave del perfil no puede estar legible en el registro')
  assert.ok(!crudo.includes(ADMIN), 'ni la contraseña del admin')
})
