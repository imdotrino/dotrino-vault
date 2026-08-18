/**
 * El sellador de verdad. `secrets-store.test.mjs` prueba la FORMA con un sellador
 * falso; aquí se prueba que la criptografía cumple lo que el diseño promete:
 *
 *   · sin la contraseña no se abre la copia maestra,
 *   · un miembro abre la CEK con SOLO su llave privada (sin conocer al emisor),
 *   · y rotar deja al de antes fuera de verdad.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { makeSealer, WrongPassword } from '../src/sealer.js'
import { makeDeviceEncKey, importDeviceEncKey } from '@dotrino/identity'
import { openWrap } from '@dotrino/identity/content'

const s = makeSealer()
const clave = (txt) => crypto.scryptSync(txt, 'sal-de-prueba', 32, { N: 16384, r: 8, p: 1 })

/** Un miembro como los del acta: su llave de firma es irrelevante aquí. */
async function miembro (pub) {
  const enc = await makeDeviceEncKey()
  return { pub, encPub: enc.encPublickey, priv: enc.encPrivateJwk }
}

test('la copia maestra: solo se abre con la contraseña correcta', async () => {
  const k = clave('la-buena')
  const blob = await s.sealMaster({ 'ns:proxy': 'cek-de-prueba' }, k)

  assert.deepEqual(await s.openMaster(blob, k), { 'ns:proxy': 'cek-de-prueba' })
  await assert.rejects(() => s.openMaster(blob, clave('la-mala')), WrongPassword)

  // Y el blob no lleva el contenido a la vista.
  assert.equal(JSON.stringify(blob).includes('cek-de-prueba'), false)
  // Sin llave tampoco: no hay camino que no pase por la contraseña.
  await assert.rejects(() => s.openMaster(blob, null), WrongPassword)
})

test('primer arranque: sin copia maestra devuelve un mapa vacio, no un error', async () => {
  assert.deepEqual(await s.openMaster(null, clave('x')), {})
})

test('el valor va cifrado y vuelve igual', async () => {
  const k = clave('frase')
  const master = await s.openMaster(null, k)
  const cek = await s.cekFor(master, 'ns:proxy')

  const sobre = await s.encrypt(cek, 'la-clave-de-turn')
  assert.equal(JSON.stringify(sobre).includes('la-clave-de-turn'), false, 'nada en claro')
  assert.equal(await s.decrypt(master, sobre, 'ns:proxy'), 'la-clave-de-turn')

  // Con la CEK de otro cajón no se abre.
  await s.cekFor(master, 'ns:geo')
  await assert.rejects(() => s.decrypt(master, sobre, 'ns:geo'))
})

test('un miembro abre la CEK con SOLO su privada, sin conocer al emisor', async () => {
  const k = clave('frase')
  const master = await s.openMaster(null, k)
  const cek = await s.cekFor(master, 'ns:proxy')

  const a = await miembro('pub-A')
  const b = await miembro('pub-B')
  const { wraps, sinLlave } = await s.wrapFor(cek, [a, b])
  assert.deepEqual(sinLlave, [])

  // Esto es lo que hará el agente: solo tiene su JWK privado.
  const privA = await importDeviceEncKey(a.priv)
  const suya = await openWrap({ wrap: wraps['pub-A'], myEncPrivateKey: privA })
  assert.equal(suya, cek, 'A recupera la CEK sin saber nada del vault')

  // Y con la llave de A no se abre la envoltura de B.
  await assert.rejects(() => openWrap({ wrap: wraps['pub-B'], myEncPrivateKey: privA }))
})

test('un miembro SIN llave de cifrado se reporta, no revienta', async () => {
  const master = await s.openMaster(null, clave('frase'))
  const cek = await s.cekFor(master, 'ns:proxy')
  const a = await miembro('pub-A')

  const { wraps, sinLlave } = await s.wrapFor(cek, [a, { pub: 'pub-viejo', encPub: null }])
  assert.deepEqual(Object.keys(wraps), ['pub-A'])
  assert.deepEqual(sinLlave, ['pub-viejo'])
})

test('rotar deja fuera al de antes: la CEK nueva no abre lo viejo ni al reves', async () => {
  const k = clave('frase')
  const master = await s.openMaster(null, k)
  const vieja = await s.cekFor(master, 'ns:proxy')
  const sobreViejo = await s.encrypt(vieja, 'secreto')

  const nueva = await s.newCek(master, 'ns:proxy')
  assert.notEqual(nueva, vieja)

  // El sobre viejo ya no se abre con lo que hay en la copia maestra.
  await assert.rejects(() => s.decrypt(master, sobreViejo, 'ns:proxy'))
  // Y el que se selle ahora, sí.
  assert.equal(await s.decrypt(master, await s.encrypt(nueva, 'secreto'), 'ns:proxy'), 'secreto')
})

test('la CEK NUNCA se envuelve a la boveda: solo salen los miembros pedidos', async () => {
  const master = await s.openMaster(null, clave('frase'))
  const cek = await s.cekFor(master, 'ns:proxy')
  const a = await miembro('pub-A')

  const { wraps } = await s.wrapFor(cek, [a])
  assert.deepEqual(Object.keys(wraps), ['pub-A'], 'ni una envoltura de mas')
})
