// Tras rotar la llave de la cuenta, la bóveda vuelve a cerrar con la vigente los sobres
// (`t: 'dotrino-cek'`) que guarda el almacén (dueño, 2026-09-30). El caso que lo pidió: la
// firma de facturero, que un aparato emparejado DESPUÉS de una rotación no podía abrir.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { makeGeneration, encryptWithCek, decryptWithKeyring } from '@dotrino/identity/content'
import { openThreadStore } from '../src/threadStore.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'reseal-'))

async function miembro (label) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { pub: 'pub-' + label, encPub: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }), priv: pair.privateKey }
}

test('the vault reseals old-generation envelopes, keeps the old copy and does not serve it', async () => {
  const d = tmp()
  const store = openThreadStore(d)
  const boveda = await miembro('boveda'); const pcx = await miembro('pcx')
  const g1 = await makeGeneration({ members: [boveda, pcx], gen: 1 })
  const firma = await encryptWithCek({ cek: g1.cek, gen: 1, plaintext: 'p12' })
  store.methods.importThreads({ threads: { 'facturero.settings': [
    { id: 'signature:x', ts: 10, envelope: firma, info: { cn: 'yo' } },
    { id: 'issuer', ts: 11, ruc: '1790000000001' }
  ] } })

  // PCX sale (rota a la 2) y entra un navegador nuevo, que solo recibe la 2.
  const nuevo = await miembro('nuevo')
  const g2 = await makeGeneration({ members: [boveda, nuevo], gen: 2 })
  const keyring = [g1.generation, g2.generation]
  const reseal = async (env) => encryptWithCek({
    cek: g2.cek, gen: 2,
    plaintext: await decryptWithKeyring({ envelope: env, keyring, myPub: boveda.pub, myEncPrivateKey: boveda.priv })
  })
  const r = await store.resealStaleEnvelopes({ gen: 2, reseal })
  assert.deepEqual(r, { changed: 1, entries: 1 })

  const [sig, issuer] = store.methods.listThread({ threadKey: 'facturero.settings' })
  assert.equal(sig.envelope.gen, 2)
  assert.ok(sig.ts > 10, 'new ts so devices pull it')
  assert.deepEqual(sig.info, { cn: 'yo' })
  assert.equal(issuer.ts, 11, 'entries without envelopes are untouched')
  assert.equal(await decryptWithKeyring({ envelope: sig.envelope, keyring, myPub: nuevo.pub, myEncPrivateKey: nuevo.priv }), 'p12')

  // La copia vieja queda retenida, pero ningún método del almacén la sirve.
  assert.equal(store.raw().resealed.length, 1)
  assert.equal(store.raw().resealed[0].before.envelope.gen, 1)
  assert.ok(!Object.hasOwn(store.methods, 'resealStaleEnvelopes'), 'a device cannot trigger it')
  assert.ok(!JSON.stringify(store.methods.exportThreads()).includes('"gen":1'))

  // Sobrevive a reabrir (va al disco) y no repite trabajo.
  const again = openThreadStore(d)
  assert.equal(again.methods.listThread({ threadKey: 'facturero.settings' })[0].envelope.gen, 2)
  assert.deepEqual(await again.resealStaleEnvelopes({ gen: 2, reseal }), { changed: 0, entries: 0 })
  fs.rmSync(d, { recursive: true, force: true })
})

test('policy: the previous envelope is kept at least a year, then it can go', async () => {
  const { RESEALED_KEEP_MS } = await import('../src/threadStore.js')
  assert.ok(RESEALED_KEEP_MS >= 365 * 24 * 60 * 60 * 1000, 'at least one year (owner policy, 2026-09-30)')
  const d = tmp()
  const store = openThreadStore(d)
  const a = await miembro('a')
  const g1 = await makeGeneration({ members: [a], gen: 1 })
  const g2 = await makeGeneration({ members: [a], gen: 2 })
  const keyring = [g1.generation, g2.generation]
  const reseal = async (env) => encryptWithCek({ cek: g2.cek, gen: 2, plaintext: await decryptWithKeyring({ envelope: env, keyring, myPub: a.pub, myEncPrivateKey: a.priv }) })
  const viejo = await encryptWithCek({ cek: g1.cek, gen: 1, plaintext: 'x' })
  store.methods.importThreads({ threads: { t: [{ id: '1', ts: 1, env: viejo }] } })
  await store.resealStaleEnvelopes({ gen: 2, reseal })
  // Casi un año después sigue ahí; pasado el año, la siguiente pasada lo puede quitar.
  store.raw().resealed[0].at = Date.now() - (RESEALED_KEEP_MS - 60_000)
  await store.resealStaleEnvelopes({ gen: 2, reseal })
  assert.equal(store.raw().resealed.length, 1, 'still kept just before the year')
  store.raw().resealed[0].at = Date.now() - RESEALED_KEEP_MS - 60_000
  await store.resealStaleEnvelopes({ gen: 2, reseal })
  assert.equal(store.raw().resealed.length, 0, 'after the year it may go')
  fs.rmSync(d, { recursive: true, force: true })
})
