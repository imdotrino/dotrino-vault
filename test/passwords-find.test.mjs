// BUSCAR UNA CONTRASEÑA POR SITIO (`dotrino-vault passwords find`). Lo que importa:
//   · encuentra por dominio, por subdominio y por passkey, con su usuario;
//   · dice a qué aparato le falta la envoltura;
//   · NO ESCRIBE: el almacén queda idéntico;
//   · nunca devuelve un valor.

import test from 'node:test'
import assert from 'node:assert/strict'
import { openSealedPasswords, importPasswordEntries, findPasswordEntries } from '../lib/src/core/passwords.js'
import { makeEncKeypair } from '@dotrino/passmanager'
import { openWrap } from '@dotrino/identity/content'
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'

async function boveda () {
  const m = new Map()
  let writes = 0
  const store = { async get (k) { return m.get(k) }, async set (k, v) { writes++; m.set(k, v) } }
  const rec = await makeEncKeypair()
  const firma = await makeDeviceKey({ label: 'maestra' })
  const members = []
  const sealed = openSealedPasswords({ store, members: () => members, canWrite: (pub) => pub === firma.publickey })
  const ctx = {
    sealed,
    openRecovery: (wrap) => openWrap({ wrap, myEncPrivateKey: rec.privateKey }),
    recipients: { recoveryPub: rec.encPub, main: [], passkeys: [] },
    author: { publickey: firma.publickey, sign: (body) => signWithDevice({ privateJwk: firma.privateJwk, publickey: firma.publickey, data: body }) }
  }
  await importPasswordEntries({
    ...ctx,
    writes: [
      { entry: { id: 'e1', title: 'Salesforce', sites: ['salesforce.com'], username: 'yo@dotrino.com', secret: 'hunter2' }, replaces: null },
      { entry: { id: 'e2', title: 'Banco', sites: [], username: 'ana', webauthn: { rpId: 'banco.com', credentialId: 'c1', userHandle: 'u', privateKey: 'PRIV' } }, replaces: null }
    ]
  })
  return { ...ctx, m, members, writes: () => writes }
}

test('passwords find: por dominio y por subdominio, con usuario y sin valores', async () => {
  const b = await boveda()
  for (const q of ['salesforce.com', 'https://login.salesforce.com/x', 'SALESFORCE.COM']) {
    const r = await findPasswordEntries({ ...b, query: q })
    assert.equal(r.sealed, true)
    assert.deepEqual(r.found.map((f) => f.id), ['e1'], q)
    const f = r.found[0]
    assert.equal(f.view.title, 'Salesforce')
    assert.equal(f.view.user, 'yo@dotrino.com')
    assert.deepEqual(f.view.sites, ['salesforce.com'])
    assert.equal(f.passkey, false)
    assert.equal(f.recovery, true)
    assert.ok(!JSON.stringify(r).includes('hunter2'), 'salió la contraseña')
    assert.ok(!('recoveryWrap' in f) && !('fields' in f), 'salieron sobres')
  }
})

test('passwords find: una passkey se encuentra por su sitio', async () => {
  const b = await boveda()
  const r = await findPasswordEntries({ ...b, query: 'banco.com' })
  assert.deepEqual(r.found.map((f) => [f.id, f.passkey, f.match, f.view.rpId]), [['e2', true, 'passkey', 'banco.com']])
  assert.ok(!JSON.stringify(r).includes('PRIV'))
})

test('passwords find: nada para otro sitio, y lo que no es un sitio se dice', async () => {
  const b = await boveda()
  const r = await findPasswordEntries({ ...b, query: 'otro.com' })
  assert.deepEqual(r.found, [])
  assert.equal(r.entries, 2)
  await assert.rejects(() => findPasswordEntries({ ...b, query: '' }), (e) => e.code === 'BAD_SITE')
})

test('passwords find: dice a qué aparato le falta, y NO ESCRIBE', async () => {
  const b = await boveda()
  const tarde = await makeEncKeypair()
  b.members.push({ pub: 'PUB-TARDE', encPub: tarde.encPub })
  const antes = JSON.stringify([...b.m])
  const n = b.writes()
  const r = await findPasswordEntries({ ...b, query: 'salesforce.com' })
  assert.deepEqual(r.found[0].missing, ['PUB-TARDE'])
  assert.equal(b.writes(), n, 'la búsqueda escribió en el almacén')
  assert.equal(JSON.stringify([...b.m]), antes)
})

test('passwords find: una bóveda sin contraseñas lo dice', async () => {
  const sealed = openSealedPasswords({ store: { async get () {}, async set () { throw new Error('no debería escribir') } } })
  const r = await findPasswordEntries({ sealed, openRecovery: async () => { throw new Error('no debería abrir') }, query: 'x.com' })
  assert.deepEqual(r, { sealed: false, entries: 0, found: [] })
})
