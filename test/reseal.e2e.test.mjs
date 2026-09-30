/**
 * E2E: DESPUÉS DE ROTAR, LA BÓVEDA SIRVE LO VIEJO CON LA LLAVE NUEVA (dueño, 2026-09-30).
 *
 * El caso que lo pidió: la firma de facturero se guardó cerrada, el navegador que la cargó
 * salió del acta (la llave de la cuenta rotó) y el navegador que entró DESPUÉS no la podía
 * abrir. Aquí, con la bóveda y el proxio de verdad:
 *
 *   1. un aparato guarda un sobre de la cuenta en el almacén (generación N);
 *   2. se quita ese aparato → la llave rota a N+1 y la bóveda vuelve a cerrar lo guardado;
 *   3. entra un aparato nuevo, que SOLO recibe N+1, y abre lo viejo;
 *   4. el que salió no abre la versión que se sirve ahora;
 *   5. un sobre viejo que aparezca después se arregla al abrir la bóveda;
 *   6. todo sobrevive a reiniciar la bóveda.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { makeDeviceKey, makeDeviceEncKey, importDeviceEncKey } from '@dotrino/identity/capabilities'
import { decryptWithKeyring, isCekEnvelope, encryptWithCek, makeContentKey } from '@dotrino/identity/content'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
const THREAD = 'facturero.settings'

let proxy, proxyUrl, vault, dir

async function aparato (label) {
  const k = await makeDeviceKey({ label })
  const e = await makeDeviceEncKey()
  return { label, pub: k.publickey, encPub: e.encPublickey, encPriv: await importDeviceEncKey(e.encPrivateJwk) }
}

/** Lo que abre ESE aparato con lo que el acta le da, o null si no puede. */
async function abre (quien, envelope) {
  const { acta } = await vault.identity.profileActa()
  return decryptWithKeyring({ envelope, keyring: acta.keyring, myPub: quien.pub, myEncPrivateKey: quien.encPriv }).catch(() => null)
}

const genVigente = async () => (await vault.identity.contentKey()).gen
const firma = () => vault.threads.methods.listThread({ threadKey: THREAD }).find((e) => e.id === 'signature:x')

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  dir = tmp('vault-reseal-')
  vault = await startVault({ dir, proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

let viejo, nuevo, genAntes, sobreAntes

test('1. a device stores an account envelope (generation N)', async () => {
  viejo = await aparato('PCX')
  assert.equal((await vault.identity.admitMember({ pub: viejo.pub, encPub: viejo.encPub, label: 'PCX' })).wrapped, true)
  genAntes = await genVigente()
  sobreAntes = await vault.identity.sealContent('el-p12')
  assert.ok(isCekEnvelope(sobreAntes), 'the envelope carries its marker')
  assert.equal(sobreAntes.gen, genAntes)
  vault.threads.methods.importThreads({ threads: { [THREAD]: [
    { id: 'signature:x', ts: 1, envelope: sobreAntes, info: { cn: 'Seyacat' } },
    { id: 'issuer', ts: 2, ruc: '1790000000001', nextSequential: 3 }
  ] } })
  assert.equal(await abre(viejo, firma().envelope), 'el-p12')
})

test('2. removing the device rotates the key and the vault reseals what it keeps', async () => {
  await vault.revokeDevice({ sub: viejo.pub })
  const g = await genVigente()
  assert.equal(g, genAntes + 1, 'removing a device rotates the account key')
  const f = firma()
  assert.equal(f.envelope.gen, g, 'the stored envelope is now in the current generation')
  assert.ok(f.ts > 1, 'new ts so devices pull the new version')
  assert.deepEqual(f.info, { cn: 'Seyacat' }, 'the rest of the entry is intact')
  const issuer = vault.threads.methods.listThread({ threadKey: THREAD }).find((e) => e.id === 'issuer')
  assert.equal(issuer.ts, 2, 'an entry without envelopes is not touched')
})

test('3. a device that joins AFTER the rotation opens the old content', async () => {
  nuevo = await aparato('BrowserLocal')
  assert.equal((await vault.identity.admitMember({ pub: nuevo.pub, encPub: nuevo.encPub, label: 'BrowserLocal' })).wrapped, true)
  const { acta } = await vault.identity.profileActa()
  const gensDelNuevo = acta.keyring.filter((g) => g.wraps?.[nuevo.pub]).map((g) => g.gen)
  assert.deepEqual(gensDelNuevo, [await genVigente()], 'it only receives the current generation')
  assert.equal(await abre(nuevo, sobreAntes), null, 'the old envelope, as it was, it cannot open')
  assert.equal(await abre(nuevo, firma().envelope), 'el-p12', 'what the vault serves now, it opens')
})

test('4. the removed device cannot open what is served now', async () => {
  assert.equal(await abre(viejo, firma().envelope), null)
  assert.ok(!JSON.stringify(vault.threads.methods.exportThreads()).includes(sobreAntes.ct), 'the old envelope is not served')
  assert.equal(vault.threads.raw().resealed.at(-1).before.envelope.ct, sobreAntes.ct, 'but it is kept, not served')
  // Las generaciones viejas siguen en el llavero y la bóveda las tiene: el respaldo abre.
  const { acta } = await vault.identity.profileActa()
  assert.ok(acta.keyring.some((g) => g.gen === genAntes), 'the old generation stays in the keyring')
  assert.equal(await vault.identity.openContent(vault.threads.raw().resealed.at(-1).before.envelope), 'el-p12', 'the vault can open the kept backup')
})

test('5. an old envelope that shows up later is resealed when the vault opens', async () => {
  // Un aparato que estuvo apagado sube, después de la rotación, algo cerrado con la vieja.
  vault.threads.methods.importThreads({ threads: { 'eco.keys': [{ id: 'k1', ts: 5, key: sobreAntes }] } })
  await vault.takeMasterKey()
  const k1 = vault.threads.methods.listThread({ threadKey: 'eco.keys' })[0]
  assert.equal(k1.key.gen, await genVigente())
  assert.equal(await abre(nuevo, k1.key), 'el-p12')
})

test('5b. MIGRATION: envelopes stored before the marker (identity < 0.107) are resealed and marked', async () => {
  // Como salían antes: { gen, iv, ct } a secas, de la generación ACTUAL y de una vieja.
  const { acta } = await vault.identity.profileActa()
  const sinMarca = ({ t, ...resto }) => resto
  const vigenteSinMarca = sinMarca(await vault.identity.sealContent('actual'))
  const viejoSinMarca = sinMarca(sobreAntes)
  // Y uno que NO es de la cuenta (otra llave, forma idéntica): no debe bloquear nada.
  const ajeno = await encryptWithCek({ cek: await makeContentKey(), gen: 7, plaintext: 'ajeno' })
  vault.threads.methods.importThreads({ threads: { 'app.legacy': [
    { id: 'l1', ts: 20, a: vigenteSinMarca, b: viejoSinMarca, c: ajeno }
  ] } })
  assert.ok(!isCekEnvelope(vigenteSinMarca) && acta.keyring.length >= 2)

  await vault.takeMasterKey()
  const l1 = vault.threads.methods.listThread({ threadKey: 'app.legacy' })[0]
  const g = await genVigente()
  for (const k of ['a', 'b']) {
    assert.ok(isCekEnvelope(l1[k]), `${k} now carries the marker`)
    assert.equal(l1[k].gen, g)
  }
  assert.equal(await abre(nuevo, l1.a), 'actual')
  assert.equal(await abre(nuevo, l1.b), 'el-p12', 'the old unmarked one opens on the device that joined later')
  assert.deepEqual(l1.c, ajeno, 'the foreign envelope is left untouched')
  assert.ok(l1.ts > 20)
})

test('6. it survives restarting the vault', async () => {
  vault.close()
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir, proxyUrl, log: () => {} })
  assert.equal(firma().envelope.gen, await genVigente())
  assert.equal(await abre(nuevo, firma().envelope), 'el-p12')
})
