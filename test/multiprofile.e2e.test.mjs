/**
 * E2E multi-perfil: proxy real (repo hermano dotrino-proxy) + daemon del vault
 * con VARIOS perfiles vivos a la vez, cada uno con su maestra y su conexión.
 *
 * El lado dispositivo NO se simula a mano: usa el cliente oficial del ecosistema
 * (`@dotrino/identity` vault/remote.js), el mismo que corre en las apps.
 *
 * Cubre lo que promete el diseño:
 *   · dos perfiles conviven: identidades distintas, conexiones distintas
 *   · un dispositivo enrolado en un perfil NO puede tocar el otro
 *   · el candado (contraseña) bloquea EDITAR el perfil…
 *   · …y NO bloquea firmar / leer / guardar contenido de las apps
 *
 * Correr:  npm test   (node --test test/)
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { enrollDevice, requestStore, requestSign } from '@dotrino/identity/vault/remote.js'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')

let proxy, proxyUrl, mgr, root

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`

  root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-mp-e2e-'))
  const { startVaultManager } = await import('../src/manager.js')
  mgr = await startVaultManager({ root, proxyUrl, log: () => {} })
  await mgr.add('Trabajo')
})

after(async () => {
  try { mgr?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

/** Empareja un dispositivo con un perfil: QR → enroll → el dueño aprueba con el código. */
async function pair (vault) {
  const { qr } = vault.startPairing({ scope: ['vault:sign', 'vault:read', 'vault:store'], label: 'test', ttlMs: 60_000 })
  const res = await enrollDevice({
    qr: { ...qr, proxy: proxyUrl },
    onChallenge: ({ code }) => { vault.approveDevice(code).catch(() => {}) }
  })
  return { device: res.device, cert: res.cert, master: res.master, proxy: proxyUrl }
}
const store = (dev, method, args) => requestStore({ ...dev, method, args })

test('los perfiles son identidades distintas, cada una con su conexión al proxy', () => {
  const [a, b] = mgr.summary()
  assert.equal(mgr.summary().length, 2)
  assert.notEqual(a.iss, b.iss, 'maestras distintas')
  assert.notEqual(a.fingerprint, b.fingerprint)
  const ca = mgr.get(a.id).client, cb = mgr.get(b.id).client
  assert.notEqual(ca, cb, 'conexión propia por perfil (no el singleton del paquete)')
  assert.notEqual(ca.token, cb.token, 'cada perfil se identifica por separado ante el proxy')
})

test('el contenido no se cruza entre perfiles', () => {
  const [a, b] = mgr.list()
  mgr.get(a.id).threads.methods.appendMessage({ threadKey: 't', entry: { id: '1', text: 'del perfil A' } })
  assert.equal(mgr.get(a.id).threads.methods.listThread({ threadKey: 't' }).length, 1)
  assert.equal(mgr.get(b.id).threads.methods.listThread({ threadKey: 't' }).length, 0)
})

test('un dispositivo de un perfil no puede usar el otro perfil', async () => {
  const [a, b] = mgr.list()
  const dev = await pair(mgr.get(a.id))
  // Su cert es válido… pero pidiéndoselo a la maestra del OTRO perfil.
  await assert.rejects(
    () => store({ ...dev, master: mgr.get(b.id).master }, 'getStats'),
    /no autorizado/
  )
})

test('con el perfil bloqueado: NO se edita el perfil, pero sí se firma y se guarda', async () => {
  const [a] = mgr.list()
  const vault = mgr.get(a.id)
  const dev = await pair(vault)

  // Sin contraseña: editar el perfil funciona.
  await store(dev, 'profileSet', { me: { nickname: 'Antes' } })
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

  await mgr.profiles.setPassword(a.id, 'secreta')
  mgr.profiles.lock(a.id)

  // Bloqueado: editar el perfil se rechaza y el dato NO cambia.
  await assert.rejects(() => store(dev, 'profileSet', { me: { nickname: 'Hackeado' } }), /bloqueado/)
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

  // …pero leer el perfil, guardar contenido de las apps y FIRMAR siguen
  // funcionando: un reinicio del PC no puede dejar las apps muertas hasta que
  // alguien teclee la contraseña.
  assert.equal((await store(dev, 'profileGet')).me.nickname, 'Antes')
  await store(dev, 'appendMessage', { threadKey: 'chat', entry: { id: 'x', text: 'hola' } })
  await store(dev, 'recordOpen', { appId: 'chat' })
  const signed = await requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } })
  assert.ok(signed.signature, 'la maestra sigue firmando con el perfil bloqueado')
  assert.equal(signed.publickey, vault.master)

  // Desbloqueado: se vuelve a poder editar.
  await mgr.profiles.unlock(a.id, 'secreta')
  await store(dev, 'profileSet', { me: { nickname: 'Después' } })
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Después')
})

test('el candado es por perfil: el otro perfil se sigue editando', async () => {
  const [a, b] = mgr.list()
  assert.equal(mgr.profiles.isProtected(a.id), true) // lo protegió el test anterior
  mgr.profiles.lock(a.id)
  const dev = await pair(mgr.get(b.id))
  await store(dev, 'profileSet', { me: { nickname: 'Trabajo' } })
  assert.equal(mgr.get(b.id).threads.methods.profileGet().me.nickname, 'Trabajo')
})
