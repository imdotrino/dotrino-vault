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
  const { qr } = await vault.startPairing({ scope: ['vault:sign', 'vault:read', 'vault:store'], label: 'test', ttlMs: 60_000 })
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
    /unauthorized/
  )
})

test('con el profile locked: NO se edita el perfil ni firma la maestra, pero sí se guarda y se lee', async () => {
  const [a] = mgr.list()
  const vault = mgr.get(a.id)
  const dev = await pair(vault)

  // Sin contraseña: editar el perfil funciona.
  await store(dev, 'profileSet', { me: { nickname: 'Antes' } })
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

  await mgr.profiles.setPassword(a.id, 'frase-de-prueba-larga')
  mgr.profiles.lock(a.id)

  // Bloqueado: editar el perfil se rechaza y el dato NO cambia.
  await assert.rejects(() => store(dev, 'profileSet', { me: { nickname: 'Hackeado' } }), /profile locked/)
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

  // …pero leer el perfil y guardar contenido de las apps siguen funcionando: un reinicio
  // del PC no puede dejar las apps muertas hasta que alguien teclee la contraseña.
  assert.equal((await store(dev, 'profileGet')).me.nickname, 'Antes')
  await store(dev, 'appendMessage', { threadKey: 'chat', entry: { id: 'x', text: 'hola' } })
  await store(dev, 'recordOpen', { appId: 'chat' })

  // LA MAESTRA, EN CAMBIO, NO FIRMA CERRADA (dueño, 2026-08-31). Este test decía lo
  // contrario, y era cierto ANTES DEL MODELO DE SOBRES: entonces la bóveda tenía que
  // firmar para servir. Ya no — con los sobres no firma nada, y abierta lo que hace es
  // rehacerlos.
  //
  // Y las apps no se quedan muertas por esto, que era el miedo de la regla vieja: un
  // aparato al que el acta le da `sign` firma con SU llave y NO pasa por la bóveda. Este
  // test la llama a pelo, que es lo que ya no procede.
  await assert.rejects(() => requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } }),
    /locked/, 'cerrada, la maestra no firma')

  // Desbloqueado: se vuelve a poder editar, y la maestra vuelve a firmar si se le pide.
  await mgr.profiles.unlock(a.id, 'frase-de-prueba-larga')
  await store(dev, 'profileSet', { me: { nickname: 'Después' } })
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Después')
  const firmado = await requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } })
  assert.equal(firmado.publickey, vault.master, 'abierta sí, si alguien se lo pide')
})

test('el candado es por perfil: el otro perfil se sigue editando', async () => {
  const [a, b] = mgr.list()
  assert.equal(mgr.profiles.isProtected(a.id), true) // lo protegió el test anterior
  mgr.profiles.lock(a.id)
  const dev = await pair(mgr.get(b.id))
  await store(dev, 'profileSet', { me: { nickname: 'Trabajo' } })
  assert.equal(mgr.get(b.id).threads.methods.profileGet().me.nickname, 'Trabajo')
})

test('BLOQUEO AUTOMÁTICO: se cierra solo sin usarse, y el dispositivo sigue sirviéndose', async () => {
  // Un vault aparte con el plazo en milisegundos (en producción son 5 min): el candado
  // no puede quedarse abierto hasta que alguien lo cierre a mano — un servicio de PC no
  // se reinicia en semanas.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-autolock-e2e-'))
  const { startVaultManager } = await import('../src/manager.js')
  const m2 = await startVaultManager({ root: root2, proxyUrl, log: () => {}, autoLockMs: 300 })
  try {
    const [p] = m2.list()
    const vault = m2.get(p.id)
    const dev = await pair(vault)
    await m2.profiles.setPassword(p.id, 'frase-de-prueba-larga')

    // Recién abierto: se edita.
    await requestStore({ ...dev, method: 'profileSet', args: { me: { nickname: 'Antes' } } })
    assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

    await new Promise((r) => setTimeout(r, 450))
    assert.equal(m2.profiles.isLocked(p.id), true, 'se cerró solo, sin que nadie lo cerrara')
    await assert.rejects(
      () => requestStore({ ...dev, method: 'profileSet', args: { me: { nickname: 'Después' } } }),
      /locked/, 'y con él cerrado ya no se edita el perfil')

    // LO QUE NO SE CORTA: leer y guardar. Es lo que las apps necesitan para no quedarse
    // muertas, y no pasa por la maestra.
    assert.equal((await requestStore({ ...dev, method: 'profileGet' })).me.nickname, 'Antes')
    await requestStore({ ...dev, method: 'appendMessage', args: { threadKey: 'chat', entry: { id: 'y', text: 'sigo' } } })

    // LO QUE SÍ SE CORTA: que firme la MAESTRA. Este test decía lo contrario y era de
    // antes del modelo de sobres. Firmar no es lo que mantiene vivas a las apps: un
    // aparato al que el acta le da `sign` firma con su propia llave, sin la bóveda.
    await assert.rejects(() => requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } }),
      /locked/, 'cerrada sola, la maestra tampoco firma')

    // Y se vuelve a abrir con la misma contraseña: cerrarse solo no es olvidarla.
    await m2.profiles.unlock(p.id, 'frase-de-prueba-larga')
    await requestStore({ ...dev, method: 'profileSet', args: { me: { nickname: 'Después' } } })
    assert.equal(vault.threads.methods.profileGet().me.nickname, 'Después')
  } finally {
    try { m2.close() } catch (_) {}
  }
})
