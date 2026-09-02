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
 *   · el candado (contraseña) bloquea EDITAR el perfil y SUELTA la maestra de memoria…
 *   · …y NO bloquea leer / guardar contenido de las apps: eso lo sirve la bóveda sin firmar
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
  // Abrir y cerrar POR EL MANAGER, no por `profiles`: son las que mueven la maestra dentro
  // y fuera de la memoria. `profiles.lock` a secas solo apunta que está cerrada.
  await mgr.unlock(a.id, 'frase-de-prueba-larga')   // aquí se SELLA la maestra que existía
  await mgr.lock(a.id)

  // Bloqueado: editar el perfil se rechaza y el dato NO cambia.
  await assert.rejects(() => store(dev, 'profileSet', { me: { nickname: 'Hackeado' } }), /profile locked/)
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

  // …pero leer el perfil y guardar contenido de las apps siguen funcionando: un reinicio
  // del PC no puede dejar las apps muertas hasta que alguien teclee la contraseña.
  assert.equal((await store(dev, 'profileGet')).me.nickname, 'Antes')
  await store(dev, 'appendMessage', { threadKey: 'chat', entry: { id: 'x', text: 'hola' } })
  await store(dev, 'recordOpen', { appId: 'chat' })

  // LA MAESTRA NO FIRMA CERRADA, y no por un `if`: NO ESTÁ. Se guarda sellada con la llave
  // que sale de la contraseña, y cerrar la suelta de memoria. Esto es lo que separa un
  // candado de una bandera — antes era un booleano al lado de una llave descifrada, y con
  // el perfil «cerrado» se firmaban certificados de 30 días igual.
  assert.equal(vault.identity.masterLocked, true, 'la privada NO está en memoria')
  await assert.rejects(() => requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } }),
    /locked/, 'cerrada, la maestra no firma')

  // Y EN EL DISCO tampoco está: se descifra el archivo con la llave de MÁQUINA —la que
  // tiene cualquiera que se lleve el disco— y aun así la privada no aparece. Eso es lo que
  // el candado no hacía antes: `atrest` protege contra llevarse el archivo, no contra tener
  // la máquina, y la maestra dependía solo de eso.
  const { atRestFor } = await import('../src/atrest.js')
  const claro = JSON.parse(atRestFor(vault.dir).decrypt(fs.readFileSync(path.join(vault.dir, 'identity.json'), 'utf8')))
  const entrada = JSON.parse(claro[Object.keys(claro).find((k) => k.endsWith('keypair'))])
  assert.ok(entrada.sealed, 'la privada está sellada con la llave de la contraseña')
  assert.equal(entrada.privateJwk, undefined, 'y no queda una copia en claro al lado')
  assert.ok(!JSON.stringify(claro).includes('"d"'), 'ni el campo `d` asoma con la llave de máquina')

  // Desbloqueado: se vuelve a poder editar, y la maestra vuelve a firmar si se le pide.
  await mgr.unlock(a.id, 'frase-de-prueba-larga')
  assert.equal(vault.identity.masterLocked, false, 'abrir la devuelve a memoria')
  await store(dev, 'profileSet', { me: { nickname: 'Después' } })
  assert.equal(vault.threads.methods.profileGet().me.nickname, 'Después')
  const firmado = await requestSign({ ...dev, payload: { op: 'hola', ts: Date.now() } })
  assert.equal(firmado.publickey, vault.master, 'abierta sí, si alguien se lo pide')
})

test('el candado es por perfil: el otro perfil se sigue editando', async () => {
  const [a, b] = mgr.list()
  assert.equal(mgr.profiles.isProtected(a.id), true) // lo protegió el test anterior
  await mgr.lock(a.id)
  const dev = await pair(mgr.get(b.id))
  await store(dev, 'profileSet', { me: { nickname: 'Trabajo' } })
  assert.equal(mgr.get(b.id).threads.methods.profileGet().me.nickname, 'Trabajo')
})

/**
 * REINICIAR EL SERVICIO CON LA MAESTRA SELLADA: `unlock` tiene que ABRIR el perfil.
 *
 * Es el caso normal y era el único en el que `unlock` no hacía nada. Un perfil con
 * contraseña guarda su maestra SELLADA, así que al arrancar el servicio no hay frase con
 * la que abrirlo y se queda fuera de `running` («could not open profile …: vault locked»).
 * `unlock` hacía `running.get(id)?.takeMasterKey?.()`, y ese `?.` sobre un perfil que no
 * está corriendo es un no-op: se marcaba desbloqueado sin abrir nada.
 *
 * Lo que se veía —y le pasó al dueño el 2026-09-02— es lo peor de todo: `status` decía
 * `🔓 desbloqueado` y CADA petición contestaba `profile is not open`. La TUI se quedaba
 * sin dispositivos, sin un solo error a la vista.
 */
test('con la maestra sellada, reiniciar y `unlock` ABRE el perfil (no solo quita el candado)', async () => {
  const root3 = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-sellada-e2e-'))
  const { startVaultManager } = await import('../src/manager.js')

  const m1 = await startVaultManager({ root: root3, proxyUrl, log: () => {} })
  let id
  try {
    id = m1.list()[0].id
    await m1.profiles.setPassword(id, 'frase-de-prueba-larga')
    await m1.unlock(id, 'frase-de-prueba-larga')   // aquí se sella la maestra
    await m1.lock(id)
  } finally { try { m1.close() } catch (_) {} }

  // EL REINICIO. Con la maestra sellada, este perfil NO puede abrirse solo: no hay frase.
  const m2 = await startVaultManager({ root: root3, proxyUrl, log: () => {} })
  try {
    // Arranque cerrado: la maestra NO está en memoria. Que llegue a `running` o no depende
    // de si su camino de arranque necesita firmar; lo que no puede pasar es lo de después.
    assert.notEqual(m2.get(id)?.identity?.masterLocked, false, 'arranca sin la maestra puesta')

    await m2.unlock(id, 'frase-de-prueba-larga')

    // Lo que fallaba: quedaba desbloqueado y sin abrir.
    assert.ok(m2.get(id), 'unlock lo ARRANCA, no solo le quita el candado')
    assert.equal(m2.profiles.isLocked(id), false)
    assert.equal(m2.get(id).identity.masterLocked, false, 'y la maestra vuelve a memoria')
    assert.ok(m2.summary().find((p) => p.id === id).fingerprint, 'ya tiene huella: está abierto de verdad')
  } finally { try { m2.close() } catch (_) {} }
})

test('una contraseña MALA no deja el perfil «abierto pero cerrado»', async () => {
  const root4 = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-mala-e2e-'))
  const { startVaultManager } = await import('../src/manager.js')

  const m1 = await startVaultManager({ root: root4, proxyUrl, log: () => {} })
  let id
  try {
    id = m1.list()[0].id
    await m1.profiles.setPassword(id, 'frase-de-prueba-larga')
    await m1.unlock(id, 'frase-de-prueba-larga')
    await m1.lock(id)
  } finally { try { m1.close() } catch (_) {} }

  const m2 = await startVaultManager({ root: root4, proxyUrl, log: () => {} })
  try {
    await assert.rejects(() => m2.unlock(id, 'la-que-no-es'), /.+/, 'se rechaza')
    // Y LO QUE IMPORTA: no se queda a medias. Un candado que dice «abierto» sin estarlo es
    // peor que uno cerrado, porque el fallo aparece después y en otro sitio.
    assert.equal(m2.profiles.isLocked(id), true, 'sigue cerrado')
    assert.equal(m2.get(id)?.identity?.masterLocked ?? true, true, 'y la maestra no está en memoria')
  } finally { try { m2.close() } catch (_) {} }
})

test('BLOQUEO AUTOMÁTICO: se cierra solo sin usarse, y el dispositivo sigue sirviéndose', async () => {
  // Un vault aparte con el plazo en milisegundos (en producción son 5 min): el candado
  // no puede quedarse abierto hasta que alguien lo cierre a mano — un servicio de PC no
  // se reinicia en semanas.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-autolock-e2e-'))
  const { startVaultManager } = await import('../src/manager.js')
  // 300 ms era muy justo por el mismo motivo que en `profiles.test.mjs`: entre medias hay
  // viajes por un proxio de verdad, y en CI eso se come la ventana antes de llegar a
  // comprobar que sigue abierta. Aquí no llegó a fallar, pero era cuestión de suerte.
  const m2 = await startVaultManager({ root: root2, proxyUrl, log: () => {}, autoLockMs: 800 })
  try {
    const [p] = m2.list()
    const vault = m2.get(p.id)
    const dev = await pair(vault)
    await m2.profiles.setPassword(p.id, 'frase-de-prueba-larga')

    // Recién abierto: se edita.
    await requestStore({ ...dev, method: 'profileSet', args: { me: { nickname: 'Antes' } } })
    assert.equal(vault.threads.methods.profileGet().me.nickname, 'Antes')

    await new Promise((r) => setTimeout(r, 1200))
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
