/**
 * LAS PUERTAS, CON LA MAESTRA DE VERDAD Y UN REINICIO DE POR MEDIO.
 *
 * Lo que de verdad importa de una puerta no se ve en el registro de perfiles: es que, después de
 * reiniciar el servicio, la maestra se siga abriendo. Ahí es donde falló quitar la contraseña
 * (2026-10-05): el perfil decía «desbloqueado» y la maestra seguía sellada con una llave que ya
 * no existía — el perfil no podía volver a firmar el acta.
 *
 * Correr:  npm test   (node --test test/)
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const PWD = 'frase-de-prueba-larga'

let proxy, proxyUrl, startVaultManager

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  ;({ startVaultManager } = await import('../src/manager.js'))
})
after(async () => { try { await proxy?.stop() } catch (_) {} })

const arrancar = (root) => startVaultManager({ root, proxyUrl, log: () => {}, autoLockMs: 0 })

test('quitar la contraseña y reiniciar: la maestra sigue abriendo', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-e2e-'))
  let mgr = await arrancar(root)
  const id = mgr.currentId()
  await mgr.addDoor(id, { kind: 'password', password: PWD })
  await mgr.lock(id)
  await mgr.unlock(id, PWD)
  await mgr.removeDoor(id, 'password')
  mgr.close()

  mgr = await arrancar(root)
  try {
    assert.equal(mgr.profiles.isLocked(id), false, 'sin candado')
    const r = await mgr.get(id).takeMasterKey()
    assert.equal(r?.locked, false, 'y la maestra abre: se puede volver a firmar el acta')
  } finally { mgr.close() }
})

test('un perfil que nace con su llave: cerrado tras reiniciar, y la llave abre la maestra', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-e2e-'))
  let mgr = await arrancar(root)
  const id = mgr.currentId()
  const secret = crypto.randomBytes(32)
  const door = await mgr.addDoor(id, { kind: 'fido2', credId: crypto.randomBytes(16).toString('base64'), hsalt: crypto.randomBytes(32).toString('base64'), secret, label: 'YubiKey' })
  mgr.close()

  mgr = await arrancar(root)
  try {
    assert.equal(mgr.profiles.isLocked(id), true, 'nace cerrado')
    assert.equal((await mgr.get(id)?.takeMasterKey())?.locked ?? true, true, 'cerrado, la maestra no está')
    await assert.rejects(() => mgr.unlock(id, PWD), { code: 'NEEDS_SECURITY_KEY' })
    await mgr.unlock(id, { door: door.id, secret })
    const r = await mgr.get(id).takeMasterKey()
    assert.equal(r?.locked, false, 'con la llave, la maestra abre')
  } finally { mgr.close() }
})

test('un perfil que el fallo viejo dejó con la maestra sellada se recupera poniendo LA MISMA contraseña', async () => {
  const { readJson, writeJson } = await import('../src/paths.js')
  const { atRestFor } = await import('../src/atrest.js')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-e2e-'))
  const file = path.join(root, 'profiles.json')
  const VIEJA = 'la-frase-de-antes'

  // 1) Un perfil de ANTES de las puertas: verificador + `K = scrypt(contraseña, kdf.salt)`. Se
  //    acuña sin el gestor, que hoy le daría su llave al arrancar: así nacían los de entonces,
  //    con la maestra bajo la llave de la máquina.
  const { openProfiles } = await import('../src/profiles.js')
  const { installNodeGlobals } = await import('../src/node-globals.js')
  const { Identity } = await import('@dotrino/identity/node')
  installNodeGlobals(root)
  const { id } = await openProfiles(root, { autoLockMs: 0 }).migrate(async (dir) => {
    const i = await Identity.connect({ dir, atRest: atRestFor(dir) })
    try { if (!i.me?.publickey) await i.setMyNickname(''); return i.me?.publickey || null } finally { i.destroy() }
  })
  let mgr
  const salt = crypto.randomBytes(16).toString('base64')
  const kdfSalt = crypto.randomBytes(32).toString('base64')
  let reg = readJson(file, null, atRestFor(root))
  reg.profiles[0].pwd = { v: 2, salt, verifier: crypto.scryptSync(VIEJA, Buffer.from(salt, 'base64'), 32, { N: 16384, r: 8, p: 1 }).toString('base64') }
  reg.profiles[0].kdf = { v: 1, salt: kdfSalt }
  writeJson(file, reg, atRestFor(root))

  // 2) Se abre (la maestra queda sellada con esa K) y se reproduce el estado que dejaba el
  //    `password-rm` de antes: sin contraseña, con el salt, y la maestra sellada.
  mgr = await arrancar(root)
  await mgr.unlock(id, VIEJA)
  mgr.close()
  reg = readJson(file, null, atRestFor(root))
  delete reg.profiles[0].doors
  reg.profiles[0].kdf = { v: 1, salt: kdfSalt }
  writeJson(file, reg, atRestFor(root))

  mgr = await arrancar(root)
  try {
    assert.equal(mgr.profiles.isLocked(id), false)
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, true, 'el daño: sin candado y la maestra no abre')
    // Otra contraseña no puede «arreglarlo»: se para sin guardar nada.
    await assert.rejects(() => mgr.addDoor(id, { kind: 'password', password: 'una-contrasena-nueva' }), { code: 'MASTER_SEALED_ELSEWHERE' })
    assert.equal(mgr.profiles.isProtected(id), false, 'no quedó ninguna puerta a medias')
    // La de antes, sí.
    await mgr.addDoor(id, { kind: 'password', password: VIEJA })
  } finally { mgr.close() }

  mgr = await arrancar(root)
  try {
    await mgr.unlock(id, VIEJA)
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, false, 'recuperada')
  } finally { mgr.close() }
})

test('todo perfil nace con llave: contraseña vacía, y la maestra sellada con ella', async () => {
  const { readJson, writeJson } = await import('../src/paths.js')
  const { atRestFor } = await import('../src/atrest.js')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-e2e-'))
  const file = path.join(root, 'profiles.json')
  let mgr = await arrancar(root)
  const id = mgr.currentId()
  try {
    assert.equal(mgr.profiles.hasKey(id), true, 'nace con su llave')
    assert.equal(mgr.profiles.isProtected(id), false, 'y sin contraseña: abre sola')
  } finally { mgr.close() }

  mgr = await arrancar(root)
  try {
    assert.equal(mgr.profiles.isLocked(id), false)
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, false, 'tras reiniciar la maestra abre sola')
  } finally { mgr.close() }

  // La prueba de que la maestra va SELLADA con esa llave: sin la puerta vacía no abre.
  const reg = readJson(file, null, atRestFor(root))
  reg.profiles[0].doors = []
  writeJson(file, reg, atRestFor(root))
  mgr = await arrancar(root)
  try {
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, true, 'sin la llave del perfil la maestra no abre')
  } finally { mgr.close() }
})

test('un perfil de antes, sin llave, la recibe al arrancar y su maestra pasa a ella', async () => {
  const { readJson, writeJson } = await import('../src/paths.js')
  const { atRestFor } = await import('../src/atrest.js')
  const { openProfiles } = await import('../src/profiles.js')
  const { installNodeGlobals } = await import('../src/node-globals.js')
  const { Identity } = await import('@dotrino/identity/node')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-puertas-e2e-'))
  installNodeGlobals(root)
  // Como nacían antes de 0.178: sin puertas y con la maestra bajo la llave de la máquina.
  const { id } = await openProfiles(root, { autoLockMs: 0 }).migrate(async (dir) => {
    const i = await Identity.connect({ dir, atRest: atRestFor(dir) })
    try { if (!i.me?.publickey) await i.setMyNickname(''); return i.me?.publickey || null } finally { i.destroy() }
  })
  assert.equal(openProfiles(root).hasKey(id), false)

  let mgr = await arrancar(root)
  try {
    assert.equal(mgr.profiles.hasKey(id), true, 'al arrancar recibe la contraseña vacía')
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, false)
  } finally { mgr.close() }

  const file = path.join(root, 'profiles.json')
  const reg = readJson(file, null, atRestFor(root))
  reg.profiles[0].doors = []
  writeJson(file, reg, atRestFor(root))
  mgr = await arrancar(root)
  try {
    assert.equal((await mgr.get(id).takeMasterKey())?.locked, true, 'la maestra ya no está bajo la llave de la máquina')
  } finally { mgr.close() }
})
