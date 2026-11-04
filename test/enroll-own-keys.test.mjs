/**
 * UN APARATO QUE YA ERA ALGUIEN entra a la cuenta con SUS llaves (enrollWithVault con
 * `device` / `enc`). Lo pide un túnel que se generó su identidad sin bóveda: su dirección
 * sale de su llave, y emparejarlo no puede cambiarla.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

let proxy, proxyUrl, vault

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-own-'), proxyUrl, log: () => {} })
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('enrollWithVault con device/enc: entra con esas llaves, no con otras', async () => {
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { makeDeviceKey, makeDeviceEncKey } = await import('@dotrino/identity/capabilities')
  const d = await makeDeviceKey({ label: 'tunnel' })
  const e = await makeDeviceEncKey()
  const inv = await vault.startPairing({ scope: ['vault:sign'], label: 'tunnel', ttlMs: 60_000 })
  let ok = null
  const res = await enrollWithVault({
    qr: inv.qr, label: 'tunnel',
    device: { publickey: d.publickey, privateJwk: d.privateJwk },
    enc: { publickey: e.encPublickey, privateJwk: e.encPrivateJwk },
    onCode: ({ code }) => { ok = vault.approveDevice(code) }
  })
  await ok
  assert.equal(res.device.publickey, d.publickey, 'la misma llave de firma')
  assert.equal(res.enc.publickey, e.encPublickey, 'la misma llave de cifrado')
  assert.equal(res.cert.sub, d.publickey, 'el papel es de esa llave')
})

test('enrollWithVault rechaza un device a medias', async () => {
  const { enrollWithVault } = await import('../lib/src/service.js')
  await assert.rejects(enrollWithVault({ qr: { sn: 'x', iss: 'y' }, device: { publickey: 'p' } }), /device needs publickey and privateJwk/)
})
