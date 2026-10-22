/**
 * LOS QUE SALIERON SE BORRAN SOLOS (dueño, 2026-10-22). La bóveda solo atiende al acta, pero a
 * un aparato de las actas de la ventana que ya no está le contesta una cosa: si pregunta si
 * sigue dentro, recibe su aviso de expulsión —firmado una vez, al salir— y se borra, aunque el
 * que se le mandó al echarlo no le llegara. Y a quien nunca estuvo, nada.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { makeDeviceKey } from '@dotrino/identity/capabilities'
import { checkMembership } from '@dotrino/identity/vault/remote.js'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const log = process.env.VAULT_LOG ? console.error : () => {}

let proxy, proxyUrl, vault, dir

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ex-member-'))
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir, proxyUrl, log })
})
after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un aparato que salió pregunta, recibe su aviso firmado y se borra', async () => {
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { qr } = await vault.startPairing({ scope: ['vault:read'], caps: ['read'], label: 'teléfono' })
  const dev = await enrollWithVault({ qr, label: 'teléfono', withEncKey: false, onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })
  const master = dev.cert.iss

  const dentro = await checkMembership({ master, proxy: proxyUrl, device: dev.device, timeoutMs: 5000 })
  assert.equal(dentro.in, true, 'mientras está, está')

  await vault.revokeDevice({ sub: dev.device.publickey })

  let borrado = false
  const r = await checkMembership({ master, proxy: proxyUrl, device: dev.device, timeoutMs: 5000, onRevoked: () => { borrado = true } })
  assert.equal(r.in ?? false, false)
  // El aviso se verifica aparte del «no»: se le da un momento.
  for (let i = 0; i < 30 && !borrado; i++) await new Promise((resolve) => setTimeout(resolve, 100))
  assert.equal(borrado, true, 'el aviso firmado le llega y se borra')
})

test('a quien nunca estuvo en el acta no se le contesta nada', async () => {
  const k = await makeDeviceKey({ label: 'extraño' })
  const master = (await vault.profileActa?.())?.acta?.profileId || vault.master
  const r = await checkMembership({ master, proxy: proxyUrl, device: { publickey: k.publickey, privateJwk: k.privateJwk }, timeoutMs: 2000 })
  assert.equal(r.in, undefined, 'ni un «no»')
  assert.match(String(r.error || ''), /did not reply/)
})
