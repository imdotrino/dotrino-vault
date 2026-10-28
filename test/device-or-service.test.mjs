/**
 * DISPOSITIVO O SERVICIO, SIN RE-ENROLAR (dueño, 2026-10-28). La única diferencia es el `cn`:
 * un servicio abre su cajón y no firma por ti; un dispositivo firma como tú y no abre ningún
 * cajón. `setCapsMany([{ pub, caps, cn }])` lo cambia en el acta, con la misma llave, y el
 * llavero de los cajones se rehace solo.
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

let proxy, vault, svcDir

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  const proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-dos-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  svcDir = tmp('svc-dos-')
  const { enrollService } = await import('../lib/src/service.js')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:tun', 'vault:sign'], label: 'service:tun', ttlMs: 60_000 })
  let ok = null
  await enrollService({ qr, ns: 'tun', dir: svcDir, onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

const lib = () => import('../lib/src/service.js')
const pub = async () => (await lib()).readServiceIdentity(svcDir).device.publickey
const member = async (p) => (await vault.profileMembers()).members.find((m) => m.pub === p)

test('un servicio pasa a dispositivo y vuelve, con la misma llave', async () => {
  const { storeVars, fetchSecrets } = await lib()
  await storeVars({ dir: svcDir, vars: [{ key: 'TOKEN', value: 'uno' }] })
  assert.equal((await fetchSecrets({ dir: svcDir })).TOKEN, 'uno')
  const p = await pub()
  const caps = (await member(p)).caps

  await vault.setCapsMany([{ pub: p, caps, cn: null }])
  assert.equal((await member(p)).cn, null, 'ahora es un dispositivo')
  await assert.rejects(fetchSecrets({ dir: svcDir }), 'un dispositivo no abre el cajón')

  await vault.setCapsMany([{ pub: p, caps, cn: 'tun' }])
  assert.equal((await member(p)).cn, 'tun', 'y vuelve a ser el servicio')
  assert.equal((await fetchSecrets({ dir: svcDir })).TOKEN, 'uno', 'el llavero se rehízo: vuelve a leer su cajón')
})
