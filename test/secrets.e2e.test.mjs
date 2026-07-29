/**
 * E2E de SECRETOS de servicios: proxy real (repo hermano dotrino-proxy) +
 * daemon del vault + cliente de servicio (@dotrino/vault/service).
 *
 *   vault: secret set proxy TURN_KEY_ID …  →  pair --service proxy
 *   servicio: enrollService (aprobación programática) → fetchSecrets
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

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

let proxy, proxyUrl, vault, svcDir

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`

  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-e2e-'), proxyUrl, log: () => {} })
  svcDir = tmp('svc-e2e-')
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('flujo completo: set → pair --service → enroll → fetchSecrets', async () => {
  vault.setSecret('proxy', 'TURN_KEY_ID', 'k-123')
  vault.setSecret('proxy', 'TURN_KEY_API_TOKEN', 't-456')
  assert.deepEqual(vault.listSecrets(), { proxy: ['TURN_KEY_ID', 'TURN_KEY_API_TOKEN'] })

  // pair --service proxy (mismo scope que arma el daemon)
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:proxy'], label: 'servicio:proxy', ttlMs: 24 * 60 * 60 * 1000 })

  const { enrollService, fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const { device, cert } = await enrollService({
    qr, ns: 'proxy', dir: svcDir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })
  assert.ok(device?.publickey && cert?.sig)
  assert.deepEqual(cert.scope, ['vault:secrets:proxy'])
  assert.equal(readServiceIdentity(svcDir)?.ns, 'proxy')

  const secrets = await fetchSecrets({ dir: svcDir })
  assert.deepEqual(secrets, { TURN_KEY_ID: 'k-123', TURN_KEY_API_TOKEN: 't-456' })
})

test('loadEnv() inyecta los secretos en process.env y PISA el .env', async () => {
  delete process.env.TURN_KEY_ID
  delete process.env.DOTRINO_ENV_OVERRIDE
  // Esto es lo que deja un `.env` cargado antes: un valor viejo ya en el entorno.
  // El vault tiene que ganarle, o rotar la llave no sirve de nada mientras quede
  // una copia rancia en la máquina.
  process.env.TURN_KEY_API_TOKEN = 'la-vieja-del-env'

  const { loadEnv } = await import('../lib/src/env.js')
  const { ns, injected, overridden, skipped } = await loadEnv({ ns: 'proxy', dir: svcDir, wait: false })

  assert.equal(ns, 'proxy')
  assert.equal(process.env.TURN_KEY_ID, 'k-123')
  assert.equal(process.env.TURN_KEY_API_TOKEN, 't-456', 'el vault manda sobre el entorno')
  assert.deepEqual(injected.sort(), ['TURN_KEY_API_TOKEN', 'TURN_KEY_ID'])
  assert.deepEqual(overridden, ['TURN_KEY_API_TOKEN'], 'se reporta lo pisado')
  assert.deepEqual(skipped, [])

  // La escotilla de depuración devuelve la precedencia clásica sin tocar código.
  process.env.TURN_KEY_API_TOKEN = 'la-del-operador'
  await loadEnv({ ns: 'proxy', dir: svcDir, wait: false, override: false })
  assert.equal(process.env.TURN_KEY_API_TOKEN, 'la-del-operador')

  // required: si falta una clave, no arranca
  await assert.rejects(
    loadEnv({ ns: 'proxy', dir: svcDir, wait: false, required: ['NO_EXISTE'] }),
    /faltan secretos/
  )
})

test('el scope corta el acceso a otro namespace', async () => {
  vault.setSecret('geo', 'DB_PASSWORD', 'nope')
  await assert.rejects(
    fetchNsWithSavedCert('geo'),
    /no autorizado: scope/
  )
})

test('un cert revocado deja de poder leer', async () => {
  const { issued } = await vault.listDevices()
  const mine = issued.find((d) => d.label === 'servicio:proxy')
  assert.ok(mine, 'el servicio enrolado aparece en delegations')
  await vault.revokeDevice(mine.nonce)
  await assert.rejects(fetchNsWithSavedCert('proxy'), /no autorizado: revoked/)
})

async function fetchNsWithSavedCert (ns) {
  const { fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const saved = readServiceIdentity(svcDir)
  return fetchSecrets({ ns, proxyUrl: saved.proxy, masterPubkey: saved.iss, device: saved.device, cert: saved.cert })
}
