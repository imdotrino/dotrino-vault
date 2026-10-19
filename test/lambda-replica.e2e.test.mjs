/**
 * LA RÉPLICA QUE DUERME (`lambda/`, modo `replica`).
 *
 * Proxio real (repo hermano `dotrino-proxy`, ≥ 1.8.0: el timbre `self`), una bóveda real como
 * la del cliente, almacén en memoria y KMS de mentira. Lo que tiene que pasar:
 *
 *   1. la réplica entra en la cuenta SOLO con la invitación de la bóveda y el código que el
 *      dueño aprueba en ella; el código queda en el almacén para quien lanzó el alta;
 *   2. tras el alta recibe el primer empujón (acta y sobres) y registra su timbre, que es de
 *      SU llave;
 *   3. dormida, un mensaje a su llave la despierta;
 *   4. lo que guarda en el almacén va cifrado: su llave de aparato no está en claro.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { runSession, replicaStarter, enrollReplica, replicaStatus, wakeSecret, sameSecret, PAIRING_FILE } from '../lambda/session.mjs'
import { memoryStore } from '../lambda/mirror.mjs'
import { encodeInvite } from '../lib/src/invite.js'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(here, '..', '..', 'dotrino-proxy', 'server.js')
const FAKE_KMS = path.join(here, 'fixtures', 'fake-kms.mjs')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
const log = process.env.VAULT_LOG ? console.error : () => {}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

let proxy, proxyUrl, server, wakeBase, vault, runReplica, openReplicaStore, REPLICA_SCOPE, keyLabel, enrollWithVault
const store = memoryStore()
const sesiones = []

const sesion = (opts = {}) => runSession({
  store, dir: tmp('replica-sesion-'), start: replicaStarter({ runReplica }), proxyUrl, wakeBase,
  deadline: Date.now() + 60_000, idleMs: 1500, log, ...opts
})

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  process.env.DOTRINO_KMS_KEY_ID = 'test'
  process.env.DOTRINO_KMS_SCRIPT = FAKE_KMS
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  ;({ runReplica, openReplicaStore, REPLICA_SCOPE } = await import('../src/replica.js'))
  ;({ keyLabel } = await import('@dotrino/identity/capabilities'))
  ;({ enrollWithVault } = await import('../lib/src/service.js'))
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('replica-cuenta-'), proxyUrl, log })

  server = http.createServer((req, res) => {
    req.resume()
    req.on('end', async () => {
      const u = new URL(req.url, 'http://x')
      const ok = u.pathname === '/wake' && sameSecret(u.searchParams.get('k'), await wakeSecret(store))
      res.writeHead(ok ? 202 : 403); res.end()
      if (ok) sesiones.push(sesion())
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  wakeBase = `http://127.0.0.1:${server.address().port}`
})

after(async () => {
  delete process.env.DOTRINO_KMS_KEY_ID
  delete process.env.DOTRINO_KMS_SCRIPT
  await Promise.allSettled(sesiones)
  try { vault?.close() } catch (_) {}
  await new Promise((resolve) => server?.close(resolve))
  try { await proxy?.stop() } catch (_) {}
})

const enroll = (invitation, req) => enrollReplica({
  store, dir: tmp('replica-alta-'), invitation, req, deadline: Date.now() + 30_000,
  enrollWithVault, openReplicaStore, keyLabel, scope: REPLICA_SCOPE, log
})

async function codeFor (req) {
  for (let i = 0; i < 100; i++) {
    const o = store.objects.get(PAIRING_FILE)
    const got = o && JSON.parse(o.body.toString('utf8'))
    if (got?.req === req) return got
    await sleep(100)
  }
  throw new Error('no pairing code')
}

test('la réplica entra con la invitación y el código del dueño, recibe el acta, y su llave la despierta', async () => {
  // 1. El dueño saca la invitación en su bóveda; la réplica la canjea y deja su código.
  const { qr } = await vault.startPairing({ scope: ['vault:replica'], label: 'réplica en la nube' })
  const alta = enroll(encodeInvite(qr), 'req-1')
  const pend = await codeFor('req-1')
  assert.match(pend.deviceId, /^[0-9A-F]{4}-[0-9A-F]{4}$/)
  assert.ok(pend.code, 'el código para teclear en la bóveda')
  await vault.approveDevice(pend.code)
  const r = await alta
  assert.equal(r.deviceId, pend.deviceId)

  const st = await replicaStatus({ store, dir: tmp('replica-estado-'), openReplicaStore, keyLabel })
  assert.equal(st.enrolled, true)
  assert.equal(st.deviceId, pend.deviceId)

  // 2. Primera sesión: el empujón de la bóveda y el timbre de su llave.
  const primera = await sesion({ idleMs: 2500 })
  assert.equal(primera.reason, 'idle')
  const st2 = await replicaStatus({ store, dir: tmp('replica-estado-'), openReplicaStore, keyLabel })
  assert.ok(st2.seq > 0, 'guardó el acta que le empujó la bóveda')

  // 3. Dormida, algo para SU llave la despierta.
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  try {
    const antes = sesiones.length
    c.sendByPubkey(r.device, { type: 'hola' })
    for (let i = 0; i < 50 && sesiones.length === antes; i++) await sleep(100)
    assert.equal(sesiones.length, antes + 1, 'el mensaje a su llave la despertó')
  } finally { c.close() }
  await Promise.allSettled(sesiones)

  // 4. Nada en claro: la llave privada del aparato no aparece en ningún objeto.
  const plano = [...store.objects.values()].some((o) => /"d"\s*:/.test(o.body.toString('utf8')))
  assert.equal(plano, false, 'la llave de aparato va cifrada en el almacén')
})

test('una réplica enrolada no se vuelve a enrolar', async () => {
  const { qr } = await vault.startPairing({ scope: ['vault:replica'], label: 'otra' })
  await assert.rejects(enroll(encodeInvite(qr), 'req-2'), (e) => e.code === 'already-enrolled')
})
