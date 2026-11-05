/**
 * LAS PETICIONES A LA BÓVEDA VAN SELLADAS, Y SUS RESPUESTAS TAMBIÉN (`docs/sealed-requests.md`).
 *
 * Regla `encrypted` de la auditoría (dueño, 2026-10-26): nada viaja en claro por la red. Se
 * comprueba donde importa: en el CABLE. Se escuchan todas las tramas que entran y salen del
 * proxio (el de verdad, repo hermano `dotrino-proxy`) y se buscan los campos que antes iban
 * en claro: el tipo de la petición, el `machine` del aparato, el método del almacén.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { enrollDevice, requestDevices, requestApproval, checkMembership } from '@dotrino/identity/vault/remote.js'
import { makeDeviceEncKey, signWithDevice } from '@dotrino/identity/capabilities'
import { SEALED_REQUEST_TYPES, unsealedRequestsAllowed, UNSEALED_REQUESTS_UNTIL, MSG } from '../lib/src/protocol.js'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(here, '..', '..', 'dotrino-proxy', 'server.js')
const WS = require(path.join(here, '..', '..', 'dotrino-proxy', 'node_modules', 'ws'))

const MACHINE = 'Portatil-de-prueba-XYZ'
let proxy, proxyUrl, vault, frames = [], logs = []
// FUERA DE LO QUE SE MIRA: el ACTA, que viaja publicada (el aviso de alta a los miembros y la
// copia que guarda el proxio). Es pública y firmada por diseño; aquí se mira la PETICIÓN.
const isActa = (f) => /^\{"type":"acta-(put|get)"|vault\.admin\.event/.test(f)

// EL CABLE: lo que el proxio manda (send) y lo que recibe (emit 'message') de cada conexión.
const text = (d) => (typeof d === 'string' ? d : Buffer.isBuffer(d) ? d.toString('latin1') : Array.isArray(d) ? Buffer.concat(d).toString('latin1') : String(d))
const origSend = WS.prototype.send
const origEmit = WS.prototype.emit
WS.prototype.send = function (data, ...rest) { frames.push(text(data)); return origSend.call(this, data, ...rest) }
WS.prototype.emit = function (ev, data, ...rest) { if (ev === 'message') frames.push(text(data)); return origEmit.call(this, ev, data, ...rest) }

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  // Sin mostrador local: el servicio de la prueba vive en este mismo proceso y, con él,
  // saldría por el socket de esta máquina, que no toca la red. Aquí interesa el proxio.
  vault = await startVault({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'vault-sealed-')), proxyUrl, platform: { openLocalDesk: null }, log: (...a) => logs.push(a.join(' ')) })
})

after(async () => {
  WS.prototype.send = origSend
  WS.prototype.emit = origEmit
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

async function pair () {
  const { qr } = await vault.startPairing({ scope: ['vault:sign', 'vault:read', 'vault:store', 'vault:approve'], label: 'test', ttlMs: 60_000 })
  const enc = await makeDeviceEncKey()
  const res = await enrollDevice({ qr: { ...qr, proxy: proxyUrl }, encPub: enc.encPublickey, onChallenge: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })
  // `approve` lo da el acta, no el papel: se concede aquí para poder pedir la lista de pedidos.
  const m = (await vault.identity.profileActa()).acta.members.find((x) => x.pub === res.cert.sub)
  await vault.setCaps(res.cert.sub, [...new Set([...(m?.caps || []), 'approve'])])
  return { device: { ...res.device, machine: MACHINE }, cert: res.cert, master: res.master, acta: (await vault.identity.profileActa()).acta }
}

test('lo que pide el aparato y lo que contesta la bóveda no lleva nada en claro por el cable', async () => {
  const dev = await pair()
  assert.ok((dev.acta?.members || []).some((m) => m.cn === 'vault'), 'el acta nombra la llave de comunicación de la bóveda')
  frames = []
  logs = []
  const r = await requestDevices({ master: dev.master, proxy: proxyUrl, device: dev.device, cert: dev.cert, acta: dev.acta })
  assert.ok(Array.isArray(r.devices) && r.devices.length, 'la bóveda contestó')
  const a = await requestApproval({ master: dev.master, proxy: proxyUrl, device: dev.device, cert: dev.cert, acta: dev.acta, op: 'approvals' })
  assert.equal(a.op, 'approvals')
  const c = await checkMembership({ master: dev.master, proxy: proxyUrl, device: dev.device, acta: dev.acta })
  assert.equal(c.in, true)

  // El mensaje viaja como JSON dentro de JSON: sin las barras, se ve igual que en el objeto.
  const wire = frames.map((f) => f.replace(/\\/g, '')).filter((f) => !isActa(f)).join('\n')
  assert.ok(wire.includes('"sealed"'), 'por el cable va el sobre')
  for (const plain of ['vault.devices', 'vault.devices.result', 'vault.secrets', 'vault.secrets.result', 'vault.check', 'vault.checked', MACHINE, '"approvals"', '"rek"']) {
    assert.ok(!wire.includes(plain), `nada en claro: ${plain}`)
  }
  assert.ok(!logs.some((l) => /UNSEALED/.test(l)), 'la bóveda no vio ninguna petición en claro')
})

test('MIGRACIÓN (caduca 2026-12-15): un cliente viejo en claro se atiende y se dice', async () => {
  const dev = await pair()
  logs = []
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, autoReconnect: false })
  await client.connect()
  try {
    const data = { op: 'devices', publickey: dev.device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: dev.device.privateJwk, data })
    const got = new Promise((resolve) => client.on('message', (_f, p, meta) => { if (p?.type === MSG.DEVICES_RESULT || p?.type === MSG.ERROR) resolve({ p, meta }) }))
    client.sendByPubkey(dev.master, { type: MSG.DEVICES, data, signature, cert: dev.cert })
    const { p, meta } = await got
    assert.equal(p.type, MSG.DEVICES_RESULT, 'antes de la fecha, se atiende')
    assert.equal(meta.sealed, false, 'y en claro, porque no trajo a dónde sellar la respuesta')
    assert.ok(logs.some((l) => /vault\.devices arrived UNSEALED .* until 2026-12-15/.test(l)), 'y se dice en el log')
  } finally { client.close() }
})

test('la ventana de la migración tiene fecha y se cierra', () => {
  assert.equal(new Date(UNSEALED_REQUESTS_UNTIL).toISOString(), '2026-12-15T00:00:00.000Z')
  assert.equal(unsealedRequestsAllowed(UNSEALED_REQUESTS_UNTIL - 1), true)
  assert.equal(unsealedRequestsAllowed(UNSEALED_REQUESTS_UNTIL), false)
  for (const t of [MSG.SECRETS, MSG.STORE, MSG.ADMIN, MSG.DEVICES, MSG.RENEW, MSG.CHECK, MSG.SIGN]) assert.ok(SEALED_REQUEST_TYPES.includes(t), t)
})

test('un servicio pide su cajón sellado: ni el tipo, ni el cajón, ni la máquina van en claro', async () => {
  const { enrollService, fetchSecrets } = await import('../lib/src/service.js')
  await vault.setSecret('cajon-sellado', 'CLAVE', 'v-1')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:cajon-sellado'], label: 'service:cajon-sellado', ttlMs: 60_000 })
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svc-sealed-'))
  let permiso = null
  await enrollService({ qr, ns: 'cajon-sellado', dir, onCode: ({ code }) => {
    permiso = (async () => {
      const r = await vault.approveDevice(code)
      const m = (await vault.identity.profileActa()).acta.members.find((x) => x.pub === r.cert.sub)
      await vault.setCaps(r.cert.sub, [...new Set([...(m?.caps || []), 'unattended'])])
    })()
  } })
  await permiso
  frames = []
  logs = []
  assert.deepEqual(await fetchSecrets({ dir }), { CLAVE: 'v-1' })
  // FUERA DE ESTA PRUEBA: el ACTA, que viaja publicada (el aviso de alta a los miembros, la copia
  // que guarda el proxio). Es pública y firmada por diseño; lo que se mira aquí es la PETICIÓN.
  const wire = frames.map((f) => f.replace(/\\/g, '')).filter((f) => !isActa(f)).join('\n')
  assert.ok(wire.includes('"sealed"'))
  for (const plain of ['vault.secrets', '"ns":"cajon-sellado"', '"op":"secrets"', '"machine"', '"rek"']) assert.ok(!wire.includes(plain), `nada en claro: ${plain}`)
  assert.ok(!logs.some((l) => /UNSEALED/.test(l)), 'la bóveda no vio ninguna petición en claro')
})
