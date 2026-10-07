/**
 * EL INCIDENTE DE LA TERMINAL Y EL BLOQUEO (dueño, 2026-10-07): un agente avisa de que un
 * aparato de la cuenta falló la clave tres veces; el aprobador BLOQUEA o IGNORA desde el
 * teléfono; bloqueado, la bóveda no le atiende y la lista viaja a los agentes con el acta;
 * se desbloquea solo en la bóveda o por el administrador.
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

let proxy, proxyUrl, vault, MSG, signWithDevice, WebSocketProxyClient
let terminal, phone, laptop

/** Un aparato de la cuenta: emparejado, con sus permisos y un papel al día. */
async function aparato (label, caps) {
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { requestRenew } = await import('@dotrino/identity/vault/remote.js')
  const inv = await vault.startPairing({ scope: ['vault:sign'], label, ttlMs: 60_000 })
  let ok = null
  const d = await enrollWithVault({ qr: inv.qr, label, onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
  await vault.setCaps(d.device.publickey, caps)
  const cert = (await requestRenew({ master: vault.master, proxy: proxyUrl, device: d.device, cert: d.cert })).cert
  return { device: d.device, cert, pub: d.device.publickey }
}

/** Manda un mensaje firmado a la bóveda y devuelve la respuesta (o lanza con el error). */
async function pedir (who, type, data, okTypes) {
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  try {
    data = { ...data, publickey: who.pub, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: who.device.privateJwk, data })
    const res = new Promise((resolve, reject) => {
      c.on('message', (_f, p) => {
        if (okTypes.includes(p?.type)) resolve(p)
        else if (p?.type === MSG.ERROR) reject(Object.assign(new Error(p.error), { code: p.code, reason: p.reason }))
      })
      setTimeout(() => reject(new Error('timeout')), 8000)
    })
    c.sendByPubkey(vault.master, { type, data, signature, cert: who.cert })
    return await res
  } finally { c.close() }
}
const incidente = (about, tries = 3) => pedir(terminal, MSG.INCIDENT, { op: 'incident', kind: 'bad-code', about, tries }, [MSG.INCIDENT_RESULT])
const aprobador = (op, extra = {}) => pedir(phone, MSG.SECRETS, { op, ...extra }, [MSG.SECRETS_RESULT]).then((p) => p.body)
const devices = (who) => pedir(who, MSG.DEVICES, { op: 'devices' }, [MSG.DEVICES_RESULT])

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-incident-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  ;({ MSG } = await import('../src/protocol.js'))
  ;({ signWithDevice } = await import('@dotrino/identity/capabilities'))
  ;({ WebSocketProxyClient } = await import('@dotrino/proxy-client'))
  terminal = await aparato('terminal', ['sign'])
  laptop = await aparato('laptop', ['sign'])
  phone = await aparato('phone', ['sign'])
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('sin nadie que apruebe, el incidente se anota y no se pide nada', async () => {
  const r = await incidente(laptop.pub)
  assert.equal(r.id, null)
  assert.equal(r.approvers, 0)
  assert.equal(r.blocked, false)
})

test('un incidente sobre un desconocido no es un incidente', async () => {
  await assert.rejects(incidente('no-es-nadie'), (e) => e.code === 'unknown-device')
})

test('con aprobador: el incidente llega como pedido `incident`, y BLOQUEAR cierra la puerta de la bóveda', async () => {
  await vault.setCaps(phone.pub, ['sign', 'approve'])
  const r = await incidente(laptop.pub)
  assert.ok(r.id, 'hay pedido')
  assert.equal(r.approvers, 1)

  const lista = await aprobador('approvals')
  const p = lista.items.find((it) => it.id === r.id)
  assert.ok(p, 'el aprobador lo ve')
  assert.equal(p.kind, 'incident')
  assert.ok(p.ctxSealed, 'el contexto va sellado como el de cualquier pedido')
  assert.match(p.ns, /^[0-9A-F]{4}-[0-9A-F]{4}$/, 'ns = quién reporta')

  // `approve` no significa nada aquí: se rechaza y el pedido sigue en la mesa.
  await assert.rejects(pedir(phone, MSG.SECRETS, { op: 'approve', id: r.id }, [MSG.SECRETS_RESULT]), /block or deny/)
  const otra = (await aprobador('approvals')).items.find((it) => it.kind === 'incident')
  assert.ok(otra, 'sigue pendiente')

  const b = await aprobador('block', { id: otra.id })
  assert.equal(b.op, 'block.result')
  assert.equal(b.ok, true)
  assert.equal(vault.listBlocked().length, 1)
  assert.equal(vault.listBlocked()[0].pub, laptop.pub)
  assert.equal(vault.listBlocked()[0].label, 'laptop')

  // La bóveda ya no le atiende, y le dice por qué.
  await assert.rejects(devices(laptop), (e) => e.reason === 'blocked')
  // Los demás reciben la lista con el acta.
  const d = await devices(terminal)
  assert.deepEqual(d.blocked, [laptop.pub])
  // Y los bloqueados se ven desde donde se bloquean.
  assert.equal((await aprobador('blocked')).items[0].deviceId, vault.listBlocked()[0].deviceId)
  // Otro incidente sobre el mismo no vuelve a timbrar.
  const r2 = await incidente(laptop.pub)
  assert.equal(r2.id, null)
  assert.equal(r2.blocked, true)
})

test('desbloquear es de la bóveda: el aprobador no puede, `unblock` en la bóveda sí', async () => {
  await assert.rejects(pedir(phone, MSG.SECRETS, { op: 'unblock', id: 'x' }, [MSG.SECRETS_RESULT]), /invalid namespace/)
  assert.equal(await vault.setBlocked(laptop.pub, false), true)
  assert.equal(vault.listBlocked().length, 0)
  const d = await devices(laptop)
  assert.deepEqual(d.blocked, [])
})

test('IGNORAR deja todo como estaba', async () => {
  const r = await incidente(laptop.pub)
  assert.ok(r.id)
  const d = await aprobador('deny', { id: r.id })
  assert.equal(d.op, 'deny.result')
  assert.equal(vault.listBlocked().length, 0)
  assert.equal((await aprobador('approvals')).items.filter((it) => it.kind === 'incident').length, 0)
})

test('quien no es miembro con `sign` no reporta', async () => {
  await vault.setCaps(terminal.pub, ['read'])
  await assert.rejects(incidente(laptop.pub), /unauthorized/)
})
