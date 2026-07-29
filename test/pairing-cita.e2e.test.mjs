/**
 * E2E de la INVITACIÓN CORTA con cita del proxio.
 *
 * El QR corto llevaba la dirección de la conexión (4 caracteres). Esa dirección
 * pasó a ser una instancia de 24 caracteres —para poder rutearla entre proxios—,
 * así que lo que va en el QR ahora es una CITA: 6 caracteres, un solo uso y
 * minutos de vida.
 *
 * El E2E de secretos NO cubre este camino: levanta un proxio sin identidad de
 * nodo, que por lo tanto no puede emitir citas, y el vault cae solo a la
 * invitación larga. Acá el proxio arranca CON identidad, así que se ejercita la
 * forma corta de punta a punta: emitir la cita, meterla en el QR, canjearla
 * desde el otro lado y hablarle a la instancia que devuelve.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { encodeInvite, parseInvite } from '../lib/src/invite.js'

const require = createRequire(import.meta.url)
const HERE = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(HERE, '..', '..', 'dotrino-proxy', 'server.js')

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

/** Identidad de nodo con la misma forma que la que escribe el vault. */
function fakeNodeIdentity (dir) {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicJwk = kp.publicKey.export({ format: 'jwk' })
  const privateJwk = kp.privateKey.export({ format: 'jwk' })
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'service-identity.json'), JSON.stringify({
    v: 1, ns: 'proxy', iss: 'test', enrolledAt: Date.now(),
    device: { publickey: JSON.stringify(publicJwk), privateJwk, publicJwk, label: 'test', createdAt: Date.now() }
  }))
  return dir
}

let proxy, proxyUrl, vault
/** Filtro (2 chars) del nodo de este proxio. Se DERIVA de su llave, ver abajo. */
let hint

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  // Antes del require: server.js lee la identidad del nodo al cargarse.
  const dir = fakeNodeIdentity(path.join(tmp('proxy-node-'), 'vault-service'))
  process.env.VAULT_SERVICE_DIR = dir

  // El id del nodo NO se declara: sale de hashear su llave pública, y la llave
  // acá es nueva en cada corrida. Fijar un prefijo esperado a mano (como hacía
  // este test con `PROXY_NODE_PREFIX='K7'`, una variable que ya no existe) es
  // apostar a que el hash caiga donde uno quiere. Se calcula con el mismo
  // módulo que usa el proxio, que es además lo que se quiere comprobar.
  const { loadNodeIdentity } = require(path.join(HERE, '..', '..', 'dotrino-proxy', 'nodeIdentity.js'))
  hint = loadNodeIdentity(dir).hint

  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`

  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-cita-'), proxyUrl, log: () => {} })
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('el QR corto lleva una CITA de 6 caracteres, no la instancia', async () => {
  const { qr } = await vault.startPairing({ label: 'test' })
  assert.ok(qr.conn, 'el QR corto trae dirección de encuentro')
  assert.match(qr.conn, new RegExp(`^${hint}[1-9A-Z]{4}$`), `esperaba una cita del nodo ${hint}, llegó ${qr.conn}`)
  assert.equal(qr.iss, undefined, 'la forma corta no lleva la llave maestra')
})

test('la invitación corta viaja y vuelve idéntica', async () => {
  const { qr } = await vault.startPairing({ label: 'test' })
  const inv = encodeInvite(qr)
  assert.equal(inv[0], 't', 'se emite la forma compacta corta, no la larga')
  assert.deepEqual(parseInvite(inv), qr)
})

test('cada emparejamiento estrena su propia cita (son de un solo uso)', async () => {
  const a = await vault.startPairing({ label: 'a' })
  const b = await vault.startPairing({ label: 'b' })
  assert.notEqual(a.qr.conn, b.qr.conn, 'reusar una cita ya emitida la dejaría quemada')
})

test('el otro lado canjea la cita y alcanza a la bóveda', async () => {
  const { qr } = await vault.startPairing({ label: 'aparato' })
  const { getWebSocketProxyClient, WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new (WebSocketProxyClient || getWebSocketProxyClient().constructor)({
    url: proxyUrl, enableWebRTC: false, autoReconnect: false
  })
  await client.connect()
  try {
    const r = await client.redeemPairingCode(qr.conn)
    assert.equal(r.ok, true, `el canje falló: ${r.error}`)
    assert.match(r.instance, new RegExp(`^${hint}`), 'la instancia que devuelve es del nodo que emitió la cita')

    // Y no vale una segunda vez.
    const otra = await client.redeemPairingCode(qr.conn)
    assert.equal(otra.ok, false, 'la cita tiene que quemarse al usarse')
  } finally {
    client.close()
  }
})
