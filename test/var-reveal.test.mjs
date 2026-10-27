/**
 * VER UNA PRIVADA DESDE LA CONSOLA (`var.reveal`, dueño 2026-10-26: «en el admin no tengo
 * botón para ver la variable; obviamente necesita aprobación si hay aprobadores»).
 *
 *   · sin nadie que apruebe en el acta, se entrega en el acto (la regla de siempre);
 *   · con aprobador, queda pendiente, y con el sí se entrega UNA vez;
 *   · NADA EN CLARO: lo pedido va sellado a una efímera de la bóveda y la respuesta, sellada a
 *     la de quien pregunta, firmada por la llave de sellado que nombra el acta;
 *   · una aprobación es por solicitud: no sirve para otro valor.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { makeEphemeralKey, openSealed } from '../lib/src/sealed.js'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

let proxy, proxyUrl, vault, consola

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-reveal-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  await vault.setSecret('demo', 'TOKEN', 's3cr3t con espacios', false)
  await vault.setSecret('demo', 'OTRA', 'otro valor', false)
  // Quien pregunta: un aparato con `admin` (la puerta lo comprueba antes de llegar aquí).
  const { enrollWithVault } = await import('../lib/src/service.js')
  const inv = await vault.startPairing({ scope: ['vault:admin'], caps: ['admin'], label: 'consola', ttlMs: 60_000 })
  let ok = null
  consola = await enrollWithVault({ qr: inv.qr, label: 'consola', withEncKey: false, onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

const caller = () => consola.device.publickey
const { seal } = await import('../lib/src/sealed.js')
/** Lo que hace la consola: pide una puerta, sella lo que quiere ver y abre lo que vuelve. */
async function pedir (key, eph) {
  const { door, ek } = await vault.vars.revealBegin({ caller: caller() })
  const enc = await seal({ ek, payload: { ns: 'demo', key, ek: eph.ek } })
  return vault.vars.reveal({ door, enc, caller: caller(), by: 'consola' })
}
const abrir = async (eph, r) => openSealed({ privateKey: eph.privateKey, enc: r.enc })

test('sin nadie que apruebe: se ve en el acto, sellado, firmado y sin nada en claro', async () => {
  const eph = await makeEphemeralKey()
  const r = await pedir('TOKEN', eph)
  assert.equal(r.pending, undefined)
  assert.deepEqual(Object.keys(r), ['enc'], 'por fuera solo va el sobre')
  assert.ok(!JSON.stringify(r).includes('TOKEN') && !JSON.stringify(r).includes('s3cr3t'), 'ni el nombre ni el valor a la vista')
  const { body, seal: firma, acta } = await abrir(eph, r)
  assert.equal(body.value, 's3cr3t con espacios')
  assert.equal(body.key, 'TOKEN')
  // FIRMADO con la llave de sellado que el acta nombra, con la efímera dentro de lo firmado.
  const { sealKeyAt } = await import('@dotrino/identity/acta')
  const { verifyDeviceSig } = await import('@dotrino/identity/capabilities')
  const pub = sealKeyAt(acta, firma.seq, firma.vault ?? null)
  assert.ok(pub, 'el acta nombra la llave que firmó')
  assert.equal(await verifyDeviceSig({ publickey: pub, data: body, signature: firma.sig }), true)
  assert.equal(body.ek, eph.ek)
  const otra = await makeEphemeralKey()
  await assert.rejects(abrir(otra, r), 'con otra llave no se abre')
})

test('una puerta es de un uso y de quien la pidió; lo que no existe se dice', async () => {
  const eph = await makeEphemeralKey()
  const { door, ek } = await vault.vars.revealBegin({ caller: caller() })
  const enc = await seal({ ek, payload: { ns: 'demo', key: 'TOKEN', ek: eph.ek } })
  await assert.rejects(vault.vars.reveal({ door, enc, caller: 'otro', by: 'x' }), (e) => e.code === 'no-door', 'de otro, no')
  await assert.rejects(vault.vars.reveal({ door, enc, caller: caller(), by: 'x' }), (e) => e.code === 'no-door', 'y ya se gastó')
  await assert.rejects(pedir('NO_ESTA', eph), (e) => e.code === 'not-found')
})

test('con quien apruebe: queda pendiente, una aprobación vale para ESE valor y una lectura', async () => {
  const { enrollWithVault } = await import('../lib/src/service.js')
  const inv = await vault.startPairing({ scope: ['vault:sign'], label: 'phone', ttlMs: 60_000 })
  let ok = null
  const phone = await enrollWithVault({ qr: inv.qr, label: 'phone', onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
  await vault.setCaps(phone.device.publickey, ['sign', 'approve'])

  const eph = await makeEphemeralKey()
  const r = await pedir('TOKEN', eph)
  assert.ok(r.pending, 'pide aprobación')
  const [pedido] = vault.listApprovals().filter((p) => p.id === r.pending)
  assert.equal(pedido.kind, 'reveal')
  const sondeo = () => vault.vars.reveal({ request: r.pending, caller: caller(), by: 'consola' })
  assert.equal((await sondeo()).pending, r.pending, 'sin respuesta, sigue esperando')

  // El teléfono dice que sí, firmado y por el proxio, como en la vida real.
  const { signWithDevice } = await import('@dotrino/identity/capabilities')
  const { requestRenew } = await import('@dotrino/identity/vault/remote.js')
  const { MSG } = await import('../src/protocol.js')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const phoneCert = (await requestRenew({ master: vault.master, proxy: proxyUrl, device: phone.device, cert: phone.cert })).cert
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  try {
    const data = { op: 'approve', id: r.pending, publickey: phone.device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: phone.device.privateJwk, data })
    const res = new Promise((resolve, reject) => {
      c.on('message', (_f, p) => { if (p?.type === MSG.SECRETS_RESULT) resolve(p); else if (p?.type === MSG.ERROR) reject(new Error(p.error)) })
      setTimeout(() => reject(new Error('timeout')), 8000)
    })
    c.sendByPubkey(vault.master, { type: MSG.SECRETS, data, signature, cert: phoneCert })
    assert.equal((await res).body.ok, true)
  } finally { c.close() }

  const dada = await sondeo()
  assert.equal((await abrir(eph, dada)).body.value, 's3cr3t con espacios', 'lo aprobado: ese valor')
  await assert.rejects(sondeo(), (e) => e.code === 'no-request', 'una sola lectura')
  // Otro valor es otra solicitud, y vuelve a pedir.
  const otro = await pedir('OTRA', eph)
  assert.ok(otro.pending && otro.pending !== r.pending, 'OTRA necesita su propia aprobación')
})
