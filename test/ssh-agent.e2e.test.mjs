/**
 * La llave SSH vive en el TELÉFONO: el agente del daemon lista la pública, y cada firma
 * es un pedido que el teléfono aprueba firmando. Aquí el «teléfono» es un par P-256 de
 * Node que firma en crudo (r‖s), igual que WebCrypto.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import net from 'node:net'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
const execFileP = promisify(execFile)

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
let proxy, proxyUrl, vault, agent, sock

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-ssh-'), proxyUrl, log: () => {} })
  const { startSshAgent } = await import('../src/sshAgent.js')
  sock = path.join(tmp('sock-'), 'a.sock')
  agent = startSshAgent({ socketPath: sock, vault: () => vault, log: () => {} })
  await new Promise((r) => setTimeout(r, 100))
})
after(async () => {
  try { agent?.close() } catch (_) {}
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

/** Un cliente ssh-agent mínimo: manda un mensaje y lee la respuesta entera. */
function agentCall (type, payload = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    const c = net.connect(sock)
    let buf = Buffer.alloc(0)
    c.on('connect', () => {
      const body = Buffer.concat([Buffer.from([type]), payload])
      const len = Buffer.alloc(4); len.writeUInt32BE(body.length)
      c.write(Buffer.concat([len, body]))
    })
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) { c.end(); resolve({ type: buf[4], payload: buf.subarray(5, 4 + buf.readUInt32BE(0)) }) }
    })
    c.on('error', reject)
    setTimeout(() => reject(new Error('agent timeout')), 20000)
  })
}
const sshStr = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]) }

test('la llave del teléfono se registra, el agente la lista, y firmar pasa por el teléfono', async () => {
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { signWithDevice } = await import('@dotrino/identity/capabilities')
  const { requestRenew } = await import('@dotrino/identity/vault/remote.js')
  const { MSG } = await import('../src/protocol.js')
  const { p256Blob, readStrings } = await import('../src/sshKeys.js')

  // El teléfono: aparato con `approve`.
  const inv = await vault.startPairing({ scope: ['vault:sign'], label: 'phone', ttlMs: 30 * 24 * 60 * 60 * 1000 })
  const phone = await enrollWithVault({ qr: inv.qr, label: 'phone', onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })
  await vault.setCaps(phone.device.publickey, ['sign', 'approve'])
  const phoneCert = (await requestRenew({ master: vault.master, proxy: proxyUrl, device: phone.device, cert: phone.cert })).cert

  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const rpc = async (data) => {
    const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
    await c.connect()
    try {
      const signed = { ...data, publickey: phone.device.publickey, ts: Date.now() }
      const { signature } = await signWithDevice({ privateJwk: phone.device.privateJwk, data: signed })
      const res = new Promise((resolve, reject) => {
        c.on('message', (_f, p) => { if (p?.type === MSG.SECRETS_RESULT) resolve(p.body); else if (p?.type === MSG.ERROR) reject(new Error(p.error)) })
        setTimeout(() => reject(new Error('timeout')), 8000)
      })
      c.sendByPubkey(vault.master, { type: MSG.SECRETS, data: signed, signature, cert: phoneCert })
      return await res
    } finally { c.close() }
  }

  // Sin llaves: el agente contesta una lista vacía (y `ssh-add -L` lo dice).
  let r = await agentCall(11)
  assert.equal(r.type, 12); assert.equal(r.payload.readUInt32BE(0), 0)

  // La llave nace en el teléfono (aquí: Node) y solo viaja la pública.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  const blob = p256Blob(jwk)
  const pubLine = `ecdsa-sha2-nistp256 ${blob.toString('base64')} phone-test`
  const added = await rpc({ op: 'ssh.key.add', pub: pubLine })
  assert.equal(added.ok, true)
  await assert.rejects(rpc({ op: 'ssh.key.add', pub: 'ssh-rsa AAAA x' }), /only ecdsa/)
  assert.equal((await rpc({ op: 'ssh.keys' })).items.length, 1)

  r = await agentCall(11)
  assert.equal(r.payload.readUInt32BE(0), 1)
  const [keyBlob, comment] = readStrings(r.payload.subarray(4), 2)
  assert.equal(keyBlob.toString('base64'), blob.toString('base64'))
  assert.equal(comment.toString(), 'phone-test')

  // `ssh-add -L` real contra el socket, si está instalado.
  // (asíncrono: el agente corre en ESTE proceso; un execFileSync lo dejaría sin responder)
  try {
    const { stdout } = await execFileP('ssh-add', ['-L'], { env: { ...process.env, SSH_AUTH_SOCK: sock }, encoding: 'utf8' })
    assert.match(stdout, /ecdsa-sha2-nistp256 .* phone-test/)
  } catch (e) { if (e.code !== 'ENOENT') throw e }

  // Firmar: el agente se queda esperando; el pedido aparece; el teléfono firma y aprueba.
  const data = Buffer.from('session-id-and-stuff')
  const flags = Buffer.alloc(4)
  const signing = agentCall(13, Buffer.concat([sshStr(blob), sshStr(data), flags]))
  await new Promise((rr) => setTimeout(rr, 600))
  const [pend] = vault.listApprovals()
  assert.equal(pend?.kind, 'ssh')
  assert.equal(pend.ssh.comment, 'phone-test')
  assert.equal(Buffer.from(pend.ssh.data, 'base64').toString(), 'session-id-and-stuff')

  // Una firma equivocada no pasa (y el ssh del usuario recibe FAILURE, no un blob roto).
  const bad = sign('sha256', Buffer.from('otra cosa'), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64')
  await assert.rejects(rpc({ op: 'approve', id: pend.id, sig: bad }), /does not verify/)
  r = await signing
  assert.equal(r.type, 5, 'FAILURE')

  // De nuevo, con la firma buena: SIGN_RESPONSE con un blob que verifica.
  const signing2 = agentCall(13, Buffer.concat([sshStr(blob), sshStr(data), flags]))
  await new Promise((rr) => setTimeout(rr, 600))
  const [pend2] = vault.listApprovals()
  const raw = sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  assert.equal((await rpc({ op: 'approve', id: pend2.id, sig: raw.toString('base64') })).ok, true)
  r = await signing2
  assert.equal(r.type, 14, 'SIGN_RESPONSE')
  const [sigBlob] = readStrings(r.payload, 1)
  const [algo, rs] = readStrings(sigBlob, 2)
  assert.equal(algo.toString(), 'ecdsa-sha2-nistp256')
  const [mr, ms] = readStrings(rs, 2)
  const strip = (b) => { while (b.length > 32) b = b.subarray(1); return Buffer.concat([Buffer.alloc(32 - b.length), b]) }
  assert.equal(verify('sha256', data, { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.concat([strip(mr), strip(ms)])), true)

  // Denegar desde el teléfono: FAILURE.
  const signing3 = agentCall(13, Buffer.concat([sshStr(blob), sshStr(data), flags]))
  await new Promise((rr) => setTimeout(rr, 600))
  const [pend3] = vault.listApprovals()
  await rpc({ op: 'deny', id: pend3.id })
  assert.equal((await signing3).type, 5)

  // Una llave que el agente no conoce: FAILURE sin molestar al teléfono.
  const other = p256Blob(generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }))
  assert.equal((await agentCall(13, Buffer.concat([sshStr(other), sshStr(data), flags]))).type, 5)
  assert.equal(vault.listApprovals().length, 0)

  // Quitar la llave.
  await rpc({ op: 'ssh.key.rm', id: added.id })
  assert.equal((await agentCall(11)).payload.readUInt32BE(0), 0)
})
