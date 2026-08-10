/**
 * «Este dispositivo es bóveda» (`lib/src/index.js`, el paquete `@dotrino/vault`).
 *
 * Lo que se prueba es el ENRUTADO: el dispositivo atendía solo `vault.enroll` y
 * `vault.devices`, así que una máquina enrolada contra él caducaba a los 30 días sin
 * poder renovar, y el QR corto (que pide la llave con un `vault.hello`) no tenía quién
 * contestara. El núcleo de enrolamiento ya estaba probado en `enroll.test.mjs`; acá se
 * comprueba que la bóveda del navegador RESPONDE a esos mensajes, con las mismas reglas
 * que el daemon: cert vigente, no revocado y `ts` fresco.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeDeviceKey, signWithDevice, signDelegationWith, verifyDelegation } from '@dotrino/identity/capabilities'
import { startDeviceVault } from '../lib/src/index.js'

/** Identidad P mínima que firma de verdad (misma forma que la del vault real). */
async function fakeIdentity () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const iss = JSON.stringify(publicJwk)
  const issued = []
  const revoked = []
  return {
    me: { publickey: iss, encryptionPubkey: null },
    iss,
    issued,
    revoked,
    async signDelegation (sub, scope, { ttlMs = 60000, label = '' } = {}) {
      const iat = Date.now()
      const cert = await signDelegationWith(pair.privateKey, iss, {
        sub, scope, iat, exp: iat + ttlMs, nonce: crypto.randomUUID()
      })
      issued.push({ nonce: cert.nonce, sub, scope, iat, exp: cert.exp, label })
      return { cert }
    },
    async signData (data) {
      const bytes = new TextEncoder().encode(JSON.stringify(data))
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, pair.privateKey, bytes)
      return { signature: Buffer.from(new Uint8Array(sig)).toString('base64'), publickey: iss }
    },
    async listDelegations () { return { issued, revoked } },
    async revokeDelegation (nonce) { revoked.push({ nonce }); return { ok: true, nonce } }
  }
}

/** Transporte de mentira: acumula lo enviado y deja disparar mensajes entrantes. */
function fakeClient () {
  const sent = []
  const handlers = {}
  return {
    sent,
    url: 'wss://test.invalid',
    token: 'tok-vault',
    on (ev, fn) { (handlers[ev] ||= []).push(fn) },
    emit (ev, ...a) { for (const fn of handlers[ev] || []) fn(...a) },
    send (to, obj) { sent.push({ to, ...obj }) },
    sendByPubkey (pub, obj) { sent.push({ pub, ...obj }) },
    async identify () { return { ok: true } },
    async requestPairingCode () { return { code: 'ABC123' } },
    close () {}
  }
}

/** Levanta la bóveda del dispositivo con el transporte de mentira. */
async function mount () {
  const identity = await fakeIdentity()
  const client = fakeClient()
  const vault = await startDeviceVault(identity, { client })
  client.sent.length = 0   // fuera el identify del arranque
  return { identity, client, vault }
}

/** Enrola una máquina «a mano» (el flujo con código ya está probado en enroll.test). */
async function enrolledMachine (identity, { ttlMs = 60_000, label = 'agente' } = {}) {
  const device = await makeDeviceKey({ label })
  const { cert } = await identity.signDelegation(device.publickey, ['vault:sign'], { ttlMs, label })
  return { device, cert }
}

/** Petición firmada por la máquina, como la manda `@dotrino/identity`. */
async function signedByDevice (device, cert, data) {
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  return { data, signature, cert }
}

test('RENEW: una máquina con cert vigente obtiene uno fresco sin aprobación', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)

  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: Date.now() })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  const out = client.sent.at(-1)
  assert.equal(out.type, 'vault.renewed', 'la bóveda del dispositivo tiene que renovar, no ignorar')
  const v = await verifyDelegation({ cert: out.cert, expectedSub: device.publickey, expectedScope: 'vault:sign' })
  assert.equal(v.ok, true, v.reason)
  assert.ok(out.cert.exp > cert.exp, 'el cert nuevo extiende la ventana')
  assert.notEqual(out.cert.nonce, cert.nonce)
  assert.equal(identity.issued.at(-1).label, 'agente', 'conserva el label del cert original')
  vault.close()
})

test('RENEW: un cert REVOCADO no se renueva (ahí toca re-emparejar)', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)
  await identity.revokeDelegation(cert.nonce)

  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: Date.now() })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  assert.equal(client.sent.at(-1).type, 'vault.error')
  assert.match(client.sent.at(-1).error, /unauthorized/)
  vault.close()
})

test('RENEW: una petición vieja se rechaza por `ts` (anti-replay)', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)

  const stale = Date.now() - 10 * 60 * 1000
  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: stale })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  assert.equal(client.sent.at(-1).type, 'vault.error')
  assert.match(client.sent.at(-1).error, /stale/)
  vault.close()
})

test('HELLO: el QR corto obtiene la llave, y fuera de un emparejamiento no hay respuesta', async () => {
  const { identity, client, vault } = await mount()

  client.emit('message', 'tok-dev', { type: 'vault.hello', sn: 'inventado' })
  await new Promise((r) => setTimeout(r, 40))
  assert.equal(client.sent.at(-1).type, 'vault.error', 'sin sesión abierta no se contesta quién eres')

  const { qr } = await vault.startPairing({ label: 'cel' })
  assert.ok(qr.sn, 'el QR corto trae el nonce de sesión')
  client.emit('message', 'tok-dev', { type: 'vault.hello', sn: qr.sn })
  await new Promise((r) => setTimeout(r, 40))

  const ok = client.sent.at(-1)
  assert.equal(ok.type, 'vault.hello.ok')
  assert.equal(ok.body.iss, identity.iss)
  assert.equal(ok.body.sn, qr.sn, 'la respuesta queda atada a ESTA sesión')
  vault.close()
})
