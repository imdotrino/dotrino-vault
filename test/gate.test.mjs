/**
 * LA PUERTA DE LA BÓVEDA (`lib/src/core/gate.js`): solo el acta (dueño, 2026-10-22). Entrar con
 * contraseña pasa con freno; el alta, solo con un emparejamiento abierto; lo demás, nada.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createGate, makeLimiter } from '../lib/src/core/gate.js'
import { MSG } from '../lib/src/protocol.js'
import { signWithDevice } from '@dotrino/identity/capabilities'

async function key () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return { pub: JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey)), privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey) }
}
const signed = async (k, data) => ({ data, signature: (await signWithDevice({ privateJwk: k.privateJwk, publickey: k.pub, data })).signature })

test('un miembro del acta pasa; un desconocido no, aunque firme bien', async () => {
  const yo = await key(); const otro = await key()
  const gate = createGate({ MSG, acta: async () => ({ members: [{ pub: yo.pub }] }), pairing: () => false })
  const mio = await signed(yo, { op: 'vars', publickey: yo.pub, ts: Date.now() })
  assert.equal((await gate.admit('t1', { type: MSG.ADMIN, ...mio })).ok, true)
  const suyo = await signed(otro, { op: 'vars', publickey: otro.pub, ts: Date.now() })
  for (const type of [MSG.ADMIN, MSG.SECRETS, MSG.CHECK, MSG.DEVICES, MSG.SIGN, MSG.STORE]) {
    assert.equal((await gate.admit('t2', { type, ...suyo })).ok, false, type)
  }
  assert.equal(gate.stats().dropped, 6)
})

test('quien dice ser miembro sin su firma no pasa', async () => {
  const yo = await key(); const ladron = await key()
  const gate = createGate({ MSG, acta: async () => ({ members: [{ pub: yo.pub }] }), pairing: () => false })
  const falso = await signed(ladron, { op: 'vars', publickey: yo.pub, ts: Date.now() })
  assert.equal((await gate.admit('t', { type: MSG.ADMIN, ...falso })).ok, false)
  assert.equal((await gate.admit('t', { type: MSG.ADMIN, data: { publickey: yo.pub } })).ok, false, 'sin firma')
})

test('sin acta no se atiende a nadie', async () => {
  const yo = await key()
  const gate = createGate({ MSG, acta: async () => null, pairing: () => false })
  assert.equal((await gate.admit('t', { type: MSG.ADMIN, ...(await signed(yo, { publickey: yo.pub })) })).ok, false)
})

test('un tipo que no se conoce no pasa', async () => {
  const gate = createGate({ MSG, acta: async () => ({ members: [] }), pairing: () => false })
  assert.equal((await gate.admit('t', { type: 'vault.whatever' })).ok, false)
})

test('el alta solo pasa con un emparejamiento abierto', async () => {
  let abierto = false
  const gate = createGate({ MSG, acta: async () => ({ members: [] }), pairing: () => abierto })
  assert.equal((await gate.admit('t', { type: MSG.HELLO, sn: 'x' })).ok, false)
  abierto = true
  assert.equal((await gate.admit('t', { type: MSG.HELLO, sn: 'x' })).ok, true)
})

test('el aviso de otra bóveda pasa solo si lo selló un miembro', async () => {
  const yo = await key()
  const gate = createGate({ MSG, acta: async () => ({ members: [{ pub: yo.pub }] }), pairing: () => false })
  assert.equal((await gate.admit('t', { type: MSG.ADMIN_EVENT, acta: { sealedBy: yo.pub } })).ok, true)
  assert.equal((await gate.admit('t', { type: MSG.ADMIN_EVENT, acta: { sealedBy: 'otra' } })).ok, false)
})

test('entrar con contraseña: pasa sin ser miembro, con freno por conexión y global', async () => {
  let t = 0
  const limiter = makeLimiter({ perKey: 3, global: 5, windowMs: 1000, now: () => t })
  const gate = createGate({ MSG, acta: async () => ({ members: [] }), pairing: () => false, limiter })
  for (let i = 0; i < 3; i++) assert.equal((await gate.admit('a', { type: MSG.LOGIN_START })).ok, true)
  const frenado = await gate.admit('a', { type: MSG.LOGIN_START })
  assert.equal(frenado.ok, false); assert.equal(frenado.throttled, true); assert.ok(frenado.waitMs > 0)
  assert.equal((await gate.admit('b', { type: MSG.LOGIN_START })).ok, true)
  assert.equal((await gate.admit('c', { type: MSG.LOGIN_START })).ok, true)
  assert.equal((await gate.admit('d', { type: MSG.LOGIN_START })).ok, false, 'el tope global')
  t = 1000
  assert.equal((await gate.admit('a', { type: MSG.LOGIN_START })).ok, true, 'ventana nueva')
})

test('un ex-miembro con su aviso pasa solo a preguntar (CHECK), con su firma y con freno', async () => {
  const yo = await key(); const ido = await key(); const extraño = await key()
  const limiter = makeLimiter({ perKey: 1, global: 100, windowMs: 1000, now: () => 0 })
  const gate = createGate({ MSG, acta: async () => ({ members: [{ pub: yo.pub }] }), pairing: () => false, former: (pub) => pub === ido.pub, limiter })
  const pregunta = await signed(ido, { op: 'check', publickey: ido.pub, ts: Date.now() })
  assert.equal((await gate.admit('t', { type: MSG.CHECK, ...pregunta })).ok, true)
  assert.equal((await gate.admit('t', { type: MSG.ADMIN, ...pregunta })).ok, false, 'solo CHECK')
  const ajena = await signed(extraño, { op: 'check', publickey: ido.pub, ts: Date.now() })
  assert.equal((await gate.admit('u', { type: MSG.CHECK, ...ajena })).ok, false, 'con su firma')
  const otro = await signed(extraño, { op: 'check', publickey: extraño.pub, ts: Date.now() })
  assert.equal((await gate.admit('u', { type: MSG.CHECK, ...otro })).ok, false, 'quien nunca estuvo, nada')
  assert.equal((await gate.admit('t', { type: MSG.CHECK, ...pregunta })).ok, false, 'freno')
})
