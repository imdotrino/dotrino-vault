/**
 * EL APARATO QUE SE ABRE CON USUARIO Y CONTRASEÑA, visto desde fuera.
 *
 * Lo que se fija aquí es lo que el dueño decidió el 2026-09-17: la bóveda nunca ve la
 * contraseña, un usuario que no existe no se distingue de una contraseña equivocada, cinco
 * intentos y después una espera que se duplica, el inicio de sesión no vence solo y se puede
 * cerrar, y cambiar la contraseña cierra lo que estuviera abierto.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { client as opaqueClient } from '@dotrino/opaque'
import { createLoginDesk, backoffFor, FREE_TRIES, BACKOFF_CAP_MS } from '../lib/src/passwordLogins.js'

/** Un escritorio con su estado en memoria y un reloj que se puede mover a mano. */
function desk () {
  let saved = null
  let clock = 1_700_000_000_000
  const d = createLoginDesk({
    load: () => (saved ? JSON.parse(saved) : null),
    save: (s) => { saved = JSON.stringify(s) },
    now: () => clock
  })
  return { desk: d, tick: (ms) => { clock += ms }, at: () => clock, raw: () => (saved ? JSON.parse(saved) : null) }
}

/** Lo que hace quien crea el aparato: nunca manda la contraseña, solo mensajes de OPAQUE. */
function register (d, { user, password, pub = '{"kty":"EC","x":"pub"}', label = 'equipo prestado', replace = false }) {
  const start = opaqueClient.registrationStart({ password })
  const { response } = d.registerBegin({ user, request: start.request, replace })
  const fin = opaqueClient.registrationFinish({ state: start.state, response, password })
  // El paquete de llaves lo cierra QUIEN CREA el aparato, con la llave que sale de la
  // contraseña. Aquí basta con que sea una cadena distinta por cada `exportKey`.
  const blob = 'sealed:' + fin.exportKey.slice(0, 16)
  d.registerFinish({ user, upload: fin.upload, pub, label, blob, replace })
  return { exportKey: fin.exportKey, blob }
}

function login (d, { user, password, label = '' }) {
  const start = opaqueClient.loginStart({ password })
  const { lid, response } = d.loginBegin({ user, request: start.request })
  const fin = opaqueClient.loginFinish({ state: start.state, response, password })
  return { ...d.loginEnd({ lid, finalization: fin.finalization, label }), exportKey: fin.exportKey }
}

const fails = (fn, code) => assert.throws(fn, (e) => e.code === code, `expected ${code}`)

/** Igual que `fails`, pero devuelve el error: hace falta para mirar cuánto hay que esperar. */
function grab (fn, code) {
  try { fn() } catch (e) {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`)
    return e
  }
  assert.fail(`expected ${code}, nothing was thrown`)
}

test('the password never reaches the vault, and what it stores cannot be used to guess it', () => {
  const { desk: d, raw } = desk()
  register(d, { user: 'ana', password: 'la contraseña larga de ana' })
  const stored = JSON.stringify(raw())
  assert.ok(!stored.includes('la contraseña larga de ana'), 'the password is stored somewhere')
  assert.ok(raw().setup && raw().users.ana.record, 'the OPAQUE setup and record are stored')
})

test('logging in returns the sealed keys, and the same password always opens them', () => {
  const { desk: d } = desk()
  const reg = register(d, { user: 'ana', password: 'correct horse' })
  const first = login(d, { user: 'ana', password: 'correct horse' })
  assert.equal(first.blob, reg.blob)
  assert.equal(first.exportKey, reg.exportKey, 'the key that opens the package comes from the password')
  assert.ok(first.sid)
  const second = login(d, { user: 'ana', password: 'correct horse' })
  assert.notEqual(second.sid, first.sid, 'each login is its own session')
  assert.equal(second.exportKey, reg.exportKey)
})

test('a wrong password and a user that does not exist fail the same way', () => {
  const { desk: d } = desk()
  register(d, { user: 'ana', password: 'correct horse' })
  fails(() => login(d, { user: 'ana', password: 'wrong horse' }), 'login-failed')
  fails(() => login(d, { user: 'nadie', password: 'whatever' }), 'login-failed')
})

test('five tries, and then a wait that doubles — counted when the try STARTS', () => {
  const { desk: d, tick } = desk()
  register(d, { user: 'ana', password: 'correct horse' })
  // Con la contraseña equivocada, quien prueba se entera él solo y puede no mandar el último
  // mensaje. Por eso se cuenta al empezar: aquí se prueba con el intento a medias.
  for (let i = 0; i < FREE_TRIES; i++) {
    const s = opaqueClient.loginStart({ password: 'no' })
    d.loginBegin({ user: 'ana', request: s.request })
  }
  const blocked = grab(() => login(d, { user: 'ana', password: 'correct horse' }), 'too-many-tries')
  assert.ok(blocked.waitMs > 0 && blocked.waitMs <= 60_000, 'the first wait is one minute: ' + blocked.waitMs)

  tick(60_001)
  const s6 = opaqueClient.loginStart({ password: 'no' })
  d.loginBegin({ user: 'ana', request: s6.request })
  const again = grab(() => login(d, { user: 'ana', password: 'correct horse' }), 'too-many-tries')
  assert.ok(again.waitMs > 60_000, 'the wait doubles: ' + again.waitMs)

  // Con la espera cumplida, la contraseña buena entra y reinicia la cuenta.
  tick(again.waitMs + 1)
  const ok = login(d, { user: 'ana', password: 'correct horse' })
  assert.ok(ok.sid)
  assert.equal(d.list()[0].fails, 0)
})

test('the owner can clear the wait from the vault machine', () => {
  const { desk: d } = desk()
  register(d, { user: 'ana', password: 'p' })
  for (let i = 0; i < FREE_TRIES; i++) {
    const s = opaqueClient.loginStart({ password: 'no' })
    d.loginBegin({ user: 'ana', request: s.request })
  }
  fails(() => login(d, { user: 'ana', password: 'p' }), 'too-many-tries')
  assert.deepEqual(d.clearBlock({ user: 'ana' }), { ok: true })
  assert.ok(login(d, { user: 'ana', password: 'p' }).sid, 'the wait is gone without changing the password')
  fails(() => d.clearBlock({ user: 'beto' }), 'no-user')
})

test('the wait has a cap, so a typo does not lock you out for days', () => {
  assert.equal(backoffFor(FREE_TRIES - 1), 0)
  assert.equal(backoffFor(FREE_TRIES), 60_000)
  assert.equal(backoffFor(FREE_TRIES + 1), 120_000)
  assert.equal(backoffFor(100), BACKOFF_CAP_MS)
})

test('sessions are listed and closed, and they do not expire on their own', () => {
  const { desk: d, tick } = desk()
  register(d, { user: 'ana', password: 'p' })
  const a = login(d, { user: 'ana', password: 'p', label: 'cyber' })
  const b = login(d, { user: 'ana', password: 'p' })
  tick(30 * 24 * 60 * 60_000)             // un mes después
  assert.equal(d.list()[0].sessions.length, 2, 'a session does not expire by itself')

  d.touch({ user: 'ana', sid: b.sid })
  assert.equal(d.list()[0].sessions[0].sid, b.sid, 'the most recently used comes first')

  assert.deepEqual(d.closeSession({ user: 'ana', sid: a.sid }), { ok: true })
  assert.deepEqual(d.list()[0].sessions.map((s) => s.sid), [b.sid])
  assert.deepEqual(d.closeSession({ user: 'ana', sid: a.sid }), { ok: false }, 'closing twice is not an error either')
})

test('changing the password closes what was open and the old one stops working', () => {
  const { desk: d } = desk()
  register(d, { user: 'ana', password: 'vieja' })
  login(d, { user: 'ana', password: 'vieja' })
  assert.equal(d.list()[0].sessions.length, 1)

  const nueva = register(d, { user: 'ana', password: 'nueva', replace: true })
  assert.equal(d.list()[0].sessions.length, 0, 'the open sessions are gone')
  fails(() => login(d, { user: 'ana', password: 'vieja' }), 'login-failed')
  const ok = login(d, { user: 'ana', password: 'nueva' })
  assert.equal(ok.blob, nueva.blob)
})

test('the exchange in flight is single use and does not stay open for ever', () => {
  const { desk: d, tick } = desk()
  register(d, { user: 'ana', password: 'p' })
  const start = opaqueClient.loginStart({ password: 'p' })
  const { lid, response } = d.loginBegin({ user: 'ana', request: start.request })
  const fin = opaqueClient.loginFinish({ state: start.state, response, password: 'p' })
  d.loginEnd({ lid, finalization: fin.finalization })
  fails(() => d.loginEnd({ lid, finalization: fin.finalization }), 'no-exchange')

  const s2 = opaqueClient.loginStart({ password: 'p' })
  const x2 = d.loginBegin({ user: 'ana', request: s2.request })
  const f2 = opaqueClient.loginFinish({ state: s2.state, response: x2.response, password: 'p' })
  tick(3 * 60_000)
  fails(() => d.loginEnd({ lid: x2.lid, finalization: f2.finalization }), 'no-exchange')
})

test('names are checked, and nothing is created twice by accident', () => {
  const { desk: d } = desk()
  register(d, { user: 'ana', password: 'p' })
  fails(() => register(d, { user: 'ana', password: 'otra' }), 'user-exists')
  fails(() => register(d, { user: 'Ana Pérez', password: 'p' }), 'bad-user')
  fails(() => register(d, { user: 'beto', password: 'p', replace: true }), 'no-user')
  fails(() => d.setCert({ user: 'beto', cert: {} }), 'no-user')
})

test('who is logged in: a key with an open session is told apart from one without', () => {
  const { desk: d } = desk()
  register(d, { user: 'ana', password: 'p', pub: 'KEY-A' })
  assert.equal(d.hasOpenSession({ pub: 'KEY-A' }), false)
  const s = login(d, { user: 'ana', password: 'p' })
  assert.equal(d.hasOpenSession({ pub: 'KEY-A' }), true)
  assert.equal(d.hasOpenSession({ pub: 'KEY-B' }), false)
  d.closeSession({ user: 'ana', sid: s.sid })
  assert.equal(d.hasOpenSession({ pub: 'KEY-A' }), false, 'closing it really cuts it')
})

test('removing the login takes its record and its sessions with it', () => {
  const { desk: d, raw } = desk()
  register(d, { user: 'ana', password: 'p' })
  login(d, { user: 'ana', password: 'p' })
  assert.deepEqual(d.remove({ user: 'ana' }), { ok: true })
  assert.deepEqual(d.list(), [])
  assert.equal(JSON.stringify(raw().users), '{}')
  fails(() => login(d, { user: 'ana', password: 'p' }), 'login-failed')
})
