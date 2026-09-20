/**
 * ENTRAR CON USUARIO Y CONTRASEÑA, de punta a punta y contra la bóveda de verdad.
 *
 * Aquí el único mentiroso es el proxio, que corre en el mismo proceso. Todo lo demás es
 * producción: `startVault`, el acta firmada, OPAQUE y el enrutador de mensajes.
 *
 * Lo que se prueba es el caso que este trabajo viene a resolver: **un navegador que no tiene
 * ninguna llave** escribe usuario y contraseña, recibe el paquete que solo esa contraseña
 * abre, y con lo que hay dentro ya es un aparato de la cuenta. Y lo que no puede pasar: que
 * una contraseña equivocada sirva, que se distinga un usuario que no existe, o que alguien
 * cierre la sesión de otro.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { makeDeviceKey, makeDeviceEncKey, signWithDevice } from '@dotrino/identity/capabilities'
import { client as opaqueClient } from '@dotrino/opaque'
// El paquete de llaves lo cierra QUIEN CREA el aparato, con la misma pieza que usan la CLI,
// la pestaña y la extensión: si esto tuviera su propia copia, la prueba dejaría de probar
// que las tres cierran igual.
import { sealDeviceKeys, openDeviceKeys, vaultChannel } from '../lib/src/passwordLogins.js'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

let proxy, proxyUrl, vault, MSG, WebSocketProxyClient

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-login-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  ;({ MSG } = await import('../lib/src/protocol.js'))
  ;({ WebSocketProxyClient } = await import('@dotrino/proxy-client'))
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

const seal = sealDeviceKeys
const open = openDeviceKeys

/** Crear el aparato: la contraseña no sale de aquí, y las llaves nacen aquí. */
async function createLogin ({ user, password, label = 'equipo prestado' }) {
  const device = await makeDeviceKey({ label })
  const enc = await makeDeviceEncKey()
  const start = opaqueClient.registrationStart({ password })
  const { response } = await vault.loginRegisterBegin({ user, request: start.request })
  const fin = opaqueClient.registrationFinish({ state: start.state, response, password })
  const blob = await seal(fin.exportKey, { sign: device.privateJwk, enc: enc.privateJwk })
  const r = await vault.loginRegisterFinish({
    user, upload: fin.upload, pub: device.publickey, encPub: enc.publickey, label, blob
  })
  return { ...r, device, exportKey: fin.exportKey }
}

/** Un navegador sin nada: se conecta al proxio y habla con la bóveda por su llave pública. */
async function browser () {
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  const waiting = []
  c.on('message', (from, payload) => { for (const w of waiting) if (w.match(payload)) { waiting.splice(waiting.indexOf(w), 1); w.resolve(payload); break } })
  const ask = (msg, types) => new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('the vault did not answer: ' + msg.type)), 8000)
    waiting.push({ match: (p) => types.includes(p?.type), resolve: (p) => { clearTimeout(t); resolve(p) } })
    c.sendByPubkey(vault.master, msg)
  })
  return { client: c, ask, close: () => c.close() }
}

/** El inicio de sesión entero, tal como lo haría la extensión o la página. */
async function login (b, { user, password, label = '' }) {
  const start = opaqueClient.loginStart({ password })
  const first = await b.ask({ type: MSG.LOGIN_START, user, request: start.request }, [MSG.LOGIN_RESPONSE, MSG.ERROR])
  if (first.type === MSG.ERROR) throw Object.assign(new Error(first.error), { code: first.code, waitMs: first.waitMs })
  const fin = opaqueClient.loginFinish({ state: start.state, response: first.response, password })
  const ok = await b.ask({ type: MSG.LOGIN_FINISH, lid: first.lid, finalization: fin.finalization, label }, [MSG.LOGIN_OK, MSG.ERROR])
  if (ok.type === MSG.ERROR) throw Object.assign(new Error(ok.error), { code: ok.code })
  return { ...ok, exportKey: fin.exportKey }
}

/**
 * ENCONTRAR LA BÓVEDA SIN TENER NINGUNA LLAVE.
 *
 * Es el primer paso del equipo prestado, y sin él lo demás no empieza: quien escribe
 * `nombre@AB12-CD34-EF56` no sabe la pubkey de nadie, así que lo único con lo que puede
 * buscar es el código de la dirección. La bóveda se anuncia en ese canal al identificarse.
 */
test('a machine with no keys finds the vault through the account channel', async () => {
  const b = await browser()
  try {
    const canal = vaultChannel(vault.fingerprint)
    // `watch` y no `publish`: quien busca no es una bóveda y no debe salir en la lista.
    const tokens = await b.client.watch(canal)
    assert.ok(tokens.includes(vault.client.token), 'the vault is announced in its account channel: ' + canal)
  } finally { b.close() }
})

test('a browser with no keys logs in with user and password, and what it gets really works', async () => {
  const creado = await createLogin({ user: 'ana', password: 'una contraseña larga de verdad' })
  assert.ok(creado.cert?.sig, 'the device comes out with its certificate')

  const b = await browser()
  try {
    const entrada = await login(b, { user: 'ana', password: 'una contraseña larga de verdad', label: 'cyber del barrio' })
    assert.ok(entrada.sid && entrada.blob && entrada.cert?.sig && entrada.acta?.seq)

    // El paquete SOLO lo abre la contraseña, y dentro están las llaves del aparato.
    const llaves = await open(entrada.exportKey, entrada.blob)
    assert.equal(llaves.sign.x, creado.device.privateJwk.x, 'the signing key is the device one')

    // Y con ellas ya es un aparato de la cuenta: la bóveda lo reconoce como miembro.
    const data = { op: 'check', publickey: creado.device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: llaves.sign, data })
    const checked = await b.ask({ type: MSG.CHECK, data, signature }, [MSG.CHECKED, MSG.ERROR])
    assert.equal(checked.type, MSG.CHECKED)
    assert.equal(checked.in, true, 'the key inside the package is a member of the record')
  } finally { b.close() }
})

test('a wrong password and a user that does not exist fail the same way', async () => {
  const b = await browser()
  try {
    const mala = await login(b, { user: 'ana', password: 'no es' }).then(() => null, (e) => e)
    const nadie = await login(b, { user: 'nadie', password: 'tampoco' }).then(() => null, (e) => e)
    assert.equal(mala?.code, 'login-failed')
    assert.equal(nadie?.code, 'login-failed')
    assert.equal(mala.message, nadie.message, 'the same error: you cannot find out which users exist')
  } finally { b.close() }
})

test('logging out closes the session, and nobody can close someone else\'s', async () => {
  await createLogin({ user: 'beto', password: 'la de beto, larga también' })
  const b = await browser()
  try {
    const entrada = await login(b, { user: 'beto', password: 'la de beto, larga también' })
    const llaves = await open(entrada.exportKey, entrada.blob)
    assert.equal(vault.listLogins().find((x) => x.user === 'beto').sessions.length, 1)

    // Otro aparato NO puede cerrarla, aunque sepa el sid.
    const impostor = await makeDeviceKey({ label: 'impostor' })
    const dImp = { op: 'login.close', user: 'beto', sid: entrada.sid, publickey: impostor.publickey, ts: Date.now() }
    const no = await b.ask({ type: MSG.LOGIN_CLOSE, data: dImp, signature: (await signWithDevice({ privateJwk: impostor.privateJwk, data: dImp })).signature }, [MSG.LOGIN_CLOSED, MSG.ERROR])
    assert.equal(no.type, MSG.ERROR)
    assert.equal(no.code, 'not-yours')
    assert.equal(vault.listLogins().find((x) => x.user === 'beto').sessions.length, 1, 'the session is still open')

    // El suyo sí.
    const d = { op: 'login.close', user: 'beto', sid: entrada.sid, publickey: llavePub(entrada), ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: llaves.sign, data: d })
    const si = await b.ask({ type: MSG.LOGIN_CLOSE, data: d, signature }, [MSG.LOGIN_CLOSED, MSG.ERROR])
    assert.equal(si.type, MSG.LOGIN_CLOSED)
    assert.equal(si.ok, true)
    assert.equal(vault.listLogins().find((x) => x.user === 'beto').sessions.length, 0)
  } finally { b.close() }

  function llavePub (entrada) { return entrada.cert.sub }
})

test('the console sees the open logins and can close them', async () => {
  await createLogin({ user: 'cris', password: 'la de cris, bien larga' })
  const b = await browser()
  try {
    const uno = await login(b, { user: 'cris', password: 'la de cris, bien larga', label: 'prestado' })
    await login(b, { user: 'cris', password: 'la de cris, bien larga' })
    const fila = vault.listLogins().find((x) => x.user === 'cris')
    assert.equal(fila.sessions.length, 2)
    assert.equal(fila.sessions.some((s) => s.label === 'prestado'), true, 'it shows where the login came from')

    assert.deepEqual(vault.closeLogin({ user: 'cris', sid: uno.sid }), { ok: true })
    assert.equal(vault.listLogins().find((x) => x.user === 'cris').sessions.length, 1)
  } finally { b.close() }
})

test('a password login cannot take the passwords permission yet', async () => {
  const e = await createLoginConScope('vault:passwords').then(() => null, (x) => x)
  assert.ok(e && /contrasenas|passwords/.test(e.message), 'it must refuse until the sealed passwords exist: ' + e?.message)

  async function createLoginConScope (scope) {
    const device = await makeDeviceKey({ label: 'x' })
    const start = opaqueClient.registrationStart({ password: 'una contraseña larga' })
    const { response } = await vault.loginRegisterBegin({ user: 'dora', request: start.request })
    const fin = opaqueClient.registrationFinish({ state: start.state, response, password: 'una contraseña larga' })
    return vault.loginRegisterFinish({
      user: 'dora', upload: fin.upload, pub: device.publickey, blob: await seal(fin.exportKey, { sign: device.privateJwk }), scope: [scope]
    })
  }
})
