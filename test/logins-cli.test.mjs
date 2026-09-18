/**
 * CREAR Y ADMINISTRAR UN INICIO DE SESIÓN DESDE LA MÁQUINA DE LA BÓVEDA.
 *
 * Es el canal que usa `dotrino-vault logins`: un archivo de petición en el dir de datos y
 * un archivo de respuesta, contra un daemon DE VERDAD (arrancado aquí). Lo que se fija es
 * lo que el dueño decidió: la contraseña no cruza este canal —lo que viaja son mensajes de
 * OPAQUE y un paquete que la bóveda no puede abrir—, y quitar un inicio de sesión saca
 * también su llave del acta, porque media baja es peor que ninguna.
 *
 * La CLI de verdad pide la contraseña por el terminal, así que lo que se prueba aquí es el
 * CONTRATO con el daemon; el resto de `ctl.js` es pedir la contraseña e imprimir.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { client as opaqueClient } from '@dotrino/opaque'
import { makeDeviceKey, makeDeviceEncKey } from '@dotrino/identity/capabilities'
import { atRestFor } from '../src/atrest.js'
import { sealDeviceKeys, openDeviceKeys, loginAddress } from '../lib/src/passwordLogins.js'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const DAEMON = path.join(ROOT, 'bin', 'dotrino-vaultd.js')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

let dir, proc, codec, seq = 0

/** Un viaje al daemon, igual que lo hace `loginsRequest` en `ctl.js`. */
async function ask (op, extra = {}) {
  const reply = path.join(dir, 'logins-list.json')
  fs.rmSync(reply, { force: true })
  const id = `test-${++seq}`
  const tmp = path.join(dir, 'logins-request.json.tmp')
  fs.writeFileSync(tmp, codec.encrypt(JSON.stringify({ op, id, at: Date.now(), ...extra })), { mode: 0o600 })
  fs.renameSync(tmp, path.join(dir, 'logins-request.json'))
  const until = Date.now() + 20000
  while (Date.now() < until) {
    await sleep(100)
    let d = null
    try { d = JSON.parse(codec.decrypt(fs.readFileSync(reply, 'utf8'))) } catch (_) { continue }
    if (d?.req === id) { fs.rmSync(reply, { force: true }); return d }
  }
  throw new Error('the daemon did not answer: ' + op)
}

/** El alta entera, tal como la hace la CLI: la contraseña no sale de aquí. */
async function createLogin (user, password, label = 'equipo prestado') {
  const start = opaqueClient.registrationStart({ password })
  const begun = await ask('register-begin', { user, request: start.request })
  assert.equal(begun.ok, true, begun.error)
  const fin = opaqueClient.registrationFinish({ state: start.state, response: begun.response, password })
  const device = await makeDeviceKey({ label })
  const enc = await makeDeviceEncKey()
  const blob = await sealDeviceKeys(fin.exportKey, { sign: device.privateJwk, enc: enc.privateJwk })
  const r = await ask('register-finish', {
    user, upload: fin.upload, pub: device.publickey, encPub: enc.publickey, label, blob
  })
  return { ...r, device }
}

/**
 * Con la contraseña equivocada quien se entera es el CLIENTE, al recibir la respuesta: por
 * eso el fallo sale de `loginFinish` y el último mensaje no llega a mandarse nunca. Ese es
 * el motivo de que los intentos se cuenten al EMPEZAR.
 */
async function login (user, password) {
  const start = opaqueClient.loginStart({ password })
  const begun = await ask('login-begin', { user, request: start.request })
  if (!begun.ok) return begun
  let fin
  try { fin = opaqueClient.loginFinish({ state: start.state, response: begun.response, password }) }
  catch (e) { return { ok: false, code: e.code, error: e.message } }
  const done = await ask('login-end', { lid: begun.lid, finalization: fin.finalization, label: 'consola' })
  return { ...done, exportKey: fin.exportKey }
}

test.before(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-logins-'))
  codec = atRestFor(dir)
  proc = spawn(process.execPath, [DAEMON], {
    env: { ...process.env, DOTRINO_VAULT_DIR: dir },
    stdio: ['ignore', 'ignore', process.env.VAULT_LOG ? 'inherit' : 'ignore']
  })
  const until = Date.now() + 30000
  while (Date.now() < until && !fs.existsSync(path.join(dir, 'state.json'))) await sleep(200)
  assert.ok(fs.existsSync(path.join(dir, 'state.json')), 'the daemon started')
})

test.after(() => {
  try { proc?.kill() } catch (_) {}
  try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {}
})

test('crear un inicio de sesión: la bóveda guarda lo que no puede abrir', async () => {
  const r = await createLogin('ana', 'una contraseña larga de verdad')
  assert.equal(r.ok, true, r.error)
  assert.ok(r.cert?.sig, 'el aparato sale con su certificado')
  assert.match(r.deviceId, /^[0-9A-F]{4}-[0-9A-F]{4}$/)
  assert.deepEqual(r.caps.sort(), ['read', 'sign', 'store'])

  // La dirección con la que se entra: `nombre@AB12-CD34-EF56`, 48 bits de la cuenta.
  const { logins, fingerprint } = await ask('list')
  assert.equal(logins.length, 1)
  assert.match(loginAddress(logins[0].user, fingerprint), /^ana@[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/)

  // Y la contraseña NO está en el disco de la bóveda, ni siquiera de refilón.
  const guardado = fs.readdirSync(path.join(dir, 'p'), { recursive: true })
    .map((f) => path.join(dir, 'p', String(f)))
    .filter((f) => fs.statSync(f).isFile())
    .map((f) => fs.readFileSync(f, 'utf8')).join('')
  assert.ok(!guardado.includes('una contraseña larga de verdad'), 'la contraseña no se guardó en ningún lado')
})

test('entrar devuelve el paquete, y solo la contraseña buena lo abre', async () => {
  const entrada = await login('ana', 'una contraseña larga de verdad')
  assert.equal(entrada.ok, true, entrada.error)
  assert.ok(entrada.sid && entrada.blob)
  const llaves = await openDeviceKeys(entrada.exportKey, entrada.blob)
  assert.equal(llaves.sign.kty, 'EC', 'dentro están las llaves privadas del aparato')

  const mala = await login('ana', 'no es esa')
  assert.equal(mala.ok, false)
  assert.equal(mala.code, 'login-failed')
  const nadie = await login('nadie', 'tampoco')
  assert.equal(nadie.code, 'login-failed', 'no se puede averiguar qué usuarios existen')
})

test('cambiar la contraseña re-cierra el MISMO paquete y cierra lo abierto', async () => {
  const antes = await login('ana', 'una contraseña larga de verdad')
  const llaves = await openDeviceKeys(antes.exportKey, antes.blob)

  const start = opaqueClient.registrationStart({ password: 'otra contraseña, también larga' })
  const begun = await ask('register-begin', { user: 'ana', request: start.request, replace: true })
  const fin = opaqueClient.registrationFinish({ state: start.state, response: begun.response, password: 'otra contraseña, también larga' })
  const r = await ask('register-finish', {
    user: 'ana', upload: fin.upload, blob: await sealDeviceKeys(fin.exportKey, llaves), replace: true
  })
  assert.equal(r.replaced, true)

  const { logins } = await ask('list')
  assert.equal(logins[0].sessions.length, 0, 'lo que estaba abierto se cerró')
  assert.equal((await login('ana', 'una contraseña larga de verdad')).code, 'login-failed', 'la vieja ya no entra')

  const nueva = await login('ana', 'otra contraseña, también larga')
  const mismas = await openDeviceKeys(nueva.exportKey, nueva.blob)
  assert.equal(mismas.sign.x, llaves.sign.x, 'el aparato y su llave son los mismos')
})

test('cerrar una sesión desde la consola la corta de verdad', async () => {
  const entrada = await login('ana', 'otra contraseña, también larga')
  assert.equal((await ask('close', { user: 'ana', sid: entrada.sid })).ok, true)
  const { logins } = await ask('list')
  assert.equal(logins[0].sessions.some((s) => s.sid === entrada.sid), false)
})

test('quitarlo lo saca TAMBIÉN del acta: nada de medias bajas', async () => {
  const r = await createLogin('beto', 'la de beto, bien larga')
  assert.equal(r.ok, true, r.error)

  const quitado = await ask('rm', { user: 'beto' })
  assert.equal(quitado.ok, true)
  assert.equal(quitado.deviceId, r.deviceId)
  assert.equal((await ask('list')).logins.some((x) => x.user === 'beto'), false)

  // Y su llave ya no es miembro de la cuenta. Es lo que faltaba: borrar el inicio de sesión
  // dejaba un aparato en el acta que ya no puede entrar pero sigue siendo de la cuenta.
  const acta = path.join(dir, 'acta.json')
  fs.rmSync(acta, { force: true })
  const tmp = path.join(dir, 'dump-request.json.tmp')
  fs.writeFileSync(tmp, codec.encrypt(JSON.stringify({ id: 'dump-1', at: Date.now() })), { mode: 0o600 })
  fs.renameSync(tmp, path.join(dir, 'dump-request.json'))
  let record = null
  const until = Date.now() + 15000
  while (Date.now() < until && !record) {
    await sleep(100)
    try { const d = JSON.parse(codec.decrypt(fs.readFileSync(acta, 'utf8'))); if (d?.req === 'dump-1') record = d } catch (_) {}
  }
  assert.ok(record, 'el daemon volcó el acta')
  assert.equal(record.members.some((m) => m.id === r.deviceId), false, 'su llave salió del acta')
})

test('el freno se puede quitar desde aquí, y no cambia la contraseña', async () => {
  for (let i = 0; i < 6; i++) await login('ana', 'no es')
  const frenada = await login('ana', 'otra contraseña, también larga')
  assert.equal(frenada.code, 'too-many-tries')
  assert.ok(frenada.waitMs > 0, 'dice cuánto hay que esperar')

  assert.equal((await ask('unblock', { user: 'ana' })).ok, true)
  assert.equal((await login('ana', 'otra contraseña, también larga')).ok, true, 'entra sin haber cambiado nada')
})
