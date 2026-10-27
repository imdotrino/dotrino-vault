/**
 * LA SEGUNDA BÓVEDA QUE DUERME (`lambda/`, modo `join`; `dotrino-accounts/docs/DISENO.md` §5).
 *
 * Proxio real (repo hermano `dotrino-proxy`), una bóveda real como la del cliente, almacén en
 * memoria y KMS de mentira. Lo que tiene que pasar:
 *
 *   1. antes de nacer pide la contraseña: da `{ ek, salt, params }`, y la derivada llega
 *      sellada a esa efímera;
 *   2. entra en la cuenta con la invitación y el código del dueño, y SELLA;
 *   3. su maestra nunca está en claro en el almacén: sin la contraseña no se abre, ni con KMS;
 *   4. con la contraseña se abre (la misma derivada que manda la consola), con otra no;
 *   5. con la invitación de OTRA cuenta no enseña código, y no deja nada a medias.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { runSession, vaultStarter, enrollJoin, joinStatus, PAIRING_FILE, DOOR_FILE } from '../lambda/session.mjs'
import { openLock, LOCK_FILE } from '../lambda/lock.mjs'
import { memoryStore } from '../lambda/mirror.mjs'
import { encodeInvite, parseInvite } from '../lib/src/invite.js'
import { makeEphemeralKey, openSealed, seal } from '../lib/src/sealed.js'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(here, '..', '..', 'dotrino-proxy', 'server.js')
const FAKE_KMS = path.join(here, 'fixtures', 'fake-kms.mjs')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
// Se guarda todo lo que dice la bóveda: al final se mira que no haya reventado nada por dentro
// (un `catch` que solo loguea no tumba ninguna prueba, y así pasó el `Acta` declarado tarde).
const lines = []
const log = (...a) => { lines.push(a.join(' ')); if (process.env.VAULT_LOG) console.error(...a) }
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const PASSWORD = 'caballo grapa batería correcta'

let proxy, proxyUrl, vault, otra, startVault, nodePlatform, pubkeyId, cuenta
const store = memoryStore()

const openIdentity = ({ dir, openKey }) => nodePlatform(dir).openIdentity({ openKey: openKey ? () => openKey() : null, log })
const invitar = async (v) => encodeInvite((await v.startPairing({ scope: ['vault:sign'], caps: ['sign', 'read', 'store', 'sealer'], label: 'bóveda en la nube' })).qr)
const alta = (invitation, req, account = cuenta) => enrollJoin({
  store, dir: tmp('join-alta-'), invitation, account, req, deadline: Date.now() + 60_000,
  openIdentity, parseInvite, makeEphemeralKey, openSealed, log
})

async function pairing (req, ready) {
  for (let i = 0; i < 200; i++) {
    const o = store.objects.get(PAIRING_FILE)
    const got = o && JSON.parse(o.body.toString('utf8'))
    if (got?.req === req && (got.error || ready(got))) return got
    await sleep(100)
  }
  throw new Error('nothing in the pairing file for ' + req)
}

/** Lo que hace el navegador: deriva AQUÍ y sella a la efímera. */
async function mandarContrasena (req, door, password = PASSWORD) {
  const key = crypto.scryptSync(password, Buffer.from(door.salt, 'base64'), door.len, { N: door.N, r: door.r, p: door.p })
  const enc = await seal({ ek: door.ek, payload: { nonce: req, key: key.toString('base64') } })
  await store.put(DOOR_FILE, Buffer.from(JSON.stringify({ req, enc })))
  return new Uint8Array(key)
}

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  process.env.DOTRINO_KMS_KEY_ID = 'test'
  process.env.DOTRINO_KMS_SCRIPT = FAKE_KMS
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  ;({ startVault } = await import('../src/vault.js'))
  ;({ nodePlatform } = await import('../src/platform.js'))
  ;({ pubkeyId } = await import('@dotrino/identity/keyid'))
  vault = await startVault({ dir: tmp('join-cuenta-'), proxyUrl, log })
  otra = await startVault({ dir: tmp('join-otra-'), proxyUrl, log })
  cuenta = await pubkeyId((await vault.startPairing({ scope: ['vault:sign'], label: 'solo para leer la cuenta' })).qr.iss)
})

after(async () => {
  delete process.env.DOTRINO_KMS_KEY_ID
  delete process.env.DOTRINO_KMS_SCRIPT
  try { vault?.close() } catch (_) {}
  try { otra?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('con la invitación de otra cuenta no hay código, y no queda nada a medias', async () => {
  const r = alta(await invitar(otra), 'req-otra')
  const door = await pairing('req-otra', (g) => g.phase === 'door')
  await mandarContrasena('req-otra', door)
  await assert.rejects(r, (e) => e.code === 'wrong-account')
  const nombres = [...store.objects.keys()]
  assert.ok(!nombres.includes(LOCK_FILE) && !nombres.includes('identity.json'), `quedó algo del alta fallida: ${nombres.join(', ')}`)
})

let derivada = null
let alojada = null
// Entra con la invitación de cualquier bóveda de la cuenta que SELLE, como cualquier aparato
// (dueño, 2026-10-19): el alta solo comprueba que quien invita sella esa cuenta.
test('nace sellada, entra en la cuenta con el código del dueño y sella', async () => {
  const r = alta(await invitar(vault), 'req-1')
  const door = await pairing('req-1', (g) => g.phase === 'door')
  assert.ok(door.ek && door.salt && door.N, 'pide la contraseña antes de nacer')
  derivada = await mandarContrasena('req-1', door)
  const pend = await pairing('req-1', (g) => !!g.code)
  assert.ok(pend.code, pend.message || 'el código para teclear en la bóveda')
  await vault.approveDevice(pend.code)
  const { lock, deviceId, publickey } = await r
  lock.close()
  assert.equal(deviceId, pend.deviceId)
  alojada = publickey

  const st = await joinStatus({ store, dir: tmp('join-estado-'), openIdentity })
  assert.equal(st.enrolled, true)
  assert.equal(st.sealer, true, 'entró con `sella`')
})

test('la maestra no se abre sin la contraseña: ni con el almacén y KMS en la mano', async () => {
  const dir = tmp('join-ladron-')
  for (const [name, o] of store.objects) {
    if (name.startsWith('.')) continue
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true })
    fs.writeFileSync(path.join(dir, name), o.body)
  }
  const id = await openIdentity({ dir, openKey: null })
  try {
    assert.equal(id.masterLocked ?? (await id.isMasterLocked?.()), true)
    await assert.rejects(id.signData({ hola: 1 }), 'sin la maestra no firma')
  } finally { id.destroy?.() }
})

test('la sesión arranca cerrada; con la derivada se abre, con otra no', async () => {
  const dir = tmp('join-sesion-')
  const lock = openLock(dir)
  const r = await runSession({
    store, dir, proxyUrl, deadline: Date.now() + 60_000, idleMs: 0, log,
    start: vaultStarter({
      startVault, locked: true, lock,
      onReady: async (v) => {
        const cerrada = await v.takeMasterKey()
        const mala = (() => { try { lock.open(new Uint8Array(32)); return 'abrió' } catch (e) { return e.code } })()
        lock.open(derivada)
        const abierta = await v.takeMasterKey()
        return { cerrada, mala, abierta }
      }
    })
  })
  assert.equal(r.ready.cerrada.locked, true, 'nace cerrada en cada sesión')
  assert.equal(r.ready.mala, 'WRONG_PASSWORD')
  assert.equal(r.ready.abierta.locked, false, 'la derivada de su contraseña la abre')
})

// A LA ALOJADA SE LE ESCRIBE POR SU LLAVE DE COMUNICACIÓN (`vault` en el acta dice de qué bóveda
// es): lo dirigido a la maestra del perfil lo recibe la que conteste primero, y lo dirigido a la
// maestra de la alojada se entrega a los aparatos que ella emparejó y no a ella.
test('dormida y cerrada, la abre desde lejos un aparato con `admin` de la OTRA bóveda', async () => {
  // Un aparato de la cuenta con `admin`, emparejado con la bóveda del cliente (su papel lo firmó
  // ella, no la alojada): lo que pasa cuando la primera se pierde y hay que abrir la segunda.
  const { enrollWithVault } = await import('../lib/src/service.js')
  const { requestAdmin } = await import('@dotrino/identity/vault/remote.js')
  const { qr } = await vault.startPairing({ scope: ['vault:admin'], caps: ['admin'], label: 'consola' })
  const alta = enrollWithVault({ qr, label: 'consola', withEncKey: false, onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })
  const consola = await alta

  const r = await runSession({
    store, dir: tmp('join-remota-'), proxyUrl, deadline: Date.now() + 60_000, idleMs: 0, log,
    start: vaultStarter({
      startVault, locked: true,
      onReady: async (v) => {
        // El acta donde entró la consola la selló la otra bóveda mientras esta dormía: le llega
        // encolada al identificarse.
        let members = []
        for (let i = 0; i < 50 && !members.some((m) => m.pub === consola.device.publickey); i++) {
          members = (await v.profileMembers()).members
          if (!members.some((m) => m.pub === consola.device.publickey)) await sleep(100)
        }
        assert.ok(members.some((m) => m.pub === consola.device.publickey), 'adoptó el acta de la otra bóveda')
        const comm = members.find((m) => m.cn === 'vault' && m.vault === alojada)?.pub
        assert.ok(comm, 'el acta dice cuál es la llave de comunicación de la alojada')
        const pide = (op, extra = {}) => requestAdmin({ master: alojada, to: comm, proxy: proxyUrl, device: consola.device, cert: consola.cert, op, ...extra })
        const begin = await pide('unlock.begin')
        const nonce = crypto.randomBytes(16).toString('hex')
        const key = crypto.scryptSync(PASSWORD, Buffer.from(begin.salt, 'base64'), begin.len, { N: begin.N, r: begin.r, p: begin.p })
        const enc = await seal({ ek: begin.ek, payload: { nonce, key: key.toString('base64') } })
        const opened = await pide('unlock', { nonce, enc })
        return { begin, opened, after: await v.takeMasterKey() }
      }
    })
  })
  assert.ok(r.ready.begin.ek, 'contesta cerrada, con la llave efímera')
  assert.equal(r.ready.opened.locked, false)
  assert.equal(r.ready.after.locked, false, 'la maestra quedó en memoria')
})

test('una bóveda ya dada de alta no se vuelve a dar de alta', async () => {
  await assert.rejects(alta(await invitar(vault), 'req-2'), (e) => e.code === 'already-enrolled')
})

// CLONES (`docs/replicas.md` §11.3-§11.4): un cajón escrito en una bóveda le llega a la otra,
// cerrada y dormida, cuando despierta; y uno borrado se borra también allí.
test('clones: el cajón escrito en la otra bóveda llega a la alojada, y el borrado también', async () => {
  await vault.setSecret('clon', 'TOKEN', 'valor del pc', false)
  await sleep(3500) // se juntan los cambios de unos segundos antes de mandarlos
  const tiene = async (v, ns, key) => ((await v.listSecrets())[ns] || []).some((x) => x.key === key)
  const espera = async (cond) => { for (let i = 0; i < 80 && !(await cond()); i++) await sleep(100); return cond() }
  const r1 = await runSession({
    store, dir: tmp('join-clon-'), proxyUrl, deadline: Date.now() + 60_000, idleMs: 0, log,
    start: vaultStarter({ startVault, locked: true, onReady: async (v) => espera(() => tiene(v, 'clon', 'TOKEN')) })
  })
  assert.equal(r1.ready, true, 'la alojada, cerrada, recibió el cajón')

  await vault.deleteSecret('clon', 'TOKEN')
  await sleep(3500)
  const r2 = await runSession({
    store, dir: tmp('join-clon2-'), proxyUrl, deadline: Date.now() + 60_000, idleMs: 0, log,
    start: vaultStarter({ startVault, locked: true, onReady: async (v) => espera(async () => !(await tiene(v, 'clon', 'TOKEN'))) })
  })
  assert.equal(r2.ready, true, 'y lo borrado se borró allí')
  assert.ok(lines.some((l) => /merged the drawers of a sibling vault/.test(l)), 'se mezclaron los cajones de la hermana')
})

// LAS DOS SON MAESTRA (`docs/replicas.md` §11.5). Lo que pasó con la de Lambda de Seyacat: la
// última acta la selló la otra bóveda, el acta solo nombraba UNA llave de sellado (la de esa), y
// la alojada no podía firmar nada de lo que sirve («no sealing key named by the record»). Ahora
// cada bóveda tiene la suya en el acta y la de la otra se conserva al sellar.
test('las dos son maestra: con la otra apagada, la alojada contesta firmado con SU llave', async () => {
  const { enrollService, fetchSecrets } = await import('../lib/src/service.js')
  const svcDir = tmp('join-svc-')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:demo'], label: 'service:demo', ttlMs: 60_000 })
  let ok
  await enrollService({ qr, ns: 'demo', dir: svcDir, onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
  // Una vuelta con la bóveda del cliente: el servicio aprende quién puede sellar la cuenta.
  await fetchSecrets({ dir: svcDir, timeoutMs: 15_000 }).catch(() => {})

  const seqOf = async (v) => (await v.profileMembers()).seq
  const dosDir = tmp('join-dos-')
  const lock = openLock(dosDir)
  const r = await runSession({
    store, dir: dosDir, proxyUrl, deadline: Date.now() + 90_000, idleMs: 0, log,
    start: vaultStarter({
      startVault, locked: true, lock,
      onReady: async (v) => {
        lock.open(derivada)
        await v.takeMasterKey()
        // Se abrió: estrenó su llave y la nombró en un acta que selló ella.
        const propia = await seqOf(v)
        for (let i = 0; i < 100 && (await seqOf(vault)) < propia; i++) await sleep(100)
        // La otra bóveda sella después (como el PC con la #58): la llave de la alojada sigue ahí.
        const me = (await vault.profileMembers()).members.find((m) => m.label === 'service:demo')
        await vault.setLabel(me.pub, 'service:demo (renombrado)')
        const otraSello = await seqOf(vault)
        for (let i = 0; i < 100 && (await seqOf(v)) < otraSello; i++) await sleep(100)
        await vault.close()
        let res = null; let err = null
        try { res = await fetchSecrets({ dir: svcDir, timeoutMs: 15_000 }) } catch (e) { err = e }
        return { propia, otraSello, adoptada: await seqOf(v), res, err }
      }
    })
  })
  assert.ok(r.ready.otraSello > r.ready.propia, 'la otra bóveda selló después')
  assert.equal(r.ready.adoptada, r.ready.otraSello, 'la alojada adoptó el acta de la otra')
  assert.ok(!lines.some((l) => /no sealing key named by the record/.test(l)), 'la alojada pudo firmar lo que sirvió')
  // Lo que importa: una respuesta VERIFICADA de la alojada (el cajón está vacío en ella hasta la
  // fase 2, así que basta un `{}` o un error firmado; lo que no vale es quedarse esperando).
  assert.ok(!r.ready.err || !/timeout|unanswered|unreachable|did not answer|unverified|nobody answered/i.test(r.ready.err.message + ' ' + (r.ready.err.code || '')),
    `contestó la alojada, verificado: ${r.ready.err?.message}`)
})

test('la bóveda no reventó por dentro en ninguna sesión', () => {
  const malas = lines.filter((l) => /before initialization|is not defined/.test(l))
  assert.deepEqual(malas, [])
})
