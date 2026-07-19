/**
 * vaultControl.js contra un DAEMON FALSO en el mismo proceso.
 *
 * El truco: el proceso de test se hace pasar por daemon —escribe state.json con
 * su propio pid e instala manejadores de SIGUSR1/SIGUSR2— así `vaultControl`
 * (que señala ese pid) dispara los manejadores, que responden por los mismos
 * archivos que usa el daemon real (`daemon.js`). Verifica el CONTRATO de
 * archivos+señales, sin red ni cripto.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-ctl-test-'))
process.env.DOTRINO_VAULT_DIR = root

let vc

// ------------------------------ daemon falso -------------------------------

const P = (n) => path.join(root, n)
const writeAtomic = (n, obj) => {
  const f = P(n); const tmp = f + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify({ ...obj, at: Date.now() }), { mode: 0o600 })
  fs.renameSync(tmp, f)
}
const readReq = (n) => { try { const d = JSON.parse(fs.readFileSync(P(n), 'utf8')); fs.rmSync(P(n), { force: true }); return d } catch { return null } }
const readRaw = (n) => { try { return JSON.parse(fs.readFileSync(P(n), 'utf8')) } catch { return null } }
const rm = (n) => { try { fs.rmSync(P(n), { force: true }) } catch {} }

let model, pcount, nonce, paircount

function resetModel () {
  model = {
    current: 'p1',
    profiles: [{ id: 'p1', name: 'Perfil 1', protected: false, locked: false, createdAt: 1, fingerprint: 'fp-p1' }],
    secrets: { p1: {} },
    devices: { p1: { issued: [], revoked: [] } }
  }
  pcount = 1; nonce = 0; paircount = 0
}
const find = (id) => model.profiles.find((p) => p.id === id)
function resolveTarget (req) {
  const ref = req?.profile
  if (!ref) return model.current
  const byId = find(ref); if (byId) return byId.id
  const byName = model.profiles.find((p) => (p.name || '').toLowerCase() === String(ref).toLowerCase())
  return byName ? byName.id : model.current
}
const listSecretsOf = (t) => {
  const out = {}; const s = model.secrets[t] || {}
  for (const ns of Object.keys(s)) out[ns] = Object.keys(s[ns])
  return out
}
function dumpProfiles (extra = {}) {
  writeAtomic('profiles-list.json', {
    current: model.current,
    profiles: model.profiles.map((p) => ({ ...p, current: p.id === model.current })),
    ...extra
  })
}
function handleProfile (req) {
  const t = resolveTarget(req)
  switch (req.op) {
    case 'list': return {}
    case 'add': { const id = 'p' + (++pcount); model.profiles.push({ id, name: req.name || '', protected: false, locked: false, createdAt: Date.now(), fingerprint: 'fp-' + id }); model.secrets[id] = {}; model.devices[id] = { issued: [], revoked: [] }; return { done: 'perfil creado: ' + (req.name || id) } }
    case 'rm': { if (model.profiles.length <= 1) throw new Error('no se puede borrar el único perfil'); const p = find(t); if (p.protected && p.locked) throw new Error('perfil bloqueado'); model.profiles = model.profiles.filter((x) => x.id !== t); delete model.secrets[t]; delete model.devices[t]; if (model.current === t) model.current = model.profiles[0].id; return { done: 'perfil borrado: ' + (p.name || t) } }
    case 'rename': { const p = find(t); if (p.protected && p.locked) throw new Error('perfil bloqueado'); p.name = req.name; return { done: 'renombrado' } }
    case 'use': { model.current = t; return { done: 'activo' } }
    case 'unlock': { const p = find(t); if (p.protected) { if (req.password !== 'secret') throw new Error('contraseña incorrecta'); p.locked = false } return { done: 'desbloqueado' } }
    case 'lock': { const p = find(t); if (p.protected) p.locked = true; return { done: 'bloqueado' } }
    case 'password-set': { const p = find(t); if (p.protected && p.locked) throw new Error('perfil bloqueado'); p.protected = true; p.locked = false; return { done: 'contraseña guardada' } }
    case 'password-rm': { const p = find(t); p.protected = false; p.locked = false; return { done: 'contraseña quitada' } }
    default: throw new Error('op desconocida')
  }
}

function onUsr2 () {
  const appr = readReq('approve-request.json')
  if (appr?.code) {
    const t = resolveTarget(appr)
    const pe = readRaw('pending-enroll.json')
    if (pe?.deviceId) { (model.devices[t] ??= { issued: [], revoked: [] }).issued.push({ sub: null, label: pe.label || 'nuevo', scope: ['vault:sign', 'vault:read', 'vault:store'], exp: Date.now() + 30 * 864e5, nonce: 'n' + (++nonce) }) }
    rm('pending-enroll.json'); rm('pair.json')
  }
  const rej = readReq('reject-request.json'); if (rej?.deviceId) rm('pending-enroll.json')
  const rv = readReq('revoke-request.json')
  if (rv?.nonce) { const t = resolveTarget(rv); const dv = model.devices[t]; const i = dv.issued.findIndex((d) => String(d.nonce) === String(rv.nonce)); if (i >= 0) { const [d] = dv.issued.splice(i, 1); dv.revoked.push({ nonce: d.nonce }) } }
  const sec = readReq('secret-request.json')
  // El store real valida ns/clave (secretsStore.js); si no valen, NO aplica (y
  // vaultControl detecta que la clave no quedó guardada → lanza).
  const NS_OK = (ns) => /^[a-z0-9-]{1,32}$/.test(ns || '')
  const KEY_OK = (k) => /^[A-Z0-9_]{1,64}$/.test(k || '')
  if (sec?.op) { const t = resolveTarget(sec); model.secrets[t] ??= {}; if (sec.op === 'set' && NS_OK(sec.ns) && KEY_OK(sec.key) && sec.value) { (model.secrets[t][sec.ns] ??= {})[sec.key] = sec.value } else if (sec.op === 'rm' && NS_OK(sec.ns)) { if (model.secrets[t][sec.ns]) { delete model.secrets[t][sec.ns][sec.key]; if (!Object.keys(model.secrets[t][sec.ns]).length) delete model.secrets[t][sec.ns] } } }
  const preq = readReq('profile-request.json')
  let extra = {}
  if (preq?.op) { try { extra = handleProfile(preq) } catch (e) { extra = { error: e.message } } }
  dumpProfiles(extra)
  const dreq = readReq('dump-request.json')
  const t = resolveTarget(dreq || appr || rej || rv || sec || {})
  writeAtomic('secrets-list.json', { profile: t, ns: listSecretsOf(t) })
  writeAtomic('devices.json', { profile: t, issued: model.devices[t]?.issued || [], revoked: model.devices[t]?.revoked || [] })
}
function onUsr1 () {
  const preq = readReq('pair-request.json')
  const t = resolveTarget(preq)
  const qr = { v: 2, iss: 'ISS-' + t, proxy: 'ws://test', token: 'tok' + (++paircount), sn: 'sn1', service: preq?.service }
  writeAtomic('pair.json', { qr, expiresAt: Date.now() + 5 * 60000, profile: t })
}

before(async () => {
  // Evita que el runtime escriba diagnostic reports al recibir SIGUSR2 (este
  // proceso se auto-señala como daemon falso; solo pasa en el test).
  try { if (process.report) process.report.reportOnSignal = false } catch {}
  resetModel()
  fs.writeFileSync(P('state.json'), JSON.stringify({ v: 2, version: 'test', pid: process.pid, proxy: 'ws://test', current: model.current, profiles: model.profiles }))
  process.on('SIGUSR2', onUsr2)
  process.on('SIGUSR1', onUsr1)
  vc = await import('../src/vaultControl.js')
})
after(() => {
  process.off('SIGUSR2', onUsr2); process.off('SIGUSR1', onUsr1)
  try { fs.rmSync(root, { recursive: true, force: true }) } catch {}
})

// --------------------------------- tests -----------------------------------

test('daemonAlive y readState', () => {
  assert.equal(vc.daemonAlive(), true)
  assert.equal(vc.readState().version, 'test')
})

test('perfiles: list / add / use / rename / rm', async () => {
  let d = await vc.listProfiles()
  assert.equal(d.profiles.length, 1)
  assert.equal(d.profiles[0].current, true)

  d = await vc.addProfile('Trabajo')
  assert.equal(d.profiles.length, 2)
  const trabajo = d.profiles.find((p) => p.name === 'Trabajo')
  assert.ok(trabajo)
  assert.equal(trabajo.current, false) // add no cambia el activo

  d = await vc.useProfile('Trabajo')
  assert.equal(d.profiles.find((p) => p.name === 'Trabajo').current, true)

  d = await vc.renameProfile(trabajo.id, 'Oficina')
  assert.ok(d.profiles.find((p) => p.name === 'Oficina'))

  await vc.useProfile('Perfil 1')
  d = await vc.removeProfile(trabajo.id)
  assert.equal(d.profiles.length, 1)
})

test('candado: unlock exige la contraseña; rename bloqueado falla', async () => {
  await vc.setProfilePassword('p1', 'secret')
  let d = await vc.listProfiles()
  assert.equal(d.profiles[0].protected, true)

  await vc.lockProfile('p1')
  d = await vc.listProfiles()
  assert.equal(d.profiles[0].locked, true)

  // editar bloqueada => error propagado del daemon
  await assert.rejects(() => vc.renameProfile('p1', 'X'), /bloqueado/)

  await assert.rejects(() => vc.unlockProfile('p1', 'mala'), /incorrecta/)
  d = await vc.unlockProfile('p1', 'secret')
  assert.equal(d.done, 'desbloqueado')

  await vc.removeProfilePassword('p1')
  d = await vc.listProfiles()
  assert.equal(d.profiles[0].protected, false)
})

test('secretos: set / list / delete variable / delete scope', async () => {
  await vc.setSecret('proxy', 'TURN_KEY_ID', 'abc123', 'p1')
  await vc.setSecret('proxy', 'TURN_SECRET', 'shhh', 'p1')
  await vc.setSecret('geo', 'API_TOKEN', 'zzz', 'p1')

  let ns = await vc.listSecrets('p1')
  assert.deepEqual(ns.proxy.sort(), ['TURN_KEY_ID', 'TURN_SECRET'])
  assert.deepEqual(ns.geo, ['API_TOKEN'])

  ns = await vc.deleteSecret('proxy', 'TURN_KEY_ID', 'p1')
  assert.deepEqual(ns.proxy, ['TURN_SECRET'])

  ns = await vc.deleteScope('proxy', 'p1')
  assert.equal(ns.proxy, undefined)
  assert.ok(ns.geo) // el otro scope sigue

  await assert.rejects(() => vc.setSecret('BAD NS', 'K', 'v', 'p1').catch((e) => { throw e }))
})

test('dispositivos: pair / pending / approve / revoke', async () => {
  const pair = await vc.startPairing({ profile: 'p1' })
  assert.match(pair.url, /profile\.dotrino\.com\/#vault=/)
  assert.ok(pair.payload.includes('tok'))
  assert.ok(pair.expiresAt > Date.now())

  // simula un dispositivo conectándose (lo que escribiría el daemon real)
  fs.writeFileSync(P('pending-enroll.json'), JSON.stringify({ v: 2, at: Date.now(), deviceId: 'AB12-CD34', label: 'móvil', profile: 'p1' }))
  const pe = vc.pendingEnroll()
  assert.equal(pe.deviceId, 'AB12-CD34')

  const after1 = await vc.approvePending('123456', 'p1')
  assert.equal(after1.issued.length, 1)
  assert.equal(after1.issued[0].deviceId, '????-????') // sub null → fallback
  assert.equal(vc.pendingEnroll(), null)

  const nonceVal = after1.issued[0].nonce
  const after2 = await vc.revokeDevice(nonceVal, 'p1')
  assert.equal(after2.issued.length, 0)
  assert.equal(after2.revoked.length, 1)
})

test('reject limpia el pendiente', async () => {
  fs.writeFileSync(P('pending-enroll.json'), JSON.stringify({ v: 2, at: Date.now(), deviceId: 'EE99-FF00', profile: 'p1' }))
  assert.ok(vc.pendingEnroll())
  await vc.rejectPending('EE99-FF00', 'p1')
  assert.equal(vc.pendingEnroll(), null)
})

test('deviceIdOf: null → ????-????', async () => {
  assert.equal(await vc.deviceIdOf(null), '????-????')
})

test('daemon caído: señalar lanza DAEMON_DOWN', async () => {
  const saved = fs.readFileSync(P('state.json'), 'utf8')
  // pid imposible (nunca vivo)
  fs.writeFileSync(P('state.json'), JSON.stringify({ ...JSON.parse(saved), pid: 2 ** 31 - 1 }))
  assert.equal(vc.daemonAlive(), false)
  await assert.rejects(() => vc.listProfiles(), (e) => e.code === 'DAEMON_DOWN')
  fs.writeFileSync(P('state.json'), saved)
})
