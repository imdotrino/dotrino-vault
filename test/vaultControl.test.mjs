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
    // El segundo cajón: variables de UN aparato (pub → KEY → valor).
    devSecrets: { p1: {} },
    devices: { p1: { issued: [], revoked: [] } }
  }
  pcount = 1; nonce = 0; paircount = 0
}
const find = (id) => model.profiles.find((p) => p.id === id)
const isLocked = (id) => { const p = find(id); return !!(p?.protected && p.locked) }
function resolveTarget (req) {
  const ref = req?.profile
  if (!ref) return model.current
  const byId = find(ref); if (byId) return byId.id
  const byName = model.profiles.find((p) => (p.name || '').toLowerCase() === String(ref).toLowerCase())
  return byName ? byName.id : model.current
}
const listSecretsOf = (t) => {
  const out = {}; const s = model.secrets[t] || {}
  for (const ns of Object.keys(s)) out[ns] = Object.entries(s[ns]).map(([key, e]) => ({ key, public: !!e.pub }))
  return out
}
// Volcado del cajón por aparato, con la forma que arma el daemon de verdad
// (`vault.listDeviceSecrets()`): una fila por llave, con sus claves y sin valores.
const listDevSecretsOf = (t) => Object.entries(model.devSecrets[t] || {})
  .map(([pub, vars]) => ({
    pub, id: 'ID-' + pub, label: '', cn: 'proxy', orphan: false,
    keys: Object.entries(vars).map(([key, e]) => ({ key, public: !!e.pub }))
  }))
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
    case 'add': { const id = 'p' + (++pcount); model.profiles.push({ id, name: req.name || '', protected: false, locked: false, createdAt: Date.now(), fingerprint: 'fp-' + id }); model.secrets[id] = {}; model.devSecrets[id] = {}; model.devices[id] = { issued: [], revoked: [] }; return { done: 'perfil creado: ' + (req.name || id) } }
    case 'rm': { if (model.profiles.length <= 1) throw new Error('no se puede borrar el único perfil'); const p = find(t); if (p.protected && p.locked) throw new Error('profile locked'); model.profiles = model.profiles.filter((x) => x.id !== t); delete model.secrets[t]; delete model.devSecrets[t]; delete model.devices[t]; if (model.current === t) model.current = model.profiles[0].id; return { done: 'perfil borrado: ' + (p.name || t) } }
    case 'rename': { const p = find(t); if (p.protected && p.locked) throw new Error('profile locked'); p.name = req.name; return { done: 'renombrado' } }
    case 'use': { model.current = t; return { done: 'activo' } }
    case 'unlock': { const p = find(t); if (p.protected) { if (req.password !== 'secret') throw new Error('wrong password'); p.locked = false } return { done: 'desbloqueado' } }
    case 'lock': { const p = find(t); if (p.protected) p.locked = true; return { done: 'bloqueado' } }
    case 'password-set': { const p = find(t); if (p.protected && p.locked) throw new Error('profile locked'); p.protected = true; p.locked = false; return { done: 'contraseña guardada' } }
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
  if (sec?.op) {
    const t = resolveTarget(sec); model.secrets[t] ??= {}; model.devSecrets[t] ??= {}
    // Como el store real: una variable guardada es { v, pub }, y sin decir nada conserva
    // su visibilidad (o nace privada).
    const put = (bag, k, key, value, isPublic) => {
      const before = (bag[k] ??= {})[key]
      bag[k][key] = { v: value, pub: isPublic === undefined ? !!before?.pub : !!isPublic }
    }
    if (sec.op === 'set' && NS_OK(sec.ns) && KEY_OK(sec.key) && sec.value) { put(model.secrets[t], sec.ns, sec.key, sec.value, sec.public) }
    else if (sec.op === 'rm' && NS_OK(sec.ns)) { if (model.secrets[t][sec.ns]) { delete model.secrets[t][sec.ns][sec.key]; if (!Object.keys(model.secrets[t][sec.ns]).length) delete model.secrets[t][sec.ns] } }
    else if (sec.op === 'dev-set' && sec.pub && KEY_OK(sec.key) && sec.value) { put(model.devSecrets[t], sec.pub, sec.key, sec.value, sec.public) }
    else if (sec.op === 'dev-rm' && sec.pub) { if (model.devSecrets[t][sec.pub]) { delete model.devSecrets[t][sec.pub][sec.key]; if (!Object.keys(model.devSecrets[t][sec.pub]).length) delete model.devSecrets[t][sec.pub] } }
    else if (sec.op === 'vis' && NS_OK(sec.ns)) { const e = model.secrets[t][sec.ns]?.[sec.key]; if (e) e.pub = !!sec.public }
    else if (sec.op === 'dev-vis' && sec.pub) { const e = model.devSecrets[t][sec.pub]?.[sec.key]; if (e) e.pub = !!sec.public }
  }
  const preq = readReq('profile-request.json')
  // La lista de bóvedas SOLO se vuelca contestando a una petición de perfil, igual que el
  // daemon de verdad: volcarla también por su cuenta se llevaba por delante las respuestas.
  if (preq?.op) {
    let extra = {}
    try { extra = handleProfile(preq) } catch (e) { extra = { error: e.message } }
    dumpProfiles({ ...extra, req: preq.id || null })
  }
  // LOS VOLCADOS SON RESPUESTAS: solo se escriben si alguien preguntó, y llevan el id de
  // SU petición. Igual que el daemon de verdad — escribirlos en cada vuelta se llevaba por
  // delante la respuesta que otro estaba esperando.
  const dreq = readReq('dump-request.json')
  const meReq = readReq('me-request.json')
  if (!dreq && !meReq) return
  const req = dreq?.id || null
  const t = resolveTarget(dreq || meReq || appr || rej || rv || sec || {})
  // EL CANDADO es de esta consola: un perfil bloqueado contesta que lo está y NADA de lo
  // suyo (ni aparatos, ni variables, ni acta), igual que el daemon de verdad.
  if (isLocked(t)) {
    const cerrado = { req, profile: t, locked: true }
    if (dreq) {
      writeAtomic('secrets-list.json', { ...cerrado, ns: {}, dev: [] })
      writeAtomic('devices.json', { ...cerrado, issued: [], revoked: [] })
      writeAtomic('acta.json', { ...cerrado, members: [] })
    }
    if (meReq) writeAtomic('me.json', { ...cerrado, req: meReq.id || null, me: null })
    return
  }
  if (dreq) {
    // Los tres contestan a la MISMA petición y llevan su id: sin el acta, `snapshot` se
    // quedaba esperándola los seis segundos de rendirse en cada llamada.
    writeAtomic('secrets-list.json', { req, profile: t, ns: listSecretsOf(t), dev: listDevSecretsOf(t) })
    writeAtomic('devices.json', { req, profile: t, issued: model.devices[t]?.issued || [], revoked: model.devices[t]?.revoked || [] })
    writeAtomic('acta.json', { req, profile: t, members: model.members?.[t] || [] })
  }
  if (meReq) writeAtomic('me.json', { req: meReq.id || null, profile: t, me: model.me?.[t] ?? null })
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
  await assert.rejects(() => vc.renameProfile('p1', 'X'), /profile locked/)

  await assert.rejects(() => vc.unlockProfile('p1', 'mala'), /wrong password/)
  d = await vc.unlockProfile('p1', 'secret')
  assert.equal(d.done, 'desbloqueado')

  await vc.removeProfilePassword('p1')
  d = await vc.listProfiles()
  assert.equal(d.profiles[0].protected, false)
})

/** Nombres de una lista de variables (que viaja como `{key, public}`), ordenados. */
const keyNames = (list) => (list || []).map((x) => x.key).sort()

test('por scope: set / list / delete variable / delete scope', async () => {
  await vc.setSecret('proxy', 'TURN_KEY_ID', 'abc123', 'p1')
  await vc.setSecret('proxy', 'TURN_SECRET', 'shhh', 'p1')
  await vc.setSecret('geo', 'API_TOKEN', 'zzz', 'p1')

  let out = await vc.listSecrets('p1')
  assert.deepEqual(keyNames(out.ns.proxy), ['TURN_KEY_ID', 'TURN_SECRET'])
  assert.deepEqual(keyNames(out.ns.geo), ['API_TOKEN'])
  assert.ok(out.ns.geo.every((v) => v.public === false), 'nacen privadas')
  assert.deepEqual(out.dev, [], 'el cajón por aparato viaja siempre, aunque esté vacío')

  out = await vc.deleteSecret('proxy', 'TURN_KEY_ID', 'p1')
  assert.deepEqual(keyNames(out.ns.proxy), ['TURN_SECRET'])

  out = await vc.deleteScope('proxy', 'p1')
  assert.equal(out.ns.proxy, undefined)
  assert.ok(out.ns.geo) // el otro scope sigue

  await assert.rejects(() => vc.setSecret('BAD NS', 'K', 'v', 'p1').catch((e) => { throw e }))
})

test('por aparato: son OTRO cajón, no tocan el del scope', async () => {
  const pub = 'PUB-DEL-PROXY-1'
  await vc.setSecret('proxy', 'TURN_KEY_ID', 'compartida', 'p1')
  await vc.setDeviceSecret(pub, 'PORT', '8443', 'p1')
  await vc.setDeviceSecret(pub, 'PUBLIC_URL', 'https://uno.example', 'p1')

  let out = await vc.listSecrets('p1')
  assert.deepEqual(keyNames(out.ns.proxy), ['TURN_KEY_ID'], 'lo del scope sigue donde estaba')
  const row = out.dev.find((x) => x.pub === pub)
  assert.deepEqual(keyNames(row.keys), ['PORT', 'PUBLIC_URL'])
  assert.equal(row.cn, 'proxy')

  out = await vc.deleteDeviceSecret(pub, 'PORT', 'p1')
  assert.deepEqual(keyNames(out.dev.find((x) => x.pub === pub).keys), ['PUBLIC_URL'])

  // Quitarlas todas hace desaparecer al aparato de la lista, no lo deja vacío.
  out = await vc.deleteDeviceVars(pub, 'p1')
  assert.equal(out.dev.find((x) => x.pub === pub), undefined)
  assert.deepEqual(keyNames(out.ns.proxy), ['TURN_KEY_ID'], 'y el scope ni se entera')

  await assert.rejects(() => vc.setDeviceSecret(pub, 'minusculas', 'v', 'p1').catch((e) => { throw e }))
})

test('visibilidad: se marca al crear, se cambia sin tocar el valor, y no se contagia', async () => {
  // Pública o privada dice si el VALOR puede salir de la máquina de la bóveda hacia la
  // consola remota. Nada de esto viaja en las listas: solo la marca.
  const pub = 'PUB-DEL-PROXY-2'
  await vc.setSecret('web', 'PUBLIC_URL', 'https://ejemplo.com', 'p1', true)
  await vc.setSecret('web', 'API_KEY', 'sk-secreta', 'p1')

  let out = await vc.listSecrets('p1')
  const varOf = (ns, key) => out.ns[ns].find((x) => x.key === key)
  assert.equal(varOf('web', 'PUBLIC_URL').public, true)
  assert.equal(varOf('web', 'API_KEY').public, false, 'sin decir nada, privada')

  // Rotar el valor NO cambia quién puede verlo (o rotar una llave la expondría sin querer).
  out = await vc.setSecret('web', 'PUBLIC_URL', 'https://otro.com', 'p1')
  assert.equal(varOf('web', 'PUBLIC_URL').public, true)

  out = await vc.setSecretVisibility('web', 'PUBLIC_URL', false, 'p1')
  assert.equal(varOf('web', 'PUBLIC_URL').public, false)

  await vc.setDeviceSecret(pub, 'PORT', '8443', 'p1', true)
  out = await vc.listSecrets('p1')
  const row = out.dev.find((x) => x.pub === pub)
  assert.equal(row.keys.find((x) => x.key === 'PORT').public, true)
  out = await vc.setDeviceSecretVisibility(pub, 'PORT', false, 'p1')
  assert.equal(out.dev.find((x) => x.pub === pub).keys.find((x) => x.key === 'PORT').public, false)
})

test('EL CANDADO: bloqueada no se ve ni se toca desde esta consola', async () => {
  // Lo que la contraseña protege es la CONSOLA de la máquina de la bóveda: con el perfil
  // bloqueado no se enseñan sus aparatos, ni sus variables, ni sus datos, y no se puede
  // operar sobre él. (A los aparatos ya emparejados la bóveda les sigue respondiendo: eso
  // pasa por el proxy, no por aquí.)
  await vc.setProfilePassword('p1', 'secret')
  await vc.lockProfile('p1')

  for (const [que, fn] of [
    ['los aparatos', () => vc.listDevices('p1')],
    ['el acta', () => vc.listMembers('p1')],
    ['las variables', () => vc.listSecrets('p1')],
    ['tus datos', () => vc.getMe('p1')],
    ['guardar una variable', () => vc.setSecret('proxy', 'K', 'v', 'p1')],
    ['quitar un aparato', () => vc.revokeDevice({ sub: 'PUB' }, 'p1')]
  ]) {
    await assert.rejects(fn, (e) => e.code === 'PROFILE_LOCKED', `debería negarse: ${que}`)
  }

  // La LISTA de bóvedas sí se ve: hay que poder saber que existe y que está cerrada.
  const d = await vc.listProfiles()
  const p1 = d.profiles.find((p) => p.id === 'p1')
  assert.equal(p1.locked, true)

  // Y con la contraseña se abre y vuelve todo.
  await vc.unlockProfile('p1', 'secret')
  const dev = await vc.listDevices('p1')
  assert.ok(Array.isArray(dev.issued))
  await vc.removeProfilePassword('p1')
})

test('dispositivos: pair / pending / approve / revoke', async () => {
  const pair = await vc.startPairing({ profile: 'p1' })
  assert.match(pair.url, /vault\.dotrino\.com\/d#v=/)
  assert.ok(pair.payload.includes('tok'))
  // Este QR de mentira (token 'tok1', `iss` que no es una JWK) no se puede
  // comprimir: el codec lo detecta y cae solo a la forma larga (`b`) en vez de
  // inventarse una invitación que no reproduce el original.
  assert.match(pair.code, /^b[A-Za-z0-9_-]+$/)
  assert.ok(pair.url.endsWith(pair.code))
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

/**
 * REGRESIÓN (2026-07-28): el enlace del QR tiene que salir CORTO —cada carácter son
 * módulos, y los módulos son filas de terminal— y tiene que seguir leyéndose
 * DESPUÉS de pasar por el navegador. Hubo una versión que lo achicaba mandando JSON
 * crudo en el `#fragment`: el navegador percent-codifica las comillas y el cliente
 * ya no lo entendía. Hoy va comprimido en base64url, que es seguro en una URL.
 */
test('el enlace del QR sale corto y sobrevive al navegador', async () => {
  const { pairUrl } = await import('../src/vaultControl.js')
  const { parseInvite } = await import('../lib/src/invite.js')
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const qr = {
    v: 2,
    iss: JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey)),
    proxy: 'wss://proxy.dotrino.com',
    token: 'a'.repeat(24),
    sn: 'b'.repeat(24),
    m: 'join',
    acct: 'Perfil 1'
  }
  const { url, code, payload } = pairUrl(qr)

  // 1. Corto: el enlace entero pesa menos que el JSON que representa.
  assert.match(url, /^https:\/\/vault\.dotrino\.com\/d#v=c[A-Za-z0-9_-]+$/)
  assert.ok(url.length < JSON.stringify(qr).length / 2, `el enlace del QR es corto (${url.length})`)
  // 2. Base64url es seguro en una URL: el navegador no lo toca.
  assert.equal(encodeURI(url), url)
  assert.deepEqual(parseInvite(encodeURI(url)), qr)
  // 3. La misma invitación sirve para pegar: una palabra, sin comillas ni llaves.
  assert.equal(code, url.slice(url.indexOf('#v=') + 3))
  assert.deepEqual(parseInvite(code), qr)
  assert.equal(payload, JSON.stringify(qr))
})

test('un volcado que NO contesta a nadie no se toma por respuesta (el rechazo no se pierde)', async () => {
  // LA REGRESIÓN. El daemon repasa su carpeta cada dos segundos y volcaba la lista de
  // perfiles en cada pasada. Si una de esas caía entre la petición y quien la esperaba,
  // se tomaba por respuesta: el «contraseña incorrecta» desaparecía —la TUI daba el
  // desbloqueo por bueno— y la bóveda seguía cerrada, así que a la siguiente tecla
  // volvía a pedir la contraseña sin decir por qué. Ahora cada volcado dice A QUÉ
  // PETICIÓN contesta (`req`), y el que no contesta a ninguna se ignora.
  process.off('SIGUSR2', onUsr2)
  const ruidoPrimero = () => {
    const preq = readReq('profile-request.json')
    dumpProfiles({ req: null })        // el repaso del daemon, que no contesta a nadie
    setTimeout(() => dumpProfiles({    // la respuesta de verdad, un poco después
      req: preq?.id ?? null, error: 'wrong password', code: 'WRONG_PASSWORD', tries: 3
    }), 300)
  }
  process.on('SIGUSR2', ruidoPrimero)
  try {
    await assert.rejects(
      () => vc.unlockProfile(model.profiles[0].id, 'la-que-sea'),
      (e) => e.code === 'WRONG_PASSWORD' && e.tries === 3
    )
  } finally {
    process.off('SIGUSR2', ruidoPrimero)
    process.on('SIGUSR2', onUsr2)
  }
})

test('el volcado NO espera a la lista de bóvedas: contesta en cuanto llega lo suyo', async () => {
  // LA OTRA MITAD DE LA MISMA REGRESIÓN. Al dejar de volcar `profiles-list.json` sin que
  // nadie lo pidiera, `snapshot()` se quedó esperando un archivo que ya no iba a llegar:
  // seis segundos —los de rendirse— en CADA refresco, con el daemon contestando lo suyo en
  // cien milisegundos. Eso era la TUI colgada en «Cargando dispositivos…».
  // Una bóveda recién creada (las de antes quedaron con candado): lo que se mide es el
  // volcado, no el candado.
  await vc.addProfile('cronómetro')
  const t0 = Date.now()
  const r = await vc.listDevices('cronómetro')
  const tardo = Date.now() - t0
  assert.ok(Array.isArray(r.issued), 'contesta con la lista')
  assert.ok(tardo < 2000, `tiene que contestar en cuanto llega el volcado, no rendirse (tardó ${tardo} ms)`)
})
