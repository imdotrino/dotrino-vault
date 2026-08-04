/**
 * Consola remota (`lib/src/admin.js`): administrar el perfil desde un dispositivo, sin red.
 *
 * Lo que de verdad se prueba acá es **el límite**: que un cert `vault:admin` sirva para
 * admitir y expulsar, y NO para ascender a nadie ni para colarse en los secretos. Y que
 * un `approve` reproducido no valga dos veces — es la única op donde la ventana de
 * frescura de ±5 min no alcanza, porque cambia estado.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createAdminDesk, ADMIN_OPS } from '../lib/src/admin.js'

const nonce = (n = 'a') => n.repeat(32)

/** Mostrador de emparejamiento de mentira: registra qué le pidieron. */
function fakeDesk () {
  const calls = []
  return {
    calls,
    listPending: () => [{ deviceId: 'XQ7F-3K9P', label: 'celular', scope: ['vault:read'] }],
    startPairing: async (o) => { calls.push(['startPairing', o]); return { qr: 'cAAAA', expiresInMs: 300000 } },
    approve: async (code, o) => { calls.push(['approve', code, o]); return { deviceId: o?.deviceId || null } },
    reject: (id) => { calls.push(['reject', id]) },
    revoke: async (n) => { calls.push(['revoke', n]); return { ok: true, nonce: n } }
  }
}

/** Monta la consola; por defecto el cert autoriza (`ok: true`). */
function mount ({ verify = async () => ({ ok: true, device: 'DPUB' }), ...rest } = {}) {
  const desk = fakeDesk()
  const audits = []
  const notices = []
  const admin = createAdminDesk({
    desk,
    verify,
    deviceIdOf: async () => 'AD01-AD01',
    audit: (op, info) => audits.push([op, info]),
    notify: async (ev, info) => notices.push([ev, info]),
    readActivity: (limit) => Array.from({ length: Math.min(limit, 7) }, (_, i) => ({ ts: i, op: 'sign' })),
    ...rest
  })
  return { admin, desk, audits, notices }
}

test('sin cert `vault:admin` no se administra nada', async () => {
  const { admin, desk, audits } = mount({ verify: async () => ({ ok: false, reason: 'scope' }) })

  for (const op of ADMIN_OPS) {
    const r = await admin.handle({ op, nonce: nonce(), ts: Date.now(), code: '111111', certNonce: 'n1' })
    assert.equal(r.ok, false, `${op} debe rechazarse`)
    assert.match(r.error, /unauthorized/)
  }
  assert.deepEqual(desk.calls, [], 'no se tocó el mostrador ni una vez')
  assert.ok(audits.every(([op]) => op === 'rejected'), 'y todo quedó en la bitácora')
})

test('el nonce es obligatorio y de un solo uso (approve no se reproduce)', async () => {
  const { admin, desk } = mount()

  const sinNonce = await admin.handle({ op: 'approve', code: '418027' })
  assert.equal(sinNonce.ok, false)
  assert.match(sinNonce.error, /nonce/)

  const uno = await admin.handle({ op: 'approve', code: '418027', deviceId: 'XQ7F-3K9P', nonce: nonce('b') })
  assert.equal(uno.ok, true)

  // El mismo mensaje otra vez, dentro de la ventana de frescura: no vale.
  const dos = await admin.handle({ op: 'approve', code: '418027', deviceId: 'XQ7F-3K9P', nonce: nonce('b') })
  assert.equal(dos.ok, false)
  assert.match(dos.error, /already used/)
  assert.equal(desk.calls.filter(([c]) => c === 'approve').length, 1, 'se aprobó UNA vez')
})

test('un cert inválido no le quema los nonces a un admin legítimo', async () => {
  let autoriza = false
  const { admin } = mount({ verify: async () => (autoriza ? { ok: true, device: 'D' } : { ok: false, reason: 'firma' }) })

  const n = nonce('c')
  assert.equal((await admin.handle({ op: 'pending', nonce: n })).ok, false, 'el impostor no pasa')
  autoriza = true
  assert.equal((await admin.handle({ op: 'pending', nonce: n })).ok, true, 'y el nonce sigue sirviendo')
})

test('EL LÍMITE: un admin no concede «administra» ni claves de servicio', async () => {
  const { admin, desk, audits } = mount()

  for (const malo of [['vault:admin'], ['vault:read', 'vault:admin'], ['vault:secrets:proxy']]) {
    const r = await admin.handle({ op: 'pair', scope: malo, nonce: nonce(String(malo)) })
    assert.equal(r.ok, false, `${malo} debe rechazarse`)
    assert.match(r.error, /vault machine/, 'y decir dónde SÍ se hace')
  }
  assert.deepEqual(desk.calls, [], 'ningún emparejamiento llegó a abrirse')
  assert.ok(audits.some(([, i]) => i?.reason === 'forbidden-scope'))

  const bueno = await admin.handle({ op: 'pair', scope: ['vault:read'], nonce: nonce('d') })
  assert.equal(bueno.ok, true)
  assert.equal(bueno.result.qr, 'cAAAA')
})

test('no existen las operaciones que no se delegan', async () => {
  const { admin } = mount()
  // No es que estén prohibidas: es que no hay mensaje que las nombre.
  for (const op of ['caps', 'handover', 'secrets', 'unlock', 'remove-profile']) {
    const r = await admin.handle({ op, nonce: nonce(op.padEnd(32, 'x')) })
    assert.equal(r.ok, false)
    assert.match(r.error, /invalid operation/)
  }
})

test('admitir y expulsar avisan a todos los miembros', async () => {
  const { admin, notices } = mount()

  await admin.handle({ op: 'approve', code: '418027', deviceId: 'XQ7F-3K9P', nonce: nonce('e') })
  await admin.handle({ op: 'revoke', certNonce: 'n-42', nonce: nonce('f') })
  // Rechazar no cambia el perfil: no hay nada que avisar.
  await admin.handle({ op: 'reject', deviceId: 'XQ7F-3K9P', nonce: nonce('g') })

  assert.deepEqual(notices.map(([ev]) => ev), ['enrolled', 'revoked'])
  assert.equal(notices[0][1].by, 'AD01-AD01', 'el aviso dice QUIÉN lo hizo')
  assert.equal(notices[1][1].certNonce, 'n-42')
})

test('la bitácora se lee acotada y con el actor en cada acción', async () => {
  const { admin, audits } = mount()

  const r = await admin.handle({ op: 'audit', limit: 9999, nonce: nonce('h') })
  assert.equal(r.ok, true)
  assert.ok(r.result.entries.length <= 500, 'el tope se respeta')

  await admin.handle({ op: 'pair', nonce: nonce('i') })
  const pair = audits.find(([op]) => op === 'admin.pair')
  assert.equal(pair[1].by, 'AD01-AD01', 'queda escrito qué dispositivo lo pidió')
})
