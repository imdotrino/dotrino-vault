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
    revoke: async (n) => { calls.push(['revoke', n]); return { ok: true, nonce: n } },
    revokeDevice: async (sub) => { calls.push(['revokeDevice', sub]); return { ok: true, nonces: ['n1', 'n2'], seq: 24 } }
  }
}

/**
 * Mostrador de VARIABLES de mentira. El de verdad (la bóveda) es quien sella y quien
 * decide qué valor sale; acá solo se comprueba el enrutado y el límite.
 */
function fakeVars () {
  const calls = []
  return {
    calls,
    list: async (a) => { calls.push(['list', a]); return { enc: { epk: 'EPK', iv: 'IV', ct: 'CT' } } },
    set: async (a) => { calls.push(['set', a]); return { ok: true, key: a.key } }
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

/**
 * EL FANTASMA. Quitar un aparato es sacarlo del acta Y retirarle los papeles, y eso solo
 * pasa por `sub`. La consola web mandaba `certNonce` (uno por certificado), que retira el
 * papel y deja al miembro dentro: desaparecía de la lista de abajo, seguía en la de arriba
 * para siempre, y la bóveda ya nunca le mandaba el aviso de expulsión —porque mientras
 * sigas en el acta, un papel retirado significa «renueva», no «estás fuera»—, así que el
 * aparato se quedaba enseñando la cuenta como si nada.
 */
test('quitar un dispositivo va por su LLAVE, y el aviso dice a quién quitaron', async () => {
  const { admin, desk, notices, audits } = mount()

  const r = await admin.handle({ op: 'revoke', sub: 'DPUB-MAC1', nonce: nonce('r') })

  assert.equal(r.ok, true)
  assert.deepEqual(desk.calls, [['revokeDevice', 'DPUB-MAC1']], 'una sola llamada, por llave')
  assert.equal(r.result.seq, 24, 'y el acta avanzó: el miembro salió de verdad')
  assert.equal(notices[0][1].deviceId, 'AD01-AD01', 'el aviso nombra al aparato quitado')
  assert.ok(audits.some(([op, i]) => op === 'admin.revoke-device' && i.certs === 2),
    'quedan anotados los DOS certificados retirados, no solo el último')
})

test('`certNonce` retira un papel y NO toca el acta (no es «quitar»)', async () => {
  const { admin, desk } = mount()

  await admin.handle({ op: 'revoke', certNonce: 'n-42', nonce: nonce('s') })

  assert.deepEqual(desk.calls, [['revoke', 'n-42']], 'sigue existiendo, pero es otra cosa')
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

// --------------------------- variables de entorno ---------------------------

test('sin mostrador de variables, la consola lo dice en vez de fingir que guardó', async () => {
  const { admin } = mount()
  for (const op of ['vars', 'var.set']) {
    const r = await admin.handle({ op, ns: 'proxy', key: 'PORT', enc: { ct: 'x' }, nonce: nonce(op.padEnd(32, 'z')) })
    assert.equal(r.ok, false)
    assert.match(r.error, /does not serve environment variables/)
  }
})

test('ver variables: viene lo que da la bóveda, sellado, y queda quién lo pidió', async () => {
  const vars = fakeVars()
  const { admin, audits } = mount({ vars })

  const r = await admin.handle({ op: 'vars', nonce: nonce('v') })

  assert.equal(r.ok, true)
  assert.ok(r.result.enc.ct, 'la lista viaja en un sobre: el proxy no ve ni los nombres')
  assert.equal(vars.calls[0][1].by, 'AD01-AD01')
  assert.ok(audits.some(([op, i]) => op === 'admin.vars' && i.by === 'AD01-AD01'))
})

test('poner valor: UN destino, y el valor SIEMPRE dentro del sobre', async () => {
  const vars = fakeVars()
  const { admin } = mount({ vars })

  // Sin destino, o con los dos, no se adivina dónde acaba la variable.
  const sinDestino = await admin.handle({ op: 'var.set', key: 'PORT', enc: { ct: 'x' }, nonce: nonce('1') })
  assert.match(sinDestino.error, /exactly one target/)
  const dosDestinos = await admin.handle({ op: 'var.set', ns: 'proxy', pub: 'PUB', key: 'PORT', enc: { ct: 'x' }, nonce: nonce('2') })
  assert.match(dosDestinos.error, /exactly one target/)

  // Un valor en claro no se acepta: no es algo que se pueda «arreglar» guardándolo igual.
  const enClaro = await admin.handle({ op: 'var.set', ns: 'proxy', key: 'PORT', value: '8443', nonce: nonce('3') })
  assert.match(enClaro.error, /sealed with the profile content key/)

  const sinClave = await admin.handle({ op: 'var.set', ns: 'proxy', enc: { ct: 'x' }, nonce: nonce('4') })
  assert.match(sinClave.error, /needs a key/)

  assert.deepEqual(vars.calls, [], 'nada de eso llegó a la bóveda')
})

test('poner valor llega al cajón que toca, con su visibilidad, y se AVISA a todos', async () => {
  const vars = fakeVars()
  const { admin, notices, audits } = mount({ vars })

  const enScope = await admin.handle({ op: 'var.set', ns: 'proxy', key: 'PUBLIC_URL', enc: { ct: 'x' }, public: true, nonce: nonce('5') })
  assert.equal(enScope.ok, true)
  assert.deepEqual(
    { ns: vars.calls[0][1].ns, pub: vars.calls[0][1].pub, key: vars.calls[0][1].key, public: vars.calls[0][1].public },
    { ns: 'proxy', pub: null, key: 'PUBLIC_URL', public: true }
  )

  await admin.handle({ op: 'var.set', pub: 'PUB-DEL-PROXY', key: 'PORT', enc: { ct: 'x' }, nonce: nonce('6') })
  const alAparato = vars.calls[1][1]
  assert.equal(alAparato.ns, null)
  assert.equal(alAparato.pub, 'PUB-DEL-PROXY')
  assert.equal(alAparato.public, undefined, 'sin decir nada, la bóveda conserva la visibilidad')

  // Cambiar la configuración de un servicio a distancia no puede ser invisible.
  assert.deepEqual(notices.map(([ev]) => ev), ['vars', 'vars'])
  assert.equal(notices[0][1].by, 'AD01-AD01')
  assert.ok(audits.some(([op, i]) => op === 'admin.var.set' && i.key === 'PUBLIC_URL' && i.ns === 'proxy'))
})

test('BORRAR variables no existe a distancia (un aparato robado no te deja sin configuración)', async () => {
  const { admin } = mount({ vars: fakeVars() })
  for (const op of ['var.rm', 'var.delete', 'vars.rm']) {
    const r = await admin.handle({ op, ns: 'proxy', key: 'PORT', nonce: nonce(op.padEnd(32, 'y')) })
    assert.match(r.error, /invalid operation/)
  }
})
