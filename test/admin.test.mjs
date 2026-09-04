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

test('el nonce es obligatorio y de un solo uso (revocar no se reproduce)', async () => {
  const { admin, desk } = mount()

  const sinNonce = await admin.handle({ op: 'revoke', certNonce: 'n-1' })
  assert.equal(sinNonce.ok, false)
  assert.match(sinNonce.error, /nonce/)

  const first = await admin.handle({ op: 'revoke', certNonce: 'n-1', nonce: nonce('b') })
  assert.equal(first.ok, true)

  // El mismo mensaje otra vez, dentro de la ventana de frescura: no vale.
  const dos = await admin.handle({ op: 'revoke', certNonce: 'n-1', nonce: nonce('b') })
  assert.equal(dos.ok, false)
  assert.match(dos.error, /already used/)
  assert.equal(desk.calls.filter(([c]) => c === 'revoke').length, 1, 'se revocó UNA vez')
})

test('un cert inválido no le quema los nonces a un admin legítimo', async () => {
  let authorized = false
  const { admin } = mount({ verify: async () => (authorized ? { ok: true, device: 'D' } : { ok: false, reason: 'firma' }) })

  const n = nonce('c')
  assert.equal((await admin.handle({ op: 'audit', nonce: n })).ok, false, 'el impostor no pasa')
  authorized = true
  assert.equal((await admin.handle({ op: 'audit', nonce: n })).ok, true, 'y el nonce sigue sirviendo')
})

/**
 * AGREGAR APARATOS SE QUITÓ DE AQUÍ (dueño, 2026-08-31), y de raíz: no hay operación, ni
 * mensaje, ni botón. El multivault quita la fricción que justificaba esto —cualquier otra
 * selladora abierta admite el aparato—, así que dejó de comprar nada y seguía pidiendo lo
 * caro: que la maestra firmara a distancia.
 *
 * Antes había aquí un test del LÍMITE (que un admin no se concediera `vault:admin` ni un
 * cajón de servicio al emparejar). Ya no hace falta un límite: no existe la puerta.
 */
test('agregar un aparato NO se puede desde la consola: la operación no existe', async () => {
  const { admin, desk } = mount()

  for (const op of ['pair', 'approve', 'reject', 'pending']) {
    const r = await admin.handle({ op, scope: ['vault:read'], code: '418027', deviceId: 'X', nonce: nonce(op.padEnd(32, 'z')) })
    assert.equal(r.ok, false, op)
    assert.match(r.error, /invalid operation/, `${op} no debe ni reconocerse`)
  }
  assert.deepEqual(desk.calls, [], 'el mostrador de emparejamiento no se toca desde aquí')
  assert.ok(!ADMIN_OPS.includes('pair') && !ADMIN_OPS.includes('approve'))
})

test('no existen las operaciones que no se delegan', async () => {
  const { admin } = mount()
  // No es que estén prohibidas: es que no hay mensaje que las nombre.
  //
  // `unlock` SALIÓ de esta lista el 2026-09-04: abrir a distancia sí existe ahora
  // (`docs/abrir-a-distancia.md`). Lo que no cambió es el resto — cambiar permisos,
  // traspasar el mando, leer secretos y borrar un perfil siguen sin tener mensaje.
  for (const op of ['caps', 'handover', 'secrets', 'remove-profile']) {
    const r = await admin.handle({ op, nonce: nonce(op.padEnd(32, 'x')) })
    assert.equal(r.ok, false)
    assert.match(r.error, /invalid operation/)
  }
})

/**
 * ABRIR A DISTANCIA EXISTE, PERO NO EN CUALQUIER BÓVEDA. El módulo es puro —sin cripto ni
 * disco— así que el trabajo va inyectado. Sin él, la operación contesta que no en vez de
 * romper con un TypeError, que es la diferencia entre «esta bóveda es vieja» y «se cayó».
 */
test('sin mostrador de apertura, abrir a distancia se contesta, no revienta', async () => {
  const { admin } = mount()
  for (const op of ['unlock.begin', 'unlock']) {
    const r = await admin.handle({ op, nonce: nonce(op.padEnd(32, 'y')) })
    assert.equal(r.ok, false)
    assert.match(r.error, /cannot be opened remotely/)
  }
})

/** Y las dos se atienden con el candado echado: son las únicas que solo sirven para eso. */
test('abrir a distancia se atiende con la bóveda CERRADA', async () => {
  const abierto = []
  const { admin } = mount({
    isLocked: () => true,
    unlockDesk: {
      begin: async () => ({ salt: 'x', N: 16384, r: 8, p: 1, len: 32, ek: 'EK' }),
      open: async ({ nonce }) => { abierto.push(nonce); return { ok: true, result: { ok: true, locked: false } } }
    }
  })
  const r1 = await admin.handle({ op: 'unlock.begin', nonce: nonce('a'.repeat(32)) })
  assert.equal(r1.ok, true)
  assert.equal(r1.result.ek, 'EK', 'la efímera sale de la bóveda, no del que pregunta')

  const r2 = await admin.handle({ op: 'unlock', enc: {}, nonce: nonce('b'.repeat(32)) })
  assert.equal(r2.ok, true)
  assert.equal(abierto.length, 1)

  // Y lo que NO se atiende cerrada sigue sin atenderse.
  const r3 = await admin.handle({ op: 'revoke', certNonce: 'n-1', nonce: nonce('c'.repeat(32)) })
  assert.equal(r3.code, 'vault-locked')
})

test('expulsar avisa a todos los miembros', async () => {
  const { admin, notices } = mount()

  await admin.handle({ op: 'revoke', certNonce: 'n-42', nonce: nonce('f') })

  assert.deepEqual(notices.map(([ev]) => ev), ['revoked'])
  assert.equal(notices[0][1].by, 'AD01-AD01', 'el aviso dice QUIÉN lo hizo')
  assert.equal(notices[0][1].certNonce, 'n-42')
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

  await admin.handle({ op: 'revoke', certNonce: 'n-7', nonce: nonce('i') })
  const rev = audits.find(([op]) => op === 'admin.revoke')
  assert.equal(rev[1].by, 'AD01-AD01', 'queda escrito qué dispositivo lo pidió')
})

// --------------------------- variables de entorno ---------------------------

test('sin mostrador de variables, la consola lo dice en vez de fingir que guardó', async () => {
  const { admin } = mount()
  for (const op of ['vars', 'var.set']) {
    const r = await admin.handle({ op, ns: 'proxy', key: 'PORT', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce(op.padEnd(32, 'z')) })
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
  const noTarget = await admin.handle({ op: 'var.set', key: 'PORT', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce('1') })
  assert.match(noTarget.error, /exactly one target/)
  const twoTargets = await admin.handle({ op: 'var.set', ns: 'proxy', pub: 'PUB', key: 'PORT', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce('2') })
  assert.match(twoTargets.error, /exactly one target/)

  // Un valor en claro no se acepta: no es algo que se pueda «arreglar» guardándolo igual.
  // Desde 2026-09-02 solo hay UNA forma: el sobre ya hecho (`sealed`), que la bóveda no
  // abre. El `enc` —que sellaba al perfil y obligaba a la bóveda a descifrar— se quitó
  // entero: dejarlo «por si acaso» habría dejado abierto el agujero que cerró.
  const inClear = await admin.handle({ op: 'var.set', ns: 'proxy', key: 'PORT', value: '8443', nonce: nonce('3') })
  assert.match(inClear.error, /already sealed/)

  const noKey = await admin.handle({ op: 'var.set', ns: 'proxy', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce('4') })
  assert.match(noKey.error, /needs a key/)

  assert.deepEqual(vars.calls, [], 'nada de eso llegó a la bóveda')
})

test('poner valor llega al cajón que toca, con su visibilidad, y se AVISA a todos', async () => {
  const vars = fakeVars()
  const { admin, notices, audits } = mount({ vars })

  const enScope = await admin.handle({ op: 'var.set', ns: 'proxy', key: 'PUBLIC_URL', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, public: true, nonce: nonce('5') })
  assert.equal(enScope.ok, true)
  assert.deepEqual(
    { ns: vars.calls[0][1].ns, pub: vars.calls[0][1].pub, key: vars.calls[0][1].key, public: vars.calls[0][1].public },
    { ns: 'proxy', pub: null, key: 'PUBLIC_URL', public: true }
  )

  await admin.handle({ op: 'var.set', pub: 'PUB-DEL-PROXY', key: 'PORT', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce('6') })
  const toDevice = vars.calls[1][1]
  assert.equal(toDevice.ns, null)
  assert.equal(toDevice.pub, 'PUB-DEL-PROXY')
  assert.equal(toDevice.public, undefined, 'sin decir nada, la bóveda conserva la visibilidad')

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

/**
 * EL CANDADO ES DE LA CONSOLA, Y ESTO ES LA CONSOLA.
 *
 * Faltaba: `admin.pair` y `admin.approve` pasaban con el perfil cerrado, y aprobar firma
 * un certificado de 30 días con la maestra. O sea que cerrar el perfil frenaba
 * `dotrino-vault pair` en la máquina y no frenaba lo mismo por la red.
 */
test('con el perfil CERRADO no se puede QUITAR: eso reescribe el acta', async () => {
  const { admin, desk, audits } = mount({ isLocked: () => true, vars: fakeVars() })

  const casos = [
    { op: 'revoke', sub: 'DPUB' },
    { op: 'revoke', certNonce: 'n-9' }
  ]
  for (const [i, c] of casos.entries()) {
    const r = await admin.handle({ ...c, nonce: nonce(String(i)) })
    assert.equal(r.ok, false, c.op)
    assert.equal(r.code, 'vault-locked', `${c.op} tiene que decirlo por código, no solo por texto`)
  }
  assert.deepEqual(desk.calls, [], 'no se tocó el mostrador ni una vez')
  assert.equal(audits.filter(([op, i]) => op === 'rejected' && i.reason === 'locked').length, casos.length)
})



/**
 * El rechazo por candado va ANTES de marcar el nonce: quien reintente después de abrir la
 * bóveda no tiene por qué inventarse otro. Si se quemara aquí, abrir el perfil no
 * arreglaría el reintento y el error diría «nonce ya usado», que no es lo que pasó.
 */
/**
 * Cerrada se sigue MIRANDO: la bitácora y los nombres de las variables. Lo que no se hace
 * es cambiar nada. (Antes había aquí un `status` que solo servía para que la consola
 * dijera «tu bóveda está cerrada»; el dueño lo quitó: esa frase no pinta nada en una
 * pantalla administrativa, así que la operación tampoco.)
 */
/**
 * CERRADA SÍ SE CONFIGURA, y esto es lo que se entendió mal al principio.
 *
 * Guardar una variable NO necesita la maestra: sellar un valor usa las llaves PÚBLICAS de
 * quien va a leerlo. Meterlo en el mismo saco que revocar dejaba la consola sin poder hacer
 * su trabajo de todos los días con el perfil cerrado — y el perfil se cierra SOLO a los 5
 * minutos, así que era casi siempre.
 */
test('cerrada se mira Y se configura; lo que no se puede es quitar', async () => {
  const vars = fakeVars()
  const { admin } = mount({ isLocked: () => true, vars })
  assert.equal((await admin.handle({ op: 'audit', nonce: nonce('q') })).ok, true)
  assert.equal((await admin.handle({ op: 'vars', nonce: nonce('r') })).ok, true)

  const g = await admin.handle({ op: 'var.set', ns: 'aws', key: 'AWS_REGION', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } }, nonce: nonce('u') })
  assert.equal(g.ok, true, 'guardar una variable con el candado echado TIENE que funcionar')
  assert.equal(vars.calls.at(-1)[0], 'set', 'y llega al mostrador de verdad, no se finge')

  const m = await admin.handle({ op: 'var.setMany', ns: 'aws', items: [{ key: 'K', sealed: { e: { iv: 'IV', ct: 'CT' }, wraps: { '#recovery': 'w' }, author: { pub: 'A', sig: 's', ts: 1 } } }], nonce: nonce('v') })
  assert.equal(m.ok, false, 'este mostrador de mentira no sabe `setMany`…')
  assert.match(m.error, /several variables at once/, '…y lo dice por eso, no por el candado')
})

test('el candado no quema el nonce', async () => {
  let cerrada = true
  const { admin, desk } = mount({ isLocked: () => cerrada })
  const msg = { op: 'revoke', certNonce: 'n-3', nonce: nonce('t') }

  assert.equal((await admin.handle({ ...msg })).code, 'vault-locked')
  cerrada = false
  const r = await admin.handle({ ...msg })
  assert.equal(r.ok, true, 'el MISMO mensaje vale una vez abierta')
  assert.equal(desk.calls.filter(([c]) => c === 'revoke').length, 1)
})

/**
 * LO QUE LA CONSOLA LLAMA TIENE QUE EXISTIR.
 *
 * `var.recipients` estaba documentada en `buildSealedVar`, la consola la llamaba en cada
 * guardado… y no existía en ninguno de los dos lados. Resultado: crear una variable desde
 * la consola remota contestaba «admin: invalid operation» — desde que el sellado se movió
 * allí, o sea desde el 2026-09-02.
 *
 * El fallo fue que tres cosas que deben decir lo mismo se escribieron por separado: lo que
 * la consola pide, lo que el módulo enruta, y lo que la bóveda ofrece. Esto las ata.
 */
test('todas las operaciones que la consola usa están permitidas y enrutadas', async () => {
  const fs = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const raiz = fileURLToPath(new URL('..', import.meta.url))

  const consola = fs.readFileSync(raiz + 'web/src/Console.vue', 'utf8')
  const pedidas = [...consola.matchAll(/vaultAdmin\(\s*'([a-z.]+)'/g)].map((m) => m[1])
  assert.ok(pedidas.length, 'algo tiene que pedir la consola')

  const admin = fs.readFileSync(raiz + 'lib/src/admin.js', 'utf8')
  for (const op of new Set(pedidas)) {
    assert.ok(admin.includes(`'${op}'`), `la consola pide «${op}» y el módulo no la conoce`)
  }
})

/**
 * Y lo que el módulo enruta, la bóveda lo tiene que ofrecer. Es el otro extremo del mismo
 * hueco: enrutar una operación hacia un método que no existe da un TypeError, no un «no».
 */
test('el mostrador de la bóveda ofrece lo que el módulo le va a pedir', async () => {
  const fs = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const raiz = fileURLToPath(new URL('..', import.meta.url))
  const vault = fs.readFileSync(raiz + 'src/vault.js', 'utf8')
  for (const metodo of ['list', 'set', 'setMany', 'recipients']) {
    assert.match(vault, new RegExp('async ' + metodo + ' \\('),
      `el mostrador de variables no ofrece «${metodo}»`)
  }
})

/**
 * QUIÉN FIRMA EL SOBRE TIENE QUE EXISTIR DE VERDAD.
 *
 * `myMembership()` contesta si estás en el acta y con qué permisos —`inProfile`, `caps`,
 * `id`— y NO trae la pública. La consola leía `me.pub` de ahí para el autor, así que iba
 * `undefined` y guardar una variable moría en «author needs { publickey, sign }». Es el
 * mismo hueco que `var.recipients`, un escalón más abajo: la consola daba por hecha la
 * forma de una respuesta que nadie comprobaba.
 *
 * No se puede montar el navegador aquí, así que se ata lo que sí es estable: de dónde saca
 * la consola la llave, y que ese método la devuelva.
 */
test('el autor del sobre saca su llave de donde la hay', async () => {
  const fs = await import('node:fs')
  const { fileURLToPath } = await import('node:url')
  const raiz = fileURLToPath(new URL('..', import.meta.url))
  const consola = fs.readFileSync(raiz + 'web/src/Console.vue', 'utf8')

  const m = /const author = \{ publickey: (\w+)\.(\w+),/.exec(consola)
  assert.ok(m, 'la consola tiene que armar un autor con su pública')
  const [, variable, campo] = m

  // De qué llamada sale esa variable.
  const orig = new RegExp('const ' + variable + ' = await id\\.value\\.(\\w+)\\(').exec(consola)
  assert.ok(orig, '«' + variable + '» tiene que venir del iframe de identidad')
  const metodo = orig[1]

  // Y que ese método devuelva ese campo. `getMe` entrega el perfil, que lleva `publickey`;
  // `myMembership` entrega la pertenencia, que no.
  assert.equal(metodo, 'getMe', 'la pública del aparato la da getMe, no la pertenencia')
  assert.equal(campo, 'publickey', 'y el campo se llama publickey')
})
