/**
 * Núcleo del lado bóveda (`lib/src/enroll.js`): el emparejamiento endurecido, sin red.
 *
 * Lo que de verdad se prueba acá es la regla que antes NO se cumplía: **no se emite un
 * certificado si quien aprueba no tiene el código que muestra el dispositivo**. Antes el
 * vault firmaba igual y la comprobación vivía solo en el cliente honesto, así que un
 * cliente malicioso (que ignora el eco) se quedaba con un cert válido.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  makeDeviceKey, signWithDevice, makePairingCode, commitCode,
  signDelegationWith, verifyDelegation
} from '@dotrino/identity/capabilities'
import { createEnrollDesk } from '../lib/src/enroll.js'

/** Identidad mínima que firma de verdad (cert real, verificable con verifyDelegation). */
async function fakeIdentity () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const iss = JSON.stringify(publicJwk)
  const issued = []
  // Acta de mentira con la forma que importa: el papel lleva su `seq`, y quien verifica
  // necesita saber quién puede sellar en este perfil.
  const acta = {
    v: 5, profileId: iss, sealedBy: iss, seq: 1,
    members: [{ pub: iss, label: 'bóveda', caps: ['sign', 'read', 'store', 'sealer'] }],
    renounced: []
  }
  return {
    iss,
    issued,
    acta,
    async profileActa () { return { acta, isMaster: true } },
    async admitMember ({ pub, label = '', cn = null, caps = [] }) {
      acta.members.push({ pub, label, ...(cn ? { cn } : {}), caps }); acta.seq++
      return { ok: true, seq: acta.seq }
    },
    async signDelegation (sub, scope, { label = '' } = {}) {
      const iat = Date.now()
      const cert = await signDelegationWith(pair.privateKey, iss, {
        sub, scope, iat, seq: acta.seq, nonce: crypto.randomUUID()
      })
      issued.push({ nonce: cert.nonce, sub, scope, iat, seq: cert.seq, label })
      return { cert }
    },
    async signData (data) {
      const bytes = new TextEncoder().encode(JSON.stringify(data))
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, pair.privateKey, bytes)
      return { signature: Buffer.from(new Uint8Array(sig)).toString('base64'), publickey: iss }
    },
    async listDelegations () { return { issued, revoked: [] } },
    async revokeDelegation (nonce) { return { ok: true, nonce } }
  }
}

/** Monta un mostrador con transporte de mentira que solo acumula lo enviado. */
async function mount (opts = {}) {
  const identity = await fakeIdentity()
  const sent = []
  const byPubkey = []
  const desk = createEnrollDesk({
    identity,
    iss: identity.iss,
    proxy: 'wss://test.invalid',
    send: (to, obj) => sent.push({ to, ...obj }),
    sendByPubkey: (pub, obj) => byPubkey.push({ pub, ...obj }),
    ...opts
  })
  return { identity, desk, sent, byPubkey }
}

/** Lo que hace un dispositivo honesto: genera código, manda el compromiso, firma. */
async function deviceEnroll (qr, { label = 'test', ts = Date.now(), code = makePairingCode() } = {}) {
  const device = await makeDeviceKey({ label })
  const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
  const data = { op: 'enroll', dpub: device.publickey, token: qr.token, sn: qr.sn, commit, label, ts }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  return { device, code, payload: { type: 'vault.enroll', data, signature } }
}

test('flujo feliz: con el código correcto se emite un cert válido para ESE dispositivo', async () => {
  const { identity, desk, sent } = await mount()
  const { qr } = await desk.startPairing({ scope: ['vault:sign'], ttlMs: 60000, label: 'cel' })
  const { device, code, payload } = await deviceEnroll(qr)

  await desk.handleEnroll('tok-1', payload)
  assert.equal(sent.at(-1).type, 'vault.enroll.challenge')
  assert.equal(desk.listPending().length, 1)

  const res = await desk.approve(code)
  assert.equal(res.ok, true)

  const enrolled = sent.at(-1)
  assert.equal(enrolled.type, 'vault.enrolled')
  assert.equal(enrolled.to, 'tok-1')
  assert.equal(enrolled.code, code, 'el código se echa de vuelta para que el dispositivo confíe')
  // Se juzga con el acta que viaja junto al papel, que es lo que sustituyó a «lo firmó la
  // maestra»: quien lo emitió tiene que ser SELLADORA de este perfil.
  assert.ok(enrolled.acta, 'el acta viaja con el papel')
  const v = await verifyDelegation({
    cert: enrolled.cert, expectedSub: device.publickey, expectedScope: 'vault:sign',
    actaSeq: enrolled.acta.seq, sealers: enrolled.acta.members.filter((m) => m.caps.includes('sealer')).map((m) => m.pub)
  })
  assert.equal(v.ok, true, v.reason)
  assert.equal(enrolled.cert.iss, identity.iss)
  assert.equal(desk.listPending().length, 0, 'el pendiente se consume al aprobar')
})

test('CÓDIGO EQUIVOCADO: no se emite ningún certificado', async () => {
  const { identity, desk, sent } = await mount()
  const { qr } = await desk.startPairing()
  const { code, payload } = await deviceEnroll(qr)
  await desk.handleEnroll('tok-1', payload)

  const wrong = String((Number(code) + 1) % 1000000).padStart(6, '0')
  await assert.rejects(() => desk.approve(wrong), /does not match/)

  assert.equal(identity.issued.length, 0, 'la maestra NO firmó nada')
  assert.equal(sent.filter((m) => m.type === 'vault.enrolled').length, 0, 'no se envió ningún cert')
  assert.equal(desk.listPending().length, 1, 'el dispositivo sigue esperando: se puede reintentar')

  // …y con el correcto, después del fallo, sí funciona.
  await desk.approve(code)
  assert.equal(identity.issued.length, 1)
})

test('cliente viejo sin compromiso: se rechaza el enrolamiento con un mensaje claro', async () => {
  const { desk, sent } = await mount()
  const { qr } = await desk.startPairing()
  const device = await makeDeviceKey({ label: 'viejo' })
  const data = { op: 'enroll', dpub: device.publickey, token: qr.token, sn: qr.sn, label: 'viejo', ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })

  await desk.handleEnroll('tok-1', { type: 'vault.enroll', data, signature })
  assert.equal(sent.at(-1).type, 'vault.error')
  assert.match(sent.at(-1).error, /old pairing version/)
  assert.equal(desk.listPending().length, 0, 'no queda nada pendiente de aprobar')
})

test('firma de dispositivo inválida: no pasa del ENROLL', async () => {
  const { desk, sent } = await mount()
  const { qr } = await desk.startPairing()
  const { payload } = await deviceEnroll(qr)
  const other = await makeDeviceKey({})
  payload.data.dpub = other.publickey // la firma ya no corresponde a este dpub

  await desk.handleEnroll('tok-1', payload)
  assert.equal(sent.at(-1).type, 'vault.error')
  assert.match(sent.at(-1).error, /invalid device signature/)
  assert.equal(desk.listPending().length, 0)
})

test('replay: un ENROLL con ts viejo se descarta', async () => {
  const { desk, sent } = await mount()
  const { qr } = await desk.startPairing()
  const { payload } = await deviceEnroll(qr, { ts: Date.now() - 10 * 60 * 1000 })

  await desk.handleEnroll('tok-1', payload)
  assert.equal(sent.at(-1).type, 'vault.error')
  assert.match(sent.at(-1).error, /stale request/)
})

test('token/sesión que no son de este emparejamiento', async () => {
  const { desk, sent } = await mount()
  const { qr } = await desk.startPairing()

  const foreign = await deviceEnroll({ ...qr, token: 'otro-token' })
  await desk.handleEnroll('tok-1', foreign.payload)
  assert.match(sent.at(-1).error, /pairing token/)

  const badSn = await deviceEnroll({ ...qr, sn: 'otro-sn' })
  await desk.handleEnroll('tok-1', badSn.payload)
  assert.match(sent.at(-1).error, /invalid session/)
})

test('rechazar: el dispositivo se entera y deja de estar pendiente', async () => {
  const { identity, desk, sent } = await mount()
  const { qr } = await desk.startPairing()
  const { payload } = await deviceEnroll(qr)
  await desk.handleEnroll('tok-1', payload)

  const r = desk.reject(desk.listPending()[0].deviceId)
  assert.equal(r.ok, true)
  assert.equal(sent.at(-1).type, 'vault.error')
  assert.equal(desk.listPending().length, 0)
  assert.equal(identity.issued.length, 0)
})

test('revocar emite un vault.revoked FIRMADO por la maestra, dirigido al dispositivo', async () => {
  const { identity, desk, byPubkey } = await mount()
  const { qr } = await desk.startPairing()
  const { device, code, payload } = await deviceEnroll(qr)
  await desk.handleEnroll('tok-1', payload)
  await desk.approve(code)

  await desk.revoke(identity.issued[0].nonce)
  const rev = byPubkey.at(-1)
  assert.equal(rev.type, 'vault.revoked')
  assert.equal(rev.pub, device.publickey, 'va dirigido al dispositivo revocado')
  assert.equal(rev.body.op, 'revoke')
  assert.equal(rev.body.sub, device.publickey)
  assert.equal(typeof rev.signature, 'string', 'firmado: es la única puerta al autoborrado')
})

test('un solo emparejamiento a la vez: abrir otro invalida el anterior', async () => {
  const { desk, sent } = await mount()
  const { qr: primero } = await desk.startPairing()
  await desk.startPairing() // el dueño reinició el emparejamiento

  const { payload } = await deviceEnroll(primero)
  await desk.handleEnroll('tok-1', payload)
  assert.match(sent.at(-1).error, /pairing token/)
})

/**
 * EL GESTOR DE CONTRASEÑAS entra como cualquier otro aparato, con su permiso puesto.
 *
 * Antes había un código aparte —dos públicas en base64— que se pegaba en la extensión y
 * otro que se pegaba de vuelta en la bóveda. Eso ya no existe: la extensión se empareja
 * con la invitación de siempre y lo que la deja pedir credenciales es la capacidad
 * `passwords` del acta, que sale del scope con el que se emparejó.
 */
test('contraseñas: el scope del emparejamiento se convierte en la capacidad del acta', async () => {
  const admitidos = []
  const { desk, identity } = await mount()
  identity.admitMember = async (m) => { admitidos.push(m); return { ok: true } }
  const { qr } = await desk.startPairing({ scope: ['vault:passwords'], ttlMs: 60000, label: 'gestor' })
  const dev = await deviceEnroll(qr, { label: 'gestor' })
  await desk.handleEnroll('FROM', dev.payload)
  const [pend] = desk.listPending()
  await desk.approve(dev.code, { deviceId: pend.deviceId })

  assert.equal(admitidos.length, 1, 'el aparato no entró en el acta')
  assert.ok(admitidos[0].caps.includes('passwords'),
    'emparejar con --scope contrasenas no concedió el permiso: ' + JSON.stringify(admitidos[0].caps))
})

test('contraseñas: un emparejamiento normal NO concede el permiso', async () => {
  const admitidos = []
  const { desk, identity } = await mount()
  identity.admitMember = async (m) => { admitidos.push(m); return { ok: true } }
  const { qr } = await desk.startPairing({ scope: ['vault:sign', 'vault:read'], ttlMs: 60000, label: 'cel' })
  const dev = await deviceEnroll(qr, { label: 'cel' })
  await desk.handleEnroll('FROM', dev.payload)
  const [pend] = desk.listPending()
  await desk.approve(dev.code, { deviceId: pend.deviceId })

  assert.ok(!admitidos[0].caps.includes('passwords'), 'cualquier aparato podía pedir contraseñas')
})
