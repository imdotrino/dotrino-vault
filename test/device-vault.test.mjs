/**
 * «Este dispositivo es bóveda» (`lib/src/index.js`, el paquete `@dotrino/vault`).
 *
 * Lo que se prueba es el ENRUTADO: el dispositivo atendía solo `vault.enroll` y
 * `vault.devices`, así que una máquina enrolada contra él caducaba a los 30 días sin
 * poder renovar, y el QR corto (que pide la llave con un `vault.hello`) no tenía quién
 * contestara. El núcleo de enrolamiento ya estaba probado en `enroll.test.mjs`; acá se
 * comprueba que la bóveda del navegador RESPONDE a esos mensajes, con las mismas reglas
 * que el daemon: cert vigente, no revocado y `ts` fresco.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeDeviceKey, signWithDevice, signDelegationWith, verifyDelegation, verifyDeviceSig } from '@dotrino/identity/capabilities'
import { startDeviceVault } from '../lib/src/index.js'
import { MSG } from '../lib/src/protocol.js'

/** Identidad P mínima que firma de verdad (misma forma que la del vault real). */
async function fakeIdentity () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const iss = JSON.stringify(publicJwk)
  const issued = []
  const revoked = []
  // ACTA de mentira, pero con la forma que importa: quién es miembro, qué puede y su `seq`.
  // Hace falta porque el papel ya no se juzga solo —lleva el `seq` del acta con el que se
  // emitió— y todos los mostradores cruzan el cert con lo que el acta dice HOY.
  const acta = {
    v: 5, profileId: iss, sealedBy: iss, seq: 1,
    members: [{ pub: iss, label: 'esta bóveda', caps: ['sign', 'read', 'store', 'sealer'] }],
    renounced: []
  }
  return {
    me: { publickey: iss, encryptionPubkey: null },
    iss,
    issued,
    revoked,
    acta,
    async profileActa () { return { acta, isMaster: true } },
    async admitMember ({ pub, label = '', cn = null, caps = [] }) {
      acta.members.push({ pub, label, ...(cn ? { cn } : {}), caps })
      acta.seq++
      return { ok: true, seq: acta.seq }
    },
    async setCaps (pub, caps) {
      const m = acta.members.find((x) => x.pub === pub)
      if (m) m.caps = caps
      acta.seq++
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
    async listDelegations () { return { issued, revoked } },
    async revokeDelegation (nonce) { revoked.push({ nonce }); return { ok: true, nonce } }
  }
}

/** Transporte de mentira: acumula lo enviado y deja disparar mensajes entrantes. */
function fakeClient () {
  const sent = []
  const handlers = {}
  return {
    sent,
    url: 'wss://test.invalid',
    token: 'tok-vault',
    on (ev, fn) { (handlers[ev] ||= []).push(fn) },
    emit (ev, ...a) { for (const fn of handlers[ev] || []) fn(...a) },
    send (to, obj) { sent.push({ to, ...obj }) },
    sendByPubkey (pub, obj) { sent.push({ pub, ...obj }) },
    async identify () { return { ok: true } },
    async requestPairingCode () { return { code: 'ABC123' } },
    close () {}
  }
}

/** Levanta la bóveda del dispositivo con el transporte de mentira. */
async function mount () {
  const identity = await fakeIdentity()
  const client = fakeClient()
  const vault = await startDeviceVault(identity, { client })
  client.sent.length = 0   // fuera el identify del arranque
  return { identity, client, vault }
}

/** Enrola una máquina «a mano» (el flujo con código ya está probado en enroll.test). */
/**
 * Una máquina enrolada de verdad: papel Y sitio en el acta.
 *
 * Antes bastaba con emitirle el certificado. Ya no, y es el cambio de fondo: el papel dice
 * que una selladora la avaló alguna vez; lo que puede HOY lo dice el acta, y todos los
 * mostradores cruzan las dos cosas. Un cert suelto sin miembro detrás no autoriza nada — que
 * es exactamente lo que se quería.
 */
async function enrolledMachine (identity, { label = 'agente', caps = ['sign'] } = {}) {
  const device = await makeDeviceKey({ label })
  await identity.admitMember({ pub: device.publickey, label, caps })
  const { cert } = await identity.signDelegation(device.publickey, ['vault:sign'], { label })
  return { device, cert }
}

/** Petición firmada por la máquina, como la manda `@dotrino/identity`. */
async function signedByDevice (device, cert, data) {
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  return { data, signature, cert }
}

test('RENEW: una máquina con cert vigente obtiene uno fresco sin aprobación', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)

  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: Date.now() })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  const out = client.sent.at(-1)
  assert.equal(out.type, 'vault.renewed', 'la bóveda del dispositivo tiene que renovar, no ignorar')
  // Se juzga con el acta que la bóveda manda junto al papel: es lo que sustituye a
  // «lo firmó la maestra», y sin ella no se puede comprobar quién lo firmó.
  assert.ok(out.acta, 'el acta viaja con el papel')
  const v = await verifyDelegation({
    cert: out.cert, expectedSub: device.publickey, expectedScope: 'vault:sign',
    actaSeq: out.acta.seq, sealers: out.acta.members.filter((m) => m.caps.includes('sealer')).map((m) => m.pub)
  })
  assert.equal(v.ok, true, v.reason)
  // Ya no hay ventana que extender: el papel no vence. Lo que cambia es el ACTA a la que se
  // ata, y que es otro papel — el anterior queda retirado.
  assert.ok(out.cert.seq >= cert.seq, 'el papel nuevo se ata a un acta que no es más vieja')
  assert.notEqual(out.cert.nonce, cert.nonce)
  assert.equal(identity.issued.at(-1).label, 'agente', 'conserva el label del cert original')
  vault.close()
})

test('RENEW: un cert REVOCADO no se renueva (ahí toca re-emparejar)', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)
  await identity.revokeDelegation(cert.nonce)

  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: Date.now() })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  assert.equal(client.sent.at(-1).type, 'vault.error')
  assert.match(client.sent.at(-1).error, /unauthorized/)
  vault.close()
})

test('RENEW: una petición vieja se rechaza por `ts` (anti-replay)', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)

  const stale = Date.now() - 10 * 60 * 1000
  const p = await signedByDevice(device, cert, { op: 'renew', publickey: device.publickey, ts: stale })
  client.emit('message', 'tok-dev', { type: 'vault.renew', ...p })
  await new Promise((r) => setTimeout(r, 60))

  assert.equal(client.sent.at(-1).type, 'vault.error')
  assert.match(client.sent.at(-1).error, /stale/)
  vault.close()
})

test('HELLO: el QR corto obtiene la llave, y fuera de un emparejamiento no hay respuesta', async () => {
  const { identity, client, vault } = await mount()

  client.emit('message', 'tok-dev', { type: 'vault.hello', sn: 'inventado' })
  await new Promise((r) => setTimeout(r, 40))
  assert.equal(client.sent.at(-1).type, 'vault.error', 'sin sesión abierta no se contesta quién eres')

  const { qr } = await vault.startPairing({ label: 'cel' })
  assert.ok(qr.sn, 'el QR corto trae el nonce de sesión')
  client.emit('message', 'tok-dev', { type: 'vault.hello', sn: qr.sn })
  await new Promise((r) => setTimeout(r, 40))

  const ok = client.sent.at(-1)
  assert.equal(ok.type, 'vault.hello.ok')
  assert.equal(ok.body.iss, identity.iss)
  assert.equal(ok.body.sn, qr.sn, 'la respuesta queda atada a ESTA sesión')
  vault.close()
})

// --- PARIDAD con el daemon ----------------------------------------------------
//
// El vault de dispositivo se quedó atrás: atendía enrolar, renovar y listar, pero no
// FIRMAR — que es para lo que un aparato se enrola. Un aparato contra un
// dispositivo-bóveda hacía el emparejamiento entero y luego no podía hacer nada.
//
// Este test compara los dos routers leyendo el código, para que la próxima vez que el
// daemon aprenda un mensaje nuevo salte aquí en vez de descubrirse usándolo.

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const raiz = join(dirname(fileURLToPath(import.meta.url)), '..')
const mensajesDe = (archivo) => new Set(
  [...readFileSync(join(raiz, archivo), 'utf8').matchAll(/(?:payload|p)\.type === MSG\.([A-Z_]+)/g)]
    .map(m => m[1]))

test('paridad: el dispositivo-bóveda atiende lo mismo que el daemon', () => {
  const daemon = mensajesDe('src/vault.js')
  const dispositivo = mensajesDe('lib/src/index.js')

  // Lo que el daemon hace y aquí no tendría sentido, con su motivo. Cualquier otra
  // diferencia es una carencia, no una decisión.
  const soloDaemon = new Set([
    // Cajones de secretos de SERVICIOS: un navegador no reparte credenciales de
    // producción a daemons; eso vive en la máquina del dueño.
    'SECRETS',
    // Consola remota de administración: se concede a mano y su sitio es el PC.
    'ADMIN',
    // Re-envolver la llave de contenido tras rotar: lo dispara el daemon al migrar.
    'REWRAP_OK',
    // Renunciar a permisos propios: lo pide un agente headless al arrancar.
    'RENOUNCE',
    // El aviso de OTRA BÓVEDA de la misma cuenta, con el acta nueva dentro (multivault).
    // Es una decisión, no una carencia: `startDeviceVault` corre DENTRO de la identidad
    // (`vault/core.js`), que ya es la dueña de `adoptActa` y ya recibe actas por sus
    // propios caminos —al renovar el cert y al adoptar—. El daemon necesita el gancho
    // explícito porque su identidad vive detrás de un RPC y nada más se las da.
    'ADMIN_EVENT',
  ])

  const faltan = [...daemon].filter(m => !dispositivo.has(m) && !soloDaemon.has(m))
  assert.deepEqual(faltan, [], `el dispositivo-bóveda no atiende: ${faltan.join(', ')}`)

  // Y lo esencial, dicho aparte para que se lea en el fallo.
  for (const m of ['SIGN', 'GET', 'STORE', 'CHECK', 'ENROLL', 'RENEW', 'DEVICES']) {
    assert.ok(dispositivo.has(m), `falta ${m}: sin eso el aparato enrolado no puede usarlo`)
  }
})

test('SIGN: una máquina enrolada consigue una firma, y VERIFICA', async () => {
  const { identity, client, vault } = await mount()
  const { device, cert } = await enrolledMachine(identity)

  const payload = { op: 'identify', publickey: device.publickey, ts: Date.now() }
  // `publickey` en el data va porque `verifyChain` lo exige: es cómo sabe QUÉ aparato
  // firmó, y sin él responde `no-device-pubkey`.
  const p = await signedByDevice(device, cert, {
    op: 'sign', publickey: device.publickey, payload, ts: Date.now(),
  })
  client.emit('message', 'from-x', { type: MSG.SIGN, ...p })
  await new Promise(r => setTimeout(r, 60))

  const resp = client.sent.find(x => x.type === MSG.SIGNED)
  assert.ok(resp, 'la bóveda no contestó a un SIGN legítimo')
  assert.equal(resp.device, device.publickey)

  // Y la firma tiene que valer de verdad contra la identidad de la bóveda, no solo venir.
  const ok = await verifyDeviceSig({
    publickey: resp.publickey,
    data: payload,
    signature: resp.signature,
  })
  assert.equal(ok, true, 'la firma no verifica contra la pubkey que devolvió')
})

test('SIGN: sin cert, con cert de otro scope o con ts viejo, NO se firma', async () => {
  const { identity, client, vault } = await mount()

  // 1. Sin cert.
  client.emit('message', 'x', { type: MSG.SIGN, data: { op: 'sign', payload: { a: 1 }, ts: Date.now() } })
  // 2. Con un cert que no sirve para firmar.
  const otro = await makeDeviceKey({ label: 'solo-lee' })
  const { cert: certLee } = await identity.signDelegation(otro.publickey, ['vault:read'], { ttlMs: 60000 })
  client.emit('message', 'x', { type: MSG.SIGN, ...(await signedByDevice(otro, certLee, { op: 'sign', publickey: otro.publickey, payload: { a: 1 }, ts: Date.now() })) })
  // 3. Con un ts fuera de la ventana (repetición de un mensaje viejo).
  const { device, cert } = await enrolledMachine(identity)
  client.emit('message', 'x', { type: MSG.SIGN, ...(await signedByDevice(device, cert, { op: 'sign', publickey: device.publickey, payload: { a: 1 }, ts: Date.now() - 30 * 60_000 })) })

  await new Promise(r => setTimeout(r, 80))
  assert.equal(client.sent.filter(x => x.type === MSG.SIGNED).length, 0, 'firmó algo que no debía')
  assert.equal(client.sent.filter(x => x.type === MSG.ERROR).length, 3, 'no rechazó los tres')
})

test('CHECK: un aparato pregunta si sigue dentro, y se le contesta', async () => {
  const { identity, client } = await mount()
  const device = await makeDeviceKey({ label: 'preguntón' })

  const data = { op: 'check', publickey: device.publickey, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  client.emit('message', 'x', { type: MSG.CHECK, data, signature })
  await new Promise(r => setTimeout(r, 60))

  const resp = client.sent.find(x => x.type === MSG.CHECKED)
  assert.ok(resp, 'no contestó al CHECK')
  // La identidad de prueba no tiene acta, así que la respuesta correcta es «no estás».
  assert.equal(resp.in, false)
})
