/**
 * E2E de las DOS puntas juntas: un agente real (`@dotrino/remote-agent`, el que corre
 * en tu VPS para `terminal` e `ia`) contra la bóveda de un DISPOSITIVO real
 * (`lib/src/index.js`, lo que corre dentro del iframe de `id.dotrino.com`).
 *
 * Lo que se prueba es el ciclo que hasta ahora no existía: **el agente pide la
 * renovación de su certificado y la bóveda del navegador se la da**. Antes ninguna de
 * las dos puntas hacía su parte —la bóveda no atendía `vault.renew` y el agente no lo
 * pedía—, así que una máquina enrolada contra un dispositivo se moría sola a los 30
 * días y había que re-emparejarla a mano.
 *
 * El único mentiroso acá es el transporte: un bus en memoria que enruta por token y
 * por pubkey como el proxy. Todo lo demás es el código de producción de los dos
 * paquetes, con firmas y verificación de cadena de verdad.
 *
 * (El ENROLAMIENTO en sí no se repite acá: lo cubre `enroll.test.mjs` contra el mismo
 * `createEnrollDesk` que usan las dos bóvedas.)
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { makeDeviceKey, signDelegationWith } from '@dotrino/identity/capabilities'
import { startDeviceVault } from '../lib/src/index.js'
import { startRemoteAgent } from '@dotrino/remote-agent/agent'

const DAY = 24 * 60 * 60 * 1000

/** Identidad P del dispositivo-bóveda: firma de verdad (ECDSA P-256). */
async function deviceIdentity () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const iss = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey))
  const issued = []
  const revoked = []
  // ACTA de mentira con la forma que importa: quién es miembro, qué puede y su `seq`. Hace
  // falta porque el papel ya no se juzga solo — lleva el `seq` del acta con el que se emitió
  // y todos los mostradores cruzan el cert con lo que el acta dice HOY.
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

/**
 * Bus en memoria con la semántica del proxy: cada punta tiene un token (su dirección)
 * y una pubkey (su nombre). `send` va por token, `sendByPubkey` por nombre.
 */
function makeBus () {
  const byToken = new Map()
  const byPubkey = new Map()
  const deliver = (client, from, obj) => {
    // Asíncrono a propósito: el proxy nunca entrega en la misma vuelta del event loop.
    queueMicrotask(() => { for (const fn of client._h) fn(from, obj) })
  }
  function endpoint (token) {
    const c = {
      token,
      url: 'wss://bus.invalid',
      _h: [],
      on (ev, fn) {
        if (ev !== 'message') return () => {}
        c._h.push(fn)
        return () => { const i = c._h.indexOf(fn); if (i >= 0) c._h.splice(i, 1) }
      },
      async identify ({ data } = {}) { if (data?.publickey) byPubkey.set(data.publickey, c); return { ok: true } },
      send (to, obj) { const t = byToken.get(to); if (t) deliver(t, token, obj) },
      sendByPubkey (pub, obj) { const t = byPubkey.get(pub); if (t) deliver(t, token, obj) },
      async requestPairingCode () { return { code: 'ABC123' } },
      close () {}
    }
    byToken.set(token, c)
    return c
  }
  return { endpoint, byPubkey }
}

/** Una máquina ya enrolada: llave propia + cert `D ← P` firmado por la bóveda. */
/**
 * Una máquina ya enrolada: llave propia, sitio en el ACTA y papel firmado por la bóveda.
 *
 * El papel ya no lleva vencimiento: lleva el `seq` del acta con el que se emitió. Lo que la
 * máquina puede HOY lo dice el acta, y por eso hace falta admitirla — un cert suelto sin
 * miembro detrás no autoriza nada.
 */
async function enrolledLink (identity, { label = 'ia-agent', caps = ['sign'] } = {}) {
  const device = await makeDeviceKey({ label })
  await identity.admitMember({ pub: device.publickey, label, caps })
  const { cert } = await identity.signDelegation(device.publickey, ['vault:sign'], { label })
  const acta = (await identity.profileActa()).acta
  return { device, cert, acta, actaSeq: acta.seq, iss: identity.iss, proxy: 'wss://bus.invalid', label, at: Date.now() }
}

test('E2E: el agente renueva su cert contra la bóveda de un dispositivo', async () => {
  const identity = await deviceIdentity()
  const bus = makeBus()

  // La bóveda del navegador, atendiendo por el bus.
  const vault = await startDeviceVault(identity, { client: bus.endpoint('tok-vault') })

  // El agente: enrolado, y el dueño le acaba de cambiar los permisos en el acta. ESO es lo
  // que dispara la renovación ahora — no el calendario.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-e2e-'))
  const link = await enrolledLink(identity)
  const viejoSeq = link.cert.seq
  await identity.setCaps(link.device.publickey, ['sign', 'read'])
  link.actaSeq = (await identity.profileActa()).acta.seq
  fs.writeFileSync(path.join(dir, 'link.json'), JSON.stringify(link, null, 2))

  const agent = await startRemoteAgent({ dir, quiet: true, client: bus.endpoint('tok-agent') })

  // El agente pide la renovación en su primer tic; la bóveda la firma.
  await new Promise((r) => setTimeout(r, 400))

  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'link.json'), 'utf8'))
  assert.ok(saved.cert.seq > viejoSeq, 'el papel guardado se ata al acta nueva, no a la vieja')
  assert.equal(saved.cert.sub, link.device.publickey, 'sigue siendo el cert de ESTA máquina')
  assert.equal(saved.cert.iss, identity.iss, 'y lo firma la misma bóveda')
  assert.notEqual(saved.cert.nonce, link.cert.nonce, 'es un cert nuevo, no el mismo')

  // La bóveda lo ve como una máquina suya, con su label.
  const machines = await vault.listMachines()
  assert.equal(machines.length, 1)
  assert.equal(machines[0].label, 'ia-agent')

  agent.close(); vault.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('E2E: a un cert con vida de sobra NO se le pide renovación', async () => {
  const identity = await deviceIdentity()
  const bus = makeBus()
  const vault = await startDeviceVault(identity, { client: bus.endpoint('tok-vault2') })

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-e2e-'))
  const link = await enrolledLink(identity, { ttlMs: 30 * DAY })
  fs.writeFileSync(path.join(dir, 'link.json'), JSON.stringify(link, null, 2))

  const agent = await startRemoteAgent({ dir, quiet: true, client: bus.endpoint('tok-agent2') })
  await new Promise((r) => setTimeout(r, 400))

  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'link.json'), 'utf8'))
  assert.equal(saved.cert.nonce, link.cert.nonce, 'el cert no se toca: renovar cada tic sería firmar por deporte')
  // Solo los certs de ESTA máquina: la bóveda emite además su self-cert `P ← P`.
  const forAgent = identity.issued.filter((x) => x.sub === link.device.publickey)
  assert.equal(forAgent.length, 1, 'la bóveda no firmó nada de más')

  agent.close(); vault.close()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('E2E: a una máquina REVOCADA la bóveda no le renueva nada', async () => {
  const identity = await deviceIdentity()
  const bus = makeBus()
  const vault = await startDeviceVault(identity, { client: bus.endpoint('tok-vault3') })

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-e2e-'))
  const link = await enrolledLink(identity, { ttlMs: 3 * DAY })
  fs.writeFileSync(path.join(dir, 'link.json'), JSON.stringify(link, null, 2))
  await identity.revokeDelegation(link.cert.nonce)

  const agent = await startRemoteAgent({ dir, quiet: true, client: bus.endpoint('tok-agent3') })
  await new Promise((r) => setTimeout(r, 400))

  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'link.json'), 'utf8'))
  assert.equal(saved.cert.nonce, link.cert.nonce, 'sin cert nuevo: revocar tiene que ser definitivo')
  const forAgent = identity.issued.filter((x) => x.sub === link.device.publickey)
  assert.equal(forAgent.length, 1, 'la bóveda no le firmó un cert nuevo a una máquina revocada')

  agent.close(); vault.close()
  fs.rmSync(dir, { recursive: true, force: true })
})
