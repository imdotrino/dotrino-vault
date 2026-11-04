/**
 * UN AGENTE QUE NO CONOCE A LA SELLADORA LA APRENDE DE LA CADENA (2026-11-04).
 *
 * El caso real: el servicio `aws-glassnote` conocía el acta #57 y no tenía selladoras
 * guardadas. La cuenta sumó una bóveda alojada (NubeLambda) y la #77 la selló ella. El agente
 * la rechazaba —«not sealed by a vault this agent knows»— y como solo aprende selladoras de
 * actas que acepta, se quedaba trabado para siempre.
 *
 * Ahora pide la cadena de selladoras y la comprueba desde la maestra que conoce. Estas
 * pruebas fijan que eso arregla el caso y que no abre la puerta a una cuenta ajena.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyResponder, sealedByChain } from '../lib/src/service.js'
import { genesisActa, sealActa, applyChanges } from '@dotrino/identity/acta'
import { signWithDevice, makeDeviceEncKey } from '@dotrino/identity/capabilities'

const key = async () => {
  const p = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', p.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', p.privateKey)
  }
}
const encPub = async () => (await makeDeviceEncKey()).encPublickey
const sign = async (k, data) => (await signWithDevice({ privateJwk: k.privateJwk, data })).signature
const step = async (acta, changes, who) =>
  sealActa({ acta: await applyChanges(acta, changes, { by: who.pub }), privateJwk: who.privateJwk })

/**
 * #1 génesis (PC) · #2 el PC admite a la nube como selladora · #3 el PC renombra (lo último
 * que vio el agente) · #4 la nube renombra · #5 la nube renombra otra vez.
 */
async function account () {
  const pc = await key(); const cloud = await key(); const phone = await key()
  const sPc = await key(); const sCloud = await key()
  const a1 = await sealActa({ acta: genesisActa({ pub: pc.pub, sealPub: sPc.pub, encPub: await encPub() }), privateJwk: pc.privateJwk })
  const a2 = await step(a1, [
    { op: 'admit', member: { pub: cloud.pub, caps: ['sealer', 'sign'], label: 'cloud', encPub: await encPub(), sealPub: sCloud.pub } },
    { op: 'admit', member: { pub: phone.pub, caps: ['sign'], label: 'phone', encPub: await encPub() } }
  ], pc)
  const a3 = await step(a2, [{ op: 'label', pub: phone.pub, label: 'Pixel' }], pc)
  const a4 = await step(a3, [{ op: 'label', pub: phone.pub, label: 'iPhone' }], cloud)
  const a5 = await step(a4, [{ op: 'label', pub: phone.pub, label: 'iPad' }], cloud)
  return { pc, cloud, sCloud, a1, a2, a3, a4, a5 }
}

const body = { op: 'secrets.result', ns: 'demo', ts: Date.now() }
const sealOf = async (acta, sKey, vault) => ({ seq: acta.seq, sig: await sign(sKey, body), vault: vault.pub })

test('sin cadena, un acta de una selladora desconocida se rechaza con código', async () => {
  const { pc, cloud, sCloud, a3, a4 } = await account()
  const seal = await sealOf(a4, sCloud, cloud)
  await assert.rejects(
    verifyResponder({ body, seal, acta: a4, masterPubkey: pc.pub, knownSeq: a3.seq }),
    (e) => e.code === 'unknown-sealer')
})

test('el caso de aws-glassnote: conoce una acta vieja, sin selladoras, y la cadena le enseña la nueva', async () => {
  const { pc, cloud, sCloud, a1, a2, a3, a4 } = await account()
  const seal = await sealOf(a4, sCloud, cloud)
  let asked = 0
  // La bóveda manda [génesis, cambios de sellador, vigente]: aquí la vigente es la #4.
  const askSealerChain = async () => { asked++; return [a1, a2, a4] }
  await verifyResponder({ body, seal, acta: a4, masterPubkey: pc.pub, knownSeq: a3.seq, askSealerChain })
  assert.equal(asked, 1)
})

test('la cadena puede ir por delante del acta de la respuesta', async () => {
  const { pc, cloud, sCloud, a1, a2, a3, a4, a5 } = await account()
  const seal = await sealOf(a4, sCloud, cloud)
  await verifyResponder({ body, seal, acta: a4, masterPubkey: pc.pub, knownSeq: a3.seq, askSealerChain: async () => [a1, a2, a5] })
})

test('una cuenta ajena que nombra a mi maestra como selladora no vale', async () => {
  const { pc } = await account()
  const intruder = await key(); const sIntruder = await key()
  const g = await sealActa({ acta: genesisActa({ pub: intruder.pub, sealPub: sIntruder.pub, encPub: await encPub() }), privateJwk: intruder.privateJwk })
  // Se puede admitir la PÚBLICA de cualquiera como selladora: no hace falta su privada.
  const fake = await step(g, [{ op: 'admit', member: { pub: pc.pub, caps: ['sealer'], label: 'victim', encPub: await encPub() } }], intruder)
  const seal = { seq: fake.seq, sig: await sign(sIntruder, body), vault: intruder.pub }
  await assert.rejects(
    verifyResponder({ body, seal, acta: fake, masterPubkey: pc.pub, knownSeq: null, askSealerChain: async () => [g, fake] }),
    (e) => e.code === 'unknown-sealer' && /not-my-account/.test(e.message))
})

test('una cadena que trae otra acta con el mismo número no vale', async () => {
  const { pc, cloud, sCloud, a1, a2, a3, a4 } = await account()
  const other = await step(a3, [{ op: 'label', pub: cloud.pub, label: 'otra' }], cloud)
  const seal = await sealOf(a4, sCloud, cloud)
  assert.equal(other.seq, a4.seq)
  assert.deepEqual(await sealedByChain({ chain: [a1, a2, other], acta: a4, masterPubkey: pc.pub }), { ok: false, reason: 'other-record' })
  await assert.rejects(
    verifyResponder({ body, seal, acta: a4, masterPubkey: pc.pub, knownSeq: a3.seq, askSealerChain: async () => [a1, a2, other] }),
    (e) => e.code === 'unknown-sealer')
})

test('una selladora que el eslabón anterior no autorizaba no vale', async () => {
  const { pc, a1, a2 } = await account()
  const stranger = await key()
  // Un acta de la cuenta, firmada por quien nunca fue selladora (el `sealedBy` lo dice ella).
  const forged = await sealActa({ acta: { ...(await applyChanges(a2, [{ op: 'label', pub: pc.pub, label: 'x' }], { by: pc.pub })), sealedBy: stranger.pub }, privateJwk: stranger.privateJwk })
  const r = await sealedByChain({ chain: [a1, a2], acta: forged, masterPubkey: pc.pub })
  assert.equal(r.ok, false)
})

test('si la cadena no se puede pedir, se dice por qué', async () => {
  const { pc, cloud, sCloud, a3, a4 } = await account()
  const seal = await sealOf(a4, sCloud, cloud)
  await assert.rejects(
    verifyResponder({ body, seal, acta: a4, masterPubkey: pc.pub, knownSeq: a3.seq, askSealerChain: async () => { throw new Error('timeout waiting for the vault reply') } }),
    (e) => e.code === 'unknown-sealer' && /could not be fetched: timeout/.test(e.message))
})
