/**
 * LAS DOS SON MAESTRA (`docs/replicas.md` §11.5), visto desde quien recibe.
 *
 * Cada bóveda de la cuenta tiene su llave de sellado en el acta, y la que sella nombra la suya y
 * conserva la de sus hermanas. Un agente tiene que poder creerle a cualquiera de ellas:
 *
 *   · un acta sellada por la OTRA bóveda vale si el acta que el agente ya aceptó le dejaba sellar
 *     (`knownSealers`); una bóveda que nunca vio, no;
 *   · lo que firma una bóveda con SU llave (`seal.vault`) se comprueba contra la llave que el
 *     acta nombra para ella, aunque la última acta la haya sellado otra.
 *
 * Y el sellado delegado: un servicio envuelve la llave de SU cajón para los de su cajón y para
 * TODAS las bóvedas de la cuenta, y para nadie más (`rewrapTarget`).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyResponder, rewrapTarget } from '../lib/src/service.js'
import { genesisActa, sealActa, applyChanges, sealersOf } from '@dotrino/identity/acta'
import { signWithDevice, makeDeviceEncKey } from '@dotrino/identity/capabilities'

const llave = async () => {
  const p = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', p.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', p.privateKey)
  }
}
const encPub = async () => (await makeDeviceEncKey()).encPublickey
const firmaDe = async (k, data) => (await signWithDevice({ privateJwk: k.privateJwk, data })).signature
const paso = async (acta, changes, who, opts = {}) =>
  sealActa({ acta: await applyChanges(acta, changes, { by: who.pub, ...opts }), privateJwk: who.privateJwk })

/** El PC (la del perfil) y la alojada, cada una con su llave de sellado, y un servicio `demo`. */
async function cuenta () {
  const pc = await llave(); const nube = await llave(); const svc = await llave(); const tel = await llave()
  const sPc = await llave(); const sNube = await llave()
  let acta = await sealActa({ acta: genesisActa({ pub: pc.pub, sealPub: sPc.pub, encPub: await encPub() }), privateJwk: pc.privateJwk })
  // El PC admite a la alojada y le PRESELLA su llave.
  acta = await paso(acta, [
    { op: 'admit', member: { pub: nube.pub, caps: ['sealer', 'sign'], label: 'nube', encPub: await encPub(), sealPub: sNube.pub } },
    { op: 'admit', member: { pub: svc.pub, cn: 'demo', caps: [], label: 'service:demo', encPub: await encPub() } },
    { op: 'admit', member: { pub: tel.pub, caps: ['sign'], label: 'teléfono', encPub: await encPub() } }
  ], pc)
  return { pc, nube, svc, tel, sPc, sNube, acta }
}

const cuerpo = { op: 'secrets.result', ns: 'demo', ts: Date.now() }

test('la alojada firma con SU llave aunque la última acta la sellara el PC', async () => {
  const { pc, nube, sNube, acta } = await cuenta()
  assert.equal(acta.sealedBy, pc.pub)
  const seal = { seq: acta.seq, sig: await firmaDe(sNube, cuerpo), vault: nube.pub }
  await verifyResponder({ body: cuerpo, seal, acta, masterPubkey: pc.pub, knownSeq: acta.seq, knownSealers: sealersOf(acta) })
})

test('la firma de una bóveda con la llave de OTRA no vale', async () => {
  const { pc, nube, sPc, acta } = await cuenta()
  const seal = { seq: acta.seq, sig: await firmaDe(sPc, cuerpo), vault: nube.pub }
  await assert.rejects(verifyResponder({ body: cuerpo, seal, acta, masterPubkey: pc.pub, knownSeq: acta.seq }), /does not check out/)
})

test('un acta sellada por la alojada vale si el acta ya aceptada la dejaba sellar', async () => {
  const { pc, nube, sNube, tel, acta } = await cuenta()
  const conocidas = sealersOf(acta)
  const nueva = await paso(acta, [{ op: 'label', pub: tel.pub, label: 'iPhone' }], nube)
  const seal = { seq: nueva.seq, sig: await firmaDe(sNube, cuerpo), vault: nube.pub }
  await verifyResponder({ body: cuerpo, seal, acta: nueva, masterPubkey: pc.pub, knownSeq: acta.seq, knownSealers: conocidas })
  // Sin saber quién sella (un agente de antes, o uno que solo conoce al PC), no vale.
  await assert.rejects(verifyResponder({ body: cuerpo, seal, acta: nueva, masterPubkey: pc.pub, knownSeq: acta.seq }), /not sealed by a vault this agent knows/)
})

test('una bóveda que el agente nunca vio no vale, aunque se nombre selladora a sí misma', async () => {
  const { pc, acta } = await cuenta()
  const intrusa = await llave(); const sIntrusa = await llave()
  const falsa = await sealActa({ acta: genesisActa({ pub: intrusa.pub, sealPub: sIntrusa.pub }), privateJwk: intrusa.privateJwk })
  const seal = { seq: falsa.seq, sig: await firmaDe(sIntrusa, cuerpo), vault: intrusa.pub }
  await assert.rejects(verifyResponder({ body: cuerpo, seal, acta: falsa, masterPubkey: pc.pub, knownSeq: null, knownSealers: sealersOf(acta) }), /not sealed by a vault this agent knows/)
})

test('sellado delegado: el servicio envuelve su cajón para su cajón y para TODAS las bóvedas', async () => {
  const { pc, nube, svc, tel, acta } = await cuenta()
  assert.equal(rewrapTarget(acta, nube.pub, 'demo').ok, true, 'la alojada')
  assert.equal(rewrapTarget(acta, pc.pub, 'demo').ok, true, 'el PC')
  assert.equal(rewrapTarget(acta, svc.pub, 'demo').ok, true, 'un hermano del cajón')
  assert.equal(rewrapTarget(acta, tel.pub, 'demo').ok, false, 'un aparato cualquiera, no')
  assert.equal(rewrapTarget(acta, svc.pub, 'otro').ok, false, 'un servicio de otro cajón, no')
  assert.equal(rewrapTarget(acta, (await llave()).pub, 'demo').ok, false, 'alguien que no está en el acta, no')
})
