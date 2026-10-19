/**
 * UN REPLICADOR PUEDE CONTESTAR, Y SOLO A QUIEN YA CONOCE LA CUENTA.
 *
 * El cliente exigía que la respuesta viniera firmada por la llave de sellado que nombra el
 * acta. Un replicador no la tiene —no tiene maestra—, así que firma con la suya de aparato
 * y lo que la autoriza es que el acta le reconozca `replica`. Los sobres de dentro se
 * siguen comprobando contra la llave de sellado, así que un replicador reparte pero no
 * puede inventarse contenido.
 *
 * Y la condición que cierra el agujero de `replicas.md` §6.1: **sin `maxSeq` pineado no se
 * le cree**. Un replicador atrasado presenta un acta donde un aparato revocado sigue
 * siendo miembro; a quien ya conoce la cuenta lo salva el pin, y a quien llega nuevo no
 * hay con qué compararlo. Mientras no exista el oráculo de frescura, éste es el freno.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyResponder } from '../lib/src/service.js'
import { genesisActa, sealActa, applyChanges } from '@dotrino/identity/acta'
import { signWithDevice } from '@dotrino/identity/capabilities'

const llave = async () => {
  const p = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', p.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', p.privateKey)
  }
}

/** Una cuenta con su bóveda y un replicador dentro. */
async function cuenta () {
  const master = await llave()
  const repl = await llave()
  const otro = await llave()
  const g = genesisActa({ pub: master.pub, sealPub: master.pub })
  const conRepl = await applyChanges(g, [
    { op: 'admit', member: { pub: repl.pub, caps: ['replica'], label: 'replicador' } },
    { op: 'admit', member: { pub: otro.pub, caps: ['sign'], label: 'un teléfono' } }
  ], { by: master.pub })
  const acta = await sealActa({ acta: conRepl, privateJwk: master.privateJwk })
  return { master, repl, otro, acta }
}

const cuerpo = { op: 'secrets.result', ns: 'proxy', ts: Date.now() }
const firmaDe = async (k, data) => (await signWithDevice({ privateJwk: k.privateJwk, data })).signature

test('la bóveda contesta como siempre: firma con la llave que nombra el acta', async () => {
  const { master, acta } = await cuenta()
  const seal = { seq: acta.seq, sig: await firmaDe(master, cuerpo) }
  await verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: acta.seq })
})

test('un replicador contesta si el acta se lo reconoce y ya conocemos la cuenta', async () => {
  const { master, repl, acta } = await cuenta()
  const seal = { by: repl.pub, sig: await firmaDe(repl, cuerpo) }
  await verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: acta.seq })
})

test('a un aparato que NO conoce la cuenta, un replicador no le vale', async () => {
  const { master, repl, acta } = await cuenta()
  const seal = { by: repl.pub, sig: await firmaDe(repl, cuerpo) }
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: null }),
    (e) => e.code === 'replica-unknown-account',
    'sin pin no hay con qué comparar: que conteste la bóveda')
})

test('un miembro SIN el permiso no puede hacer de replicador', async () => {
  const { master, otro, acta } = await cuenta()
  const seal = { by: otro.pub, sig: await firmaDe(otro, cuerpo) }
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: acta.seq }),
    /does not allow to serve as a replica/)
})

test('firma que no cuadra: no vale ni con el permiso puesto', async () => {
  const { master, repl, otro, acta } = await cuenta()
  const seal = { by: repl.pub, sig: await firmaDe(otro, cuerpo) }   // firma OTRO
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: acta.seq }),
    /replica signature does not check out/)
})

/**
 * EL ROLLBACK, que es el ataque concreto: un replicador atrasado sirve el acta de antes de
 * que revocaras a alguien. Se rechaza por el `seq`, y vale para los dos caminos — también
 * para la bóveda, porque un respaldo viejo restaurado hace exactamente lo mismo.
 */
test('un acta más vieja de la que ya vimos se rechaza, venga de quien venga', async () => {
  const { master, repl, acta } = await cuenta()
  const seal = { by: repl.pub, sig: await firmaDe(repl, cuerpo) }
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal, acta, masterPubkey: master.pub, knownSeq: acta.seq + 5 }),
    (e) => e.code === 'stale-record')

  const dela = { seq: acta.seq, sig: await firmaDe(master, cuerpo) }
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal: dela, acta, masterPubkey: master.pub, knownSeq: acta.seq + 5 }),
    (e) => e.code === 'stale-record', 'la bóveda tampoco puede retroceder')
})

test('un acta sellada por OTRA maestra no vale ni con replicador', async () => {
  const { repl, acta } = await cuenta()
  const ajeno = await llave()
  const seal = { by: repl.pub, sig: await firmaDe(repl, cuerpo) }
  await assert.rejects(
    () => verifyResponder({ body: cuerpo, seal, acta, masterPubkey: ajeno.pub, knownSeq: acta.seq }),
    /not sealed by the master this agent knows/)
})
