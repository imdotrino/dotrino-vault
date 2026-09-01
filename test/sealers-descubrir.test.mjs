/**
 * A QUIÉN LE MANDA LA BÓVEDA SU CADENA.
 *
 * La primera versión llevaba la pubkey del testigo QUEMADA en el código. El dueño lo paró:
 * «¿no me puedes quemar un device en el código?». Y tenía razón — es el mismo fallo que ya
 * costó caro con el `nodeId` del proxio: re-enrolar el aparato cambia su pubkey y todo lo
 * que la tuviera apuntada se queda hablando con una dirección muerta.
 *
 * Lo que se lleva en el código es la IDENTIDAD, que no cambia nunca. El aparato se descubre
 * en un canal, y solo vale si trae un cert emitido por esa identidad — si no, cualquiera se
 * anuncia ahí y se traga los depósitos EN SILENCIO, que es peor que un error.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeDeviceKey, signDelegationWith } from '@dotrino/identity/capabilities'
import { startSealersPublisher, CANAL } from '../src/sealers.js'

const SCOPE = ['vault:secrets:sealers']

/** Una cuenta que puede emitir certs (la maestra firma con una CryptoKey de verdad). */
async function cuenta () {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
  return { priv: par.privateKey, pub }
}

/** Un aparato anunciado en el canal, con cert emitido por `dueño`. */
async function anunciado (dueño) {
  const d = await makeDeviceKey()
  const iat = Date.now()
  const cert = await signDelegationWith(dueño.priv, dueño.pub, {
    sub: d.publickey, scope: SCOPE, iat, exp: iat + 3600_000, nonce: crypto.randomUUID()
  })
  return { d, entrada: { data: { role: 'sealers', repo: 'x/y', cert } } }
}

/** Una bóveda de mentira: dos actas encadenadas, con eslabón, y un cliente que apunta. */
async function boveda (canal) {
  const { genesisActa, sealActa, applyChanges } = await import('@dotrino/identity/acta')
  const A = await makeDeviceKey(); const B = await makeDeviceKey()
  const g = await sealActa({ acta: genesisActa({ pub: A.publickey, label: 'A' }), privateJwk: A.privateJwk })
  let dos = await applyChanges(g, [
    { op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }
  ], { by: A.publickey })
  dos = await sealActa({ acta: dos, privateJwk: A.privateJwk })

  const enviados = []
  const client = {
    async list () { return canal },
    async sendByPubkey (to, msg) { enviados.push({ to, msg }) }
  }
  return { identity: { sealerChain: async () => [g, dos], onVault: () => () => {} }, client, enviados }
}

const esperar = () => new Promise((r) => setTimeout(r, 30))

test('deposita en el testigo anunciado con un cert de la identidad esperada', async () => {
  const dotrino = await cuenta()
  const { d, entrada } = await anunciado(dotrino)
  const { identity, client, enviados } = await boveda([entrada])

  startSealersPublisher({ identity, client, log: () => {}, registryId: dotrino.pub })
  await esperar()

  assert.equal(enviados.length, 1, 'se depositó')
  assert.equal(enviados[0].to, d.publickey, 'al aparato anunciado, descubierto y no quemado')
  assert.equal(enviados[0].msg.chain.length, 2)
})

test('un impostor en el canal NO se lleva los depósitos', async () => {
  const dotrino = await cuenta()
  const otro = await cuenta()
  // Se anuncia con un cert perfectamente válido… emitido por SU cuenta, no por la nuestra.
  const { entrada } = await anunciado(otro)
  const { identity, client, enviados } = await boveda([entrada])

  startSealersPublisher({ identity, client, log: () => {}, registryId: dotrino.pub })
  await esperar()

  assert.equal(enviados.length, 0, 'no se le manda nada a quien no es de esa identidad')
})

test('re-enrolar el testigo no rompe nada: el cert es otro, la identidad la misma', async () => {
  const dotrino = await cuenta()
  const viejo = await anunciado(dotrino)
  const nuevo = await anunciado(dotrino)          // re-enrolado: otra llave, otro cert
  const { identity, client, enviados } = await boveda([nuevo.entrada])

  startSealersPublisher({ identity, client, log: () => {}, registryId: dotrino.pub })
  await esperar()

  assert.equal(enviados[0]?.to, nuevo.d.publickey)
  assert.notEqual(nuevo.d.publickey, viejo.d.publickey, 'y es un aparato distinto del de antes')
})

test('si no hay testigo anunciado, la cadena se guarda para la próxima', async () => {
  const dotrino = await cuenta()
  const { identity, client, enviados } = await boveda([])

  startSealersPublisher({ identity, client, log: () => {}, registryId: dotrino.pub })
  await esperar()

  assert.equal(enviados.length, 0)
  assert.equal(CANAL, 'dotrino.sealers')
})
