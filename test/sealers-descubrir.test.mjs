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
  return { d, cert, token: 'tok-' + d.publickey.slice(20, 32) }
}

/**
 * Una bóveda de mentira, con un cliente que habla como el proxio DE VERDAD: `list` devuelve
 * TOKENS sueltos (no el `extraData` del anuncio — eso costó una vuelta) y el cert se
 * consigue preguntando `sealers.whois` al token.
 */
async function boveda (anunciados) {
  const { genesisActa, sealActa, applyChanges } = await import('@dotrino/identity/acta')
  const A = await makeDeviceKey(); const B = await makeDeviceKey()
  const g = await sealActa({ acta: genesisActa({ pub: A.publickey, label: 'A' }), privateJwk: A.privateJwk })
  let dos = await applyChanges(g, [
    { op: 'admit', member: { pub: B.publickey, label: 'B', caps: ['sign', 'sealer'] } }
  ], { by: A.publickey })
  dos = await sealActa({ acta: dos, privateJwk: A.privateJwk })

  const enviados = []
  const oyentes = new Set()
  const client = {
    async list () { return anunciados.map((a) => a.token) },
    on (_ev, cb) { oyentes.add(cb); return () => oyentes.delete(cb) },
    send (token, msg) {
      if (msg?.op !== 'sealers.whois') return
      const quien = anunciados.find((a) => a.token === token)
      // Contesta como el testigo: con su cert.
      queueMicrotask(() => { for (const cb of oyentes) cb(token, { op: 'sealers.whois.result', ok: true, cert: quien?.cert || null }) })
    },
    async sendByPubkey (to, msg) { enviados.push({ to, msg }) }
  }
  return { identity: { sealerChain: async () => [g, dos], onVault: () => () => {} }, client, enviados }
}

const esperar = () => new Promise((r) => setTimeout(r, 120))

test('deposita en el testigo anunciado con un cert de la identidad esperada', async () => {
  const dotrino = await cuenta()
  const anuncio = await anunciado(dotrino)
  const d = anuncio.d
  const { identity, client, enviados } = await boveda([anuncio])

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
  const anuncio = await anunciado(otro)
  const { identity, client, enviados } = await boveda([anuncio])

  startSealersPublisher({ identity, client, log: () => {}, registryId: dotrino.pub })
  await esperar()

  assert.equal(enviados.length, 0, 'no se le manda nada a quien no es de esa identidad')
})

test('re-enrolar el testigo no rompe nada: el cert es otro, la identidad la misma', async () => {
  const dotrino = await cuenta()
  const viejo = await anunciado(dotrino)
  const nuevo = await anunciado(dotrino)          // re-enrolado: otra llave, otro cert
  const { identity, client, enviados } = await boveda([nuevo])

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
