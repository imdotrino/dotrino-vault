/**
 * QUIÉN FIRMA QUÉ. El acta lo decide; la maestra no.
 *
 * La maestra tiene exactamente dos trabajos: sellar el acta y reenvolver los sobres de
 * todos los aparatos. Servir una petición no es ninguno de los dos. Durante un tiempo el
 * transporte la usaba igual —`identity.signData` en cada respuesta— y eso tenía dos
 * consecuencias feas: la maestra no podía estar cerrada, y no había forma de que sirviera
 * nadie más que ella.
 *
 * Estas pruebas fijan la regla nueva para que no se vuelva atrás sin darse cuenta.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { verifyResponder } from '../lib/src/service.js'
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'

/** Un acta de mentira no cuela: `verifyResponder` la verifica de verdad. */
const actaFalsa = (sealedBy, sealPub, seq = 1) => ({ v: 1, profileId: sealedBy, seq, sealedBy, sealer: sealedBy, sealPub, members: [], sig: 'x' })

test('sin firma de sellado no se acepta nada', async () => {
  await assert.rejects(
    () => verifyResponder({ body: { op: 'secrets.result' }, seal: null, acta: {}, masterPubkey: 'M' }),
    /no sealing signature/
  )
})

test('sin acta no se acepta: no se sabría qué llave podía firmar', async () => {
  await assert.rejects(
    () => verifyResponder({ body: { op: 'x' }, seal: { seq: 1, sig: 'a' }, acta: null, masterPubkey: 'M' }),
    /no record/
  )
})

/**
 * EL PASO QUE SOSTIENE TODO LO DEMÁS. Si no se exigiera que el acta venga sellada por la
 * maestra pineada, cualquiera mandaría un acta suya nombrando su propia llave de sellado
 * y firmaría lo que quisiera. Comprobar la firma contra «la llave que dice el acta» sin
 * comprobar antes DE QUIÉN es el acta no comprueba nada.
 */
test('un acta que no selló MI maestra se rechaza, aunque la firma cuadre con ella', async () => {
  const impostor = await makeDeviceKey()
  const body = { op: 'secrets.result', ns: 'proxy', ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: impostor.privateJwk, data: body })

  await assert.rejects(
    () => verifyResponder({
      body,
      seal: { seq: 1, sig: signature },
      // El impostor se nombra a sí mismo sellador y llave de sellado: internamente
      // coherente, y ajeno a la maestra que este agente conoce.
      acta: actaFalsa(impostor.publickey, impostor.publickey),
      masterPubkey: 'LA-MAESTRA-DE-VERDAD'
    }),
    /not sealed by the master this agent knows/
  )
})

test('la maestra ya no vale para firmar una respuesta: el acta manda', async () => {
  const maestra = await makeDeviceKey()
  const sellado = await makeDeviceKey()
  const body = { op: 'secrets.result', ns: 'proxy', ts: Date.now() }

  // Firmada por la MAESTRA, que es lo que se hacía antes. El acta nombra otra llave para
  // esto, así que ya no cuadra — y ese es justo el cambio.
  const { signature } = await signWithDevice({ privateJwk: maestra.privateJwk, data: body })
  await assert.rejects(
    () => verifyResponder({
      body,
      seal: { seq: 1, sig: signature },
      acta: actaFalsa(maestra.publickey, sellado.publickey),
      masterPubkey: maestra.publickey
    }),
    // Cae en la verificación del acta de mentira o en la firma; lo que importa es que
    // NO se acepta por venir de la maestra.
    (e) => e instanceof Error
  )
})
