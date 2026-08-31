/**
 * sealers.js — depositar la cadena de selladores en el registro público.
 *
 * POR QUÉ ESTO EXISTE. Un acta que alguien guardó el año pasado no puede responder la única
 * pregunta que importa al leer una firma vieja: *la llave que firmó esto, ¿sigue pudiendo
 * sellar?* Si a una bóveda le quitaron el permiso, quien tenga el acta vieja no se entera
 * nunca — y seguiría creyéndole. El registro es el sitio donde mirar.
 *
 * QUÉ SE MANDA: los ESLABONES (`sealerLinkOf`), nunca las actas. Y un eslabón no es un acta
 * recortada: es un documento propio de ocho campos, firmado aparte y metido DENTRO del acta
 * antes de firmarla (identity >= 0.72). Costó una vuelta descubrirlo — la primera cadena que
 * llegó al registro se fue con los `label` y los `cn` de cada aparato, porque «un eslabón»
 * era un acta entera. Un acta lleva el inventario de tu casa: no se publica, ni recortada.
 *
 * POR QUÉ SIN SELLAR, y no es un descuido (§4.1 pide sellar los mensajes dirigidos): lo que
 * viaja aquí va a acabar en un repo PÚBLICO, que es su propósito. Es el mismo caso que los
 * canales `publish`/`list` del proxio, exentos por la misma razón: no hay nada que ocultar.
 * Y no filtra de más — quién lo manda ya lo sabe el proxio por el `identify`. Sellarlo,
 * además, obligaría a conocer la llave de cifrado del testigo, y depositar tiene que poder
 * hacerlo cualquiera sin pedirle nada a nadie.
 *
 * Va por `sendByPubkey` y no por `send`: al testigo se le conoce por su pubkey, y así lo
 * depositado entra en la cola de 24 h del proxio si estuviera caído.
 *
 * CUÁNDO: al arrancar y después de cada acta. Publicar de más no cuesta nada (el registro
 * contesta «ya estaba») y así no hay que llevar la cuenta de qué se depositó — un estado
 * que se desincroniza en cuanto se restaura un disco.
 */
import * as Acta from '@dotrino/identity/acta'

export const OP = 'sealers.publish'

/** El testigo de Dotrino. Se puede apuntar a otro: el registro no es un privilegio. */
export const DEFAULT_REGISTRY = process.env.DOTRINO_SEALERS || ''

export function startSealersPublisher ({ identity, client, log = console.log, registry = DEFAULT_REGISTRY } = {}) {
  if (!registry) return () => {}

  let ultima = null

  async function publicar (motivo) {
    let actas
    try { actas = await identity.sealerChain?.() } catch (_) { return }
    if (!Array.isArray(actas)) return
    // De cada acta sale su eslabón, y las que no cambiaron el sellador no dan ninguno.
    const chain = actas.map((a) => Acta.sealerLinkOf(a)).filter(Boolean)
    // Una cuenta de una sola bóveda no tiene nada que refrescar: su conjunto de selladores
    // no puede cambiar. El registro la rechazaría, así que ni se molesta en mandarla.
    // Una cuenta anterior a identity 0.72 tampoco tiene eslabones, y es el mismo caso: no
    // aparece en el registro hasta que selle un acta nueva.
    if (chain.length < 2) return

    const cabeza = chain[chain.length - 1]?.seq
    if (cabeza === ultima) return
    try {
      await client.sendByPubkey(registry, { op: OP, chain })
      ultima = cabeza
      log(`[sealers] chain up to #${cabeza} deposited (${motivo})`)
    } catch (e) {
      // Que no se pueda depositar no rompe nada de lo que la bóveda hace: el registro es
      // una comodidad para terceros, no una dependencia. Se reintenta en la próxima acta.
      log('[sealers] could not deposit the chain:', e.message)
    }
  }

  publicar('startup').catch(() => {})
  const off = identity.onVault?.((e) => { if (e?.phase === 'acta') publicar(`record #${e.seq}`).catch(() => {}) })
  return () => { try { off?.() } catch (_) {} }
}

export default { startSealersPublisher, OP, DEFAULT_REGISTRY }
