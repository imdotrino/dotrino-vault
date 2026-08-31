/**
 * sealers.js — depositar la cadena de selladores en el registro público.
 *
 * POR QUÉ ESTO EXISTE. Un acta que alguien guardó el año pasado no puede responder la única
 * pregunta que importa al leer una firma vieja: *la llave que firmó esto, ¿sigue pudiendo
 * sellar?* Si a una bóveda le quitaron el permiso, quien tenga el acta vieja no se entera
 * nunca — y seguiría creyéndole. El registro es el sitio donde mirar.
 *
 * QUÉ SE MANDA: solo los eslabones donde CAMBIA quién sella, nunca las actas. Un acta lleva
 * los aparatos de una persona con sus nombres y cuándo entró cada uno; eso no se publica.
 *
 * POR QUÉ SIN SELLAR, y no es un descuido (§4.1 pide sellar los mensajes dirigidos): lo que
 * viaja aquí va a acabar en un repo PÚBLICO, que es su propósito. Es el mismo caso que los
 * canales `publish`/`list` del proxio, exentos por la misma razón: no hay nada que ocultar.
 * Y no filtra de más — quién lo manda ya lo sabe el proxio por el `identify`.
 *
 * CUÁNDO: al arrancar y después de cada acta. Publicar de más no cuesta nada (el registro
 * contesta «ya estaba») y así no hay que llevar la cuenta de qué se depositó — un estado
 * que se desincroniza en cuanto se restaura un disco.
 */
export const OP = 'sealers.publish'

/** El testigo de Dotrino. Se puede apuntar a otro: el registro no es un privilegio. */
export const DEFAULT_REGISTRY = process.env.DOTRINO_SEALERS || ''

export function startSealersPublisher ({ identity, client, log = console.log, registry = DEFAULT_REGISTRY } = {}) {
  if (!registry) return () => {}

  let ultima = null

  async function publicar (motivo) {
    let chain
    try { chain = await identity.sealerChain?.() } catch (_) { return }
    // Una cuenta de una sola bóveda no tiene nada que refrescar: su conjunto de selladores
    // no puede cambiar. El registro la rechazaría, así que ni se molesta en mandarla.
    if (!Array.isArray(chain) || chain.filter((a) => a?.sealerChanged).length < 2) return

    const cabeza = chain[chain.length - 1]?.seq
    if (cabeza === ultima) return
    try {
      client.send(registry, { op: OP, chain })
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
