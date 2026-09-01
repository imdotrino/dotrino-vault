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

/**
 * EL TESTIGO DE DOTRINO, como constante y no como variable de entorno (dueño, 2026-08-31:
 * «¿DOTRINO_SEALERS es una variable?»).
 *
 * No es un secreto ni configuración de la máquina: es una dirección pública, y a dónde va
 * una cadena es propiedad de la IDENTIDAD, no del servidor donde corra su bóveda. Dejarlo
 * en el entorno se saltaba justo la garantía del `chainUrl` del génesis —que nadie pueda
 * redirigirte a su rama— porque lo decidía quien tuviera el servidor.
 *
 * Que venga por defecto no arriesga nada: el eslabón es público, así que depositarlo en el
 * testigo equivocado no filtra nada — simplemente no sirve de nada. La variable se queda
 * como escape para desarrollo, no como la forma normal de decirlo.
 */
export const DOTRINO_REGISTRY = "{\"key_ops\":[\"verify\"],\"ext\":true,\"kty\":\"EC\",\"x\":\"X09h_5ufwjABrXIY3WI99LLP8hSe8QMYK0P3ue4vyf0\",\"y\":\"nmq93S4_0YaV91V5ean6Db-R-ZjqIXPKDadTLBc8SfU\",\"crv\":\"P-256\"}"

export const DEFAULT_REGISTRY = process.env.DOTRINO_SEALERS || DOTRINO_REGISTRY

export function startSealersPublisher ({ identity, client, log = console.log, registry = DEFAULT_REGISTRY } = {}) {
  if (!registry) return () => {}

  let ultima = null

  let avisadoDeOtroTestigo = false

  async function publicar (motivo) {
    let actas
    try { actas = await identity.sealerChain?.() } catch (_) { return }
    if (!Array.isArray(actas)) return

    // SI LA CUENTA DECLARÓ SU PROPIO TESTIGO, no se deposita en el de Dotrino. No es que
    // hacerlo filtre algo —el eslabón es público— sino que el `chainUrl` del génesis es la
    // forma que tiene una cuenta de decir dónde vive su cadena, y decidir por ella sería
    // exactamente lo que ese campo existe para impedir. Se dice una vez y se calla.
    const genesis = actas[0]
    if (genesis?.chainUrl && registry === DOTRINO_REGISTRY) {
      if (!avisadoDeOtroTestigo) {
        avisadoDeOtroTestigo = true
        log(`[sealers] this account names its own registry (${genesis.chainUrl}): not depositing into Dotrino's`)
      }
      return
    }
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
