/**
 * replica.js — UNA BÓVEDA QUE REPARTE Y NO DECIDE.
 *
 * Diseño: `docs/replicas.md` §8.bis. Es la otra pieza del par, y NO sustituye al
 * multivault: una segunda bóveda tiene maestra y sella; un replicador no tiene maestra y
 * no sella nunca. Las dos se conservan.
 *
 * Qué guarda, y no hay una cuarta cosa:
 *
 *   · su LLAVE DE APARATO y su papel — para ser alcanzable y para firmar lo que contesta;
 *   · el ACTA vigente — pública y firmada, la verifica quien la recibe;
 *   · los SOBRES — que ya vienen cerrados a su destinatario.
 *
 * Por qué se puede poner en una máquina ajena, que es el punto entero: **no puede abrir
 * nada de lo que reparte**. Entra al acta SIN llave de cifrado (`withEncKey: false`), así
 * que no existe camino por el que le llegue un sobre dirigido a él — regla del dueño:
 * «recibirá todos los sobres que se generen, ningún sobre firmado para él». Que lo
 * comprometan cuesta disponibilidad, no confidencialidad.
 *
 * Y lo que NO hace, comprobado y no prometido: no sella actas, no emite certificados, no
 * admite aparatos, no cambia permisos. Si algo de eso le llega, contesta que no.
 */
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { WebSocketProxyClient } from '@dotrino/proxy-client'
import { signWithDevice, verifyDeviceSig, pubkeyId } from '@dotrino/identity/capabilities'
import { verifyActa, memberCan, sealKeyAt } from '@dotrino/identity/acta'
import { MSG } from '../lib/src/protocol.js'
import { seal } from '../lib/src/sealed.js'
import { atRestFor } from './atrest.js'
import { readJson, writeJson } from './paths.js'

export const REPLICA_SCOPE = 'vault:replica'

export const replicaDir = () =>
  process.env.DOTRINO_REPLICA_DIR || path.join(os.homedir(), '.dotrino', 'replica')

const LINK = 'link.json'
const STATE = 'state.json'

/**
 * MEZCLAR DOS VERSIONES DEL MISMO PAQUETE, DATO A DATO.
 *
 * Antes se reemplazaba el paquete entero, y eso pierde datos en un caso concreto: una
 * bóveda restaurada de un respaldo empuja un paquete donde un dato está más atrasado que
 * el que ya tenemos. El `seq` del acta no lo caza —el acta puede ir por delante mientras
 * un dato va por detrás—, así que la comparación tiene que ser POR DATO.
 *
 * Gana la GENERACIÓN más alta, que es la que sube en cada escritura. Un empate se rompe
 * igual en todas partes —gana el `ct` menor— y no es justicia, es determinismo: dos
 * replicadores que reciban lo mismo en distinto orden acaban idénticos.
 *
 * Las envolturas se SUMAN: son de aparatos distintos y ninguna estorba a otra.
 */
export function mergeBundle (viejo, nuevo) {
  if (!viejo) return nuevo
  if (!nuevo) return viejo
  const entries = { ...(viejo.entries || {}) }
  for (const [k, e] of Object.entries(nuevo.entries || {})) {
    const a = entries[k]
    if (!a) { entries[k] = e; continue }
    const ga = a.gen || 0
    const gb = e.gen || 0
    if (gb > ga) entries[k] = e
    else if (gb === ga && String(e.e?.ct ?? e.pubv ?? '') < String(a.e?.ct ?? a.pubv ?? '')) entries[k] = e
  }
  const porGen = new Map()
  for (const w of [...(viejo.wraps || []), ...(nuevo.wraps || [])]) porGen.set(w.gen, w)
  return { ...viejo, ...nuevo, entries, wraps: [...porGen.values()].sort((x, y) => x.gen - y.gen) }
}

/** La clave de un sobre: es POR (cajón, aparato), porque va tallado a quien lo pide. */
export const bundleKey = (ns, devicePub) => `${ns} ${devicePub}`

/** Lo que este replicador sabe de la cuenta: su papel, el acta y los sobres. */
export function openReplicaStore (dir) {
  fs.mkdirSync(dir, { recursive: true })
  const atRest = atRestFor(dir)
  const leer = (f, d) => readJson(path.join(dir, f), d, atRest)
  const escribir = (f, v) => writeJson(path.join(dir, f), v, atRest)

  let link = leer(LINK, null)
  let state = leer(STATE, null) || { seq: 0, acta: null, bundles: {} }

  return {
    get link () { return link },
    get acta () { return state.acta },
    get seq () { return state.seq },
    setLink (v) { link = v; escribir(LINK, v) },
    bundleFor (ns, devicePub) { return state.bundles[bundleKey(ns, devicePub)] || null },
    get bundles () { return Object.keys(state.bundles).length },
    /**
     * SOLO HACIA ADELANTE. Es el mismo freno que el pin del cliente: un empujón con un
     * acta más vieja de la que ya tenemos es un rollback, y aceptarlo convertiría al
     * replicador en el camino para servir un acta donde un aparato revocado sigue dentro.
     * @returns {boolean} si se aplicó (false = venía atrasado y se descartó)
     */
    apply ({ seq, acta, bundles }) {
      if (typeof seq !== 'number' || seq < state.seq) return false
      const mezclados = { ...state.bundles }
      for (const [k, nuevo] of Object.entries(bundles || {})) mezclados[k] = mergeBundle(mezclados[k], nuevo)
      state = { seq, acta: acta || state.acta, bundles: mezclados }
      escribir(STATE, state)
      return true
    }
  }
}

/**
 * Arranca el replicador. No crea ninguna maestra ni ningún perfil: si no está enrolado,
 * lo dice y se para. Estrenar una identidad aquí sería justo lo que no debe existir.
 */
export async function runReplica ({ dir = replicaDir(), proxyUrl, log = console.log } = {}) {
  const store = openReplicaStore(dir)
  const link = store.link
  if (!link?.device?.privateJwk || !link?.cert || !link?.iss) {
    throw Object.assign(
      new Error('this replica is not enrolled yet: run `dotrino-vault replica enroll <invitation>` here first'),
      { code: 'replica-not-enrolled' })
  }
  const url = proxyUrl || link.proxy || process.env.PROXY_URL || 'wss://proxy.dotrino.com'
  const id = (await pubkeyId(link.device.publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')

  const firmar = (data) => signWithDevice({ privateJwk: link.device.privateJwk, data })
  // CONTESTAR es por la CONEXIÓN (`send`) y no por la llave (`sendByPubkey`): `from` es el
  // identificador de quien escribe en el proxio, no su pubkey. Mandar por llave a un `from`
  // no falla — se va a la nada, y quien preguntó se queda esperando el plazo entero.
  // Por llave solo se habla con la BÓVEDA (`link.iss`), que es a quien queremos alcanzar
  // aunque no esté conectada ahora mismo.

  const client = new WebSocketProxyClient({ url })
  await client.connect()
  const data = { op: 'identify', publickey: link.device.publickey, token: client.token, ts: Date.now() }
  await client.identify({ data, signature: (await firmar(data)).signature })
  log(`[replica] ${id} · connected to ${url}`)
  log(`[replica] record #${store.seq}${store.acta ? '' : ' · no record yet: waiting for the vault'}`)

  /**
   * UN EMPUJÓN DE LA BÓVEDA. Va firmado con la llave de sellado que el acta nombra, así
   * que se comprueba de dónde viene antes de guardar nada. Y se comprueba contra el acta
   * QUE VIENE, después de verificar que la selló la maestra que este replicador conoce:
   * fiarse de la que ya tiene impediría para siempre recibir una nueva.
   */
  async function onPush (from, p) {
    const body = p?.body
    if (!body || body.op !== 'replica.push') return
    const acta = body.acta || store.acta
    if (!acta) return log('[replica] a push arrived with no record and none is stored: ignored')
    if (acta.sealedBy !== link.iss) return log('[replica] the pushed record was sealed by another master: ignored')
    if (!(await verifyActa({ acta })).ok) return log('[replica] the pushed record does not verify: ignored')
    const pub = sealKeyAt(acta, p.seal?.seq)
    if (!pub || !(await verifyDeviceSig({ publickey: pub, data: body, signature: p.seal?.sig }))) {
      return log('[replica] the push is not signed by the key the record names: ignored')
    }
    if (!memberCan(acta, link.device.publickey, 'replica')) {
      return log('[replica] the record no longer lets this device serve as a replica: ignored')
    }
    if (!store.apply({ seq: body.seq, acta, bundles: body.bundles })) {
      return log(`[replica] a push arrived with an older record (#${body.seq} < #${store.seq}): refused`)
    }
    log(`[replica] record #${store.seq} · ${Object.keys(body.bundles || {}).length} bundle(s) stored`)
    const ack = { op: 'replica.ack', publickey: link.device.publickey, seq: store.seq, ts: Date.now() }
    client.send(from, { type: MSG.REPLICA_ACK, body: ack, signature: (await firmar(ack)).signature })
  }

  /**
   * UNA PETICIÓN DE CLAVES. Se contesta con lo que hay guardado, cerrado a la efímera de
   * quien pregunta y firmado con NUESTRA llave — que es lo que el cliente acepta cuando el
   * acta nos reconoce `replica` (`verifyResponder` de `@dotrino/vault`).
   *
   * Lo que NO se decide aquí, y es a propósito: si quien pide tiene derecho a ese cajón.
   * Lo dice el sobre, no nosotros — va cerrado a su llave, así que a quien no le toque le
   * llega algo que no puede abrir. Un replicador que decidiera quién lee sería un
   * replicador del que hay que fiarse, y la gracia es que no haga falta.
   */
  async function onSecrets (from, p) {
    const ns = p?.data?.ns
    const ek = p?.data?.ek
    const quien = p?.data?.publickey
    if (typeof ns !== 'string' || !ek || !quien) return
    if (!store.acta) return client.send(from, { type: MSG.ERROR, error: 'replica: no record yet' })
    const b = store.bundleFor(ns, quien)
    if (!b) {
      log(`[replica] asked for "${ns}" and has nothing stored for that device`)
      return client.send(from, {
        type: MSG.ERROR,
        error: `replica: nothing stored for "${ns}" and this device — ask the vault once while it is up`
      })
    }
    const enc = await seal({ ek, payload: { sealed: b, acta: store.acta } })
    const body = { op: 'secrets.result', ns, enc, ts: Date.now() }
    // `by` y no `seq`: no tenemos la llave de sellado y no debemos tenerla. Quien recibe
    // mira el acta, ve que a esta llave le reconoce `replica`, y acepta.
    const { signature } = await firmar(body)
    client.send(from, { type: MSG.SECRETS_RESULT, body, seal: { by: link.device.publickey, sig: signature } })
    log(`[replica] served "${ns}" from record #${store.seq}`)
  }

  /** Todo lo que DECIDE algo se contesta que no, y se dice por qué. */
  const NO_DECIDE = new Set([MSG.ENROLL, MSG.ADMIN, MSG.RENEW, MSG.RENOUNCE, MSG.SIGN, MSG.ACTA_SEALED])

  client.on('message', (from, p) => {
    const t = p?.type
    if (t === MSG.REPLICA_PUSH) return onPush(from, p).catch((e) => log('[replica] push: ' + e.message))
    if (t === MSG.SECRETS) return onSecrets(from, p).catch((e) => log('[replica] secrets: ' + e.message))
    if (NO_DECIDE.has(t)) {
      log(`[replica] refused "${t}": a replica hands things out, it does not decide`)
      return client.send(from, {
        type: MSG.ERROR,
        error: 'replica: this is a replica — it has no master and decides nothing'
      })
    }
  })

  // EL ARRASTRE AL ARRANCAR (`docs/replicas.md` §6). Se dice por dónde vamos en cuanto hay
  // conexión: si la bóveda va por delante, contesta con un empujón. Sin esto, un
  // replicador recién encendido se queda vacío hasta que alguien cambie algo — y el
  // empujón del propio enrolamiento se manda cuando este proceso todavía no existe.
  const saludo = { op: 'replica.ack', publickey: link.device.publickey, seq: store.seq, ts: Date.now() }
  try {
    client.sendByPubkey(link.iss, { type: MSG.REPLICA_ACK, body: saludo, signature: (await firmar(saludo)).signature })
  } catch (e) { log('[replica] could not say hello to the vault: ' + e.message) }

  log('[replica] ready · it hands out what the vault already signed, and nothing else')
  return {
    id,
    publickey: link.device.publickey,
    seq: () => store.seq,
    stop: () => { try { client.close() } catch (_) {} }
  }
}
