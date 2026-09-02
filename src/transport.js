/**
 * Transporte headless del vault: el cliente OFICIAL `@dotrino/proxy-client`
 * corriendo en Node (mismo patrón que `dotrino-bots/src/core/transport.js`).
 * Hace el `identify` — liga el token efímero de la conexión a una pubkey estable,
 * habilitando el direccionamiento por pubkey (`sendByPubkey`) y la cola offline
 * de 24 h del proxy.
 *
 * QUIÉN FIRMA ESE `identify`, que es lo que cambió: **la llave de comunicación**
 * (`commKey.js`), no la maestra. La maestra sella el acta y reenvuelve sobres, y
 * nada más; si además tuviera que firmar aquí no podría vivir bajo llave, porque
 * esto se firma en cada conexión Y en cada reconexión — una bóveda cerrada no
 * existiría en la red.
 *
 * Lo que ata el token al PERFIL entonces ya no es un certificado sino el ACTA: el
 * proxio comprueba que quien habla sea miembro (`verifyActaMembership`) y ata el
 * token también al `profileId`. Por eso se manda el acta siempre.
 *
 * IMPORTANTE: `me.publickey` puede ser null en el primer arranque (solo se puebla
 * al fijar un nickname), así que la pubkey maestra se obtiene de forma robusta
 * con un `signData` de cortesía si hace falta. El daemon (vault.js) además puebla
 * `me` antes de conectar.
 */
import { installNodeGlobals } from './node-globals.js'

const DEFAULT_PROXY = 'wss://proxy.dotrino.com'

export async function masterPubkeyOf (identity) {
  return identity.me?.publickey || (await identity.signData({ op: 'whoami', ts: Date.now() })).publickey
}

/**
 * Conecta el transporte y lo identifica con la maestra del vault.
 * @param {Object} opts
 * @param {import('@dotrino/identity/node').Identity} opts.identity
 * @param {string} opts.dir   Directorio de persistencia.
 * @param {string} [opts.url] URL del proxy (default wss://proxy.dotrino.com).
 * @returns {Promise<{ client, token:string, identify():Promise<void> }>}
 */
export async function createTransport ({ identity, dir, url = DEFAULT_PROXY, commKey = null, log = () => {} }) {
  installNodeGlobals(dir)
  // Import dinámico DESPUÉS de instalar los globals que el paquete usa.
  // `WebSocketProxyClient` (la clase) y NO el helper `getWebSocketProxyClient`:
  // ese es un SINGLETON de proceso, y con multi-perfil el vault necesita una
  // conexión POR PERFIL (cada maestra se identifica con su propia pubkey ante el
  // proxy). Con el singleton, el segundo perfil reusaba el cliente del primero y
  // su `identify` pisaba al anterior. Sigue siendo el cliente oficial del paquete.
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')

  // WebRTC off: el vault usa el proxy como transporte (RTCPeerConnection no existe
  // en Node). Reconexión prácticamente ilimitada: un daemon de larga duración no
  // debe rendirse tras unos intentos.
  const client = new WebSocketProxyClient({
    url, enableWebRTC: false, autoReconnect: true,
    maxReconnectAttempts: 100000, reconnectDelay: 4000
  })

  await client.connect()

  const identify = async () => {
    if (!client.token) return
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    const comm = commKey?.pub?.() || null
    // ¿Nos nombra el acta? Con `cn` o sin él, lo que el proxio mira es la pertenencia.
    const esMiembro = comm && (record?.members || []).some((m) => m?.pub === comm)

    if (comm && esMiembro) {
      const data = { op: 'identify', publickey: comm, token: client.token, ts: Date.now() }
      const signature = await commKey.sign(data)
      if (signature) {
        await client.identify({ data, signature, acta: record })
        // SE DICE QUE SE IDENTIFICÓ, y con qué llave. Este camino era MUDO: al pasar de la
        // maestra a la llave de comunicación, el único rastro de «estoy alcanzable» que
        // quedaba en el log era el del repliegue. Así que cuando la consola decía «no
        // contesta», no había forma de saber desde aquí si la bóveda estaba atada al proxio
        // o no. Una línea por reconexión es barata; no tenerla cuesta una hora de sondeos.
        log(`[vault] identified on the proxy with the communication key · record #${record?.seq ?? '?'}`)
        return
      }
    }

    // REPLIEGUE, y solo para migrar: una bóveda que todavía no ha metido su llave de
    // comunicación en el acta se identifica con la maestra, como siempre. Exige el perfil
    // ABIERTO —la maestra bajo llave no firma— y por eso se dice en voz alta: mientras se
    // esté aquí, cerrar el perfil deja la bóveda sin voz.
    const publickey = await masterPubkeyOf(identity)
    if (!publickey) return
    const data = { op: 'identify', publickey, token: client.token, ts: Date.now() }
    const { signature } = await identity.signData(data)
    log('[vault] identifying with the master key: this vault is not in its own record yet (open the profile once to fix it)')
    await client.identify({ data, signature, acta: record })
  }
  await identify()
  // Re-identificar al reconectar (el token cambia).
  client.on('token', () => { identify().catch(() => {}) })

  return { client, token: client.token, identify }
}
