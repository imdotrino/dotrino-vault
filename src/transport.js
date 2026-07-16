/**
 * Transporte headless del vault: el cliente OFICIAL `@dotrino/proxy-client`
 * corriendo en Node (mismo patrón que `dotrino-bots/src/core/transport.js`).
 * Hace el `identify` firmado por la maestra del vault — liga el token efímero de
 * la conexión a la pubkey estable, habilitando el direccionamiento por pubkey
 * (`sendByPubkey`) y la cola offline de 24 h del proxy.
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
export async function createTransport ({ identity, dir, url = DEFAULT_PROXY }) {
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
    const publickey = await masterPubkeyOf(identity)
    if (!publickey || !client.token) return
    const data = { op: 'identify', publickey, token: client.token, ts: Date.now() }
    const { signature } = await identity.signData(data)
    await client.identify({ data, signature })
  }
  await identify()
  // Re-identificar al reconectar (el token cambia).
  client.on('token', () => { identify().catch(() => {}) })

  return { client, token: client.token, identify }
}
