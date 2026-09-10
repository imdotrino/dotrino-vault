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
export async function createTransport ({ identity, dir, url = DEFAULT_PROXY, commKey = null, log = () => {}, makeClient = null }) {
  installNodeGlobals(dir)
  // Import dinámico DESPUÉS de instalar los globals que el paquete usa.
  // `WebSocketProxyClient` (la clase) y NO el helper `getWebSocketProxyClient`:
  // ese es un SINGLETON de proceso, y con multi-perfil el vault necesita una
  // conexión POR PERFIL (cada maestra se identifica con su propia pubkey ante el
  // proxy). Con el singleton, el segundo perfil reusaba el cliente del primero y
  // su `identify` pisaba al anterior. Sigue siendo el cliente oficial del paquete.
  // `makeClient` es la costura de las PRUEBAS, y existe por una razón concreta: comprobar
  // que un `identify` rechazado no tumba el perfil y se reintenta solo. Sin ella habría que
  // levantar un proxio de verdad para probar el caso que ya costó una tarde. En producción
  // no se pasa nunca y esto es el cliente oficial de siempre.
  const { WebSocketProxyClient } = makeClient ? {} : await import('@dotrino/proxy-client')

  /**
   * EL CANAL DIRECTO, ENCENDIDO Y CON LA PUERTA CERRADA.
   *
   * Encendido porque es el escalón 2 de la regla del transporte (`CLAUDE.md`) y en Node ya
   * hay con qué (`werift`, que el pilar carga solo). Si no lo hubiera, negociar falla y se
   * sigue por el proxio — el escalón 4 siempre está.
   *
   * Y con la puerta cerrada desde el primer día, que es lo que hace defendible encenderlo:
   * **solo se le negocia a quien está en el acta.** Aceptar una señal arranca DTLS, ICE y
   * SCTP, o sea código que parsea red no confiable, dentro del proceso que guarda la
   * maestra. Quien decide si eso corre no puede ser el que llama a la puerta.
   *
   * Reconexión prácticamente ilimitada: un daemon de larga duración no debe rendirse tras
   * unos intentos.
   */
  // La puerta tiene que decidir AL INSTANTE (la señal llega y o se atiende o no), y pedir
  // el acta es asíncrono. Así que se guarda una copia y se refresca donde ya se refresca
  // todo: en `identify`, que es lo que corre cada vez que el acta cambia o se reconecta.
  let actaVista = null
  // ¿Está esta bóveda ATADA al proxio ahora mismo? Conectado no es identificado: el socket
  // puede estar perfectamente abierto y el sobre rechazado, y entonces nadie la alcanza por
  // su pubkey. Se expone para que `status` lo enseñe en vez de dejarlo a un log del arranque.
  let identificado = false
  const enElActa = (token) => {
    // SIN ACTA NO SE NEGOCIA. No se sabe quién es nadie, y en la duda no se arranca a
    // parsear red no confiable. Se sigue por el proxio, que es el escalón que siempre está.
    if (!actaVista) return false
    return (actaVista.members || []).some((m) => m?.pub === token)
  }
  const client = makeClient ? makeClient({ url, acceptDirectFrom: enElActa }) : new WebSocketProxyClient({
    url, enableWebRTC: true, acceptDirectFrom: enElActa, autoReconnect: true,
    maxReconnectAttempts: 100000, reconnectDelay: 4000
  })

  await client.connect()

  const identify = async () => {
    identificado = false
    if (!client.token) return
    const record = (await identity.profileActa?.().catch(() => null))?.acta || null
    actaVista = record   // la copia que mira la puerta del canal directo
    const comm = commKey?.pub?.() || null
    // ¿Nos nombra el acta? Con `cn` o sin él, lo que el proxio mira es la pertenencia.
    const esMiembro = comm && (record?.members || []).some((m) => m?.pub === comm)

    if (comm && esMiembro) {
      // El sobre lo arma el pilar (`identifyAs`), que le pone el destinatario.
      try {
        await client.identifyAs({ publickey: comm, sign: (d) => commKey.sign(d), acta: record })
        identificado = true
        // SE DICE QUE SE IDENTIFICÓ, y con qué llave. Este camino era MUDO: al pasar de la
        // maestra a la llave de comunicación, el único rastro de «estoy alcanzable» que
        // quedaba en el log era el del repliegue. Así que cuando la consola decía «no
        // contesta», no había forma de saber desde aquí si la bóveda estaba atada al proxio
        // o no. Una línea por reconexión es barata; no tenerla cuesta una hora de sondeos.
        log(`[vault] identified on the proxy with the communication key · record #${record?.seq ?? '?'}`)
        return
      } catch (e) {
        // SOLO «esta llave no firma» cae al camino de abajo, y se distingue por el `code`.
        // Un fallo de red no es eso: tragárselo aquí mandaría a la maestra a firmar por un
        // problema pasajero, que es justo lo que la llave de comunicación vino a evitar.
        if (e?.code !== 'no-signature') throw e
      }
    }

    // REPLIEGUE, y solo para migrar: una bóveda que todavía no ha metido su llave de
    // comunicación en el acta se identifica con la maestra, como siempre. Exige el perfil
    // ABIERTO —la maestra bajo llave no firma— y por eso se dice en voz alta: mientras se
    // esté aquí, cerrar el perfil deja la bóveda sin voz.
    //
    // QUEDARSE SIN VOZ NO ES NO ARRANCAR, y aquí eran lo mismo. Un perfil con la maestra
    // sellada y sin llave de comunicación todavía llegaba hasta este `signData`, que tira
    // `vault locked`; el error subía por `createTransport` hasta `startVault` y **el perfil
    // entero se quedaba sin abrir**. Al dueño le pasó el 2026-09-02: su perfil principal no
    // arrancaba, `unlock` lo marcaba abierto igual y cada petición contestaba «profile is
    // not open», con la TUI vacía y sin un error a la vista.
    //
    // Se dice y se sigue. Sin red se puede vivir hasta que alguien teclee la frase; sin
    // bóveda, no.
    try {
      const publickey = await masterPubkeyOf(identity)
      if (!publickey) return
      log('[vault] identifying with the master key: this vault is not in its own record yet (open the profile once to fix it)')
      await client.identifyAs({ publickey, sign: (d) => identity.signData(d), acta: record })
      identificado = true
    } catch (e) {
      log(`[vault] cannot identify on the proxy yet: ${e.message} — the profile still opens; unlock it once and it gets its own communication key`)
    }
  }
  /**
   * IDENTIFICARSE PUEDE FALLAR, Y ESO NO PUEDE TUMBAR EL PERFIL — NI QUEDARSE ASÍ.
   *
   * Esto era `await identify()` a secas, así que cualquier «no» del proxio subía por
   * `createTransport` hasta `startVault` y el perfil **no se abría en absoluto**: no es que
   * se quedara sin voz, es que cada petición contestaba `profile is not open` y en el
   * `status` el perfil salía sin huella. Y no se reintentaba nunca: `identify` solo vuelve a
   * correr con el evento `token`, o sea al RECONECTAR, y aquí el socket estaba perfectamente
   * conectado — lo que el proxio rechazó fue el sobre.
   *
   * El caso real (2026-09-10): esta máquina arranca con el reloj 35 minutos atrasado (el
   * `systemd-timesyncd` no contactó el servidor de hora hasta media hora después del
   * arranque), el proxio rechaza el `identify` con «ts fuera de la ventana ±5min» y la
   * bóveda se quedaba fuera de la red DESDE EL ARRANQUE HASTA QUE ALGUIEN LA REINICIABA.
   * Con ella fuera no hay a quién timbrar: el teléfono nunca recibía un pedido de
   * aprobación, y desde fuera eso se ve igual que «no hay pedidos».
   *
   * Reintentar con espera creciente lo arregla solo en cuanto el reloj se corrige, y cada
   * intento se dice en voz alta: una bóveda inalcanzable en silencio es el fallo que ya
   * costó un día entero (`CLAUDE.md`, el apagón del 1-2 de septiembre).
   */
  let reintento = null
  let fallos = 0
  const identifyWithRetry = async () => {
    if (reintento) { clearTimeout(reintento); reintento = null }
    try {
      await identify()
      if (fallos) log(`[vault] identified on the proxy after ${fallos + 1} attempt(s)`)
      fallos = 0
    } catch (e) {
      fallos++
      const espera = Math.min(60000, 5000 * fallos)
      log(`[vault] could not identify on the proxy (${e.message}) — retrying in ${Math.round(espera / 1000)}s; until then this vault is unreachable and cannot ring anyone`)
      reintento = setTimeout(() => { reintento = null; identifyWithRetry() }, espera)
      reintento.unref?.()
    }
  }
  await identifyWithRetry()
  // Re-identificar al reconectar (el token cambia).
  client.on('token', () => { fallos = 0; identifyWithRetry() })

  return { client, token: client.token, identify: identifyWithRetry, isIdentified: () => identificado }
}
