/**
 * dotrino-vault — núcleo del certificador personal (daemon headless).
 *
 * Custodia la clave MAESTRA del usuario (vía `@dotrino/identity`, que la genera y
 * persiste) y la expone como una CA propia: enrola dispositivos firmándoles un
 * certificado de delegación acotado por scope/exp/revocación, y firma datos a
 * pedido de un dispositivo enrolado SIN que la maestra salga nunca de la máquina.
 *
 * Todo el transporte es el proxy del ecosistema (`@dotrino/proxy-client`) y toda
 * la cripto es la de `@dotrino/identity` (`signDelegation` + `verifyChain`). Este
 * módulo solo orquesta: NO reimplementa firmas, protocolo ni persistencia de
 * identidad.
 */
import { Identity } from '@dotrino/identity/node'
import { verifyChain, pubkeyId } from '@dotrino/identity/capabilities'
import { createTransport, masterPubkeyOf } from './transport.js'
import { openStore } from './store.js'
import { dataDir, ensureDir } from './paths.js'
import { MSG, SCOPE } from './protocol.js'

const PAIRING_TTL_MS = 5 * 60 * 1000 // un token de emparejamiento vale 5 min

function randToken () {
  const b = crypto.getRandomValues(new Uint8Array(16))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/**
 * Arranca el vault: abre/crea la identidad, conecta el transporte y queda
 * atendiendo pedidos de dispositivos por el proxy.
 *
 * @param {Object} [opts]
 * @param {string} [opts.dir]       Dir de datos (default ~/.dotrino/vault).
 * @param {string} [opts.proxyUrl]  URL del proxy.
 * @param {(...a:any)=>void} [opts.log]
 * @returns {Promise<Object>} API local del vault.
 */
export async function startVault ({ dir = dataDir(), proxyUrl, log = console.log } = {}) {
  ensureDir(dir)
  const identity = await Identity.connect({ dir })

  // Primer arranque: `me` es null hasta fijar nickname. Lo poblamos para que el
  // `identify` del transporte tenga la pubkey estable y el vault sea direccionable.
  if (!identity.me?.publickey) await identity.setMyNickname('')

  const store = openStore(dir)
  const master = await masterPubkeyOf(identity)
  const fp = (await pubkeyId(master)).slice(0, 16)

  const { client } = await createTransport({ identity, dir, url: proxyUrl })

  // token de emparejamiento (un uso) -> { exp, scope, ttlMs, label, used }
  const pending = new Map()

  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set(revoked.map((r) => r.nonce))
  }

  const reply = (to, obj) => {
    try { client.send(to, obj) } catch (e) { log('[vault] no se pudo responder:', e.message) }
  }

  async function handleEnroll (from, p) {
    const pend = pending.get(p.token)
    if (!pend || pend.used || Date.now() > pend.exp) {
      return reply(from, { type: MSG.ERROR, error: 'token de emparejamiento inválido o expirado' })
    }
    if (typeof p.dpub !== 'string') return reply(from, { type: MSG.ERROR, error: 'dpub requerido' })
    pend.used = true
    pending.delete(p.token)
    const label = String(p.label || pend.label || '').slice(0, 60)
    const { cert } = await identity.signDelegation(p.dpub, pend.scope, { ttlMs: pend.ttlMs, label })
    log(`[vault] dispositivo enrolado: ${label || '(sin etiqueta)'} · scope ${JSON.stringify(pend.scope)}`)
    reply(from, { type: MSG.ENROLLED, cert, iss: master })
  }

  async function handleSign (from, p) {
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.SIGN, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const toSign = p.data?.payload
    if (toSign == null) return reply(from, { type: MSG.ERROR, error: 'data.payload requerido' })
    // Firma con la MAESTRA, localmente. La privada nunca sale del vault.
    const { signature, publickey } = await identity.signData(toSign)
    reply(from, { type: MSG.SIGNED, signature, publickey, device: chk.device })
  }

  async function handleGet (from, p) {
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.READ, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const id = p.data?.id || 'root'
    reply(from, { type: MSG.DATA, id, node: store.getNode(id) })
  }

  client.on('message', async (from, payload) => {
    if (!payload || typeof payload !== 'object') return
    try {
      if (payload.type === MSG.ENROLL) return await handleEnroll(from, payload)
      if (payload.type === MSG.SIGN) return await handleSign(from, payload)
      if (payload.type === MSG.GET) return await handleGet(from, payload)
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: e.message })
    }
  })

  log(`[vault] listo · id ${fp} · ${store.getTree().children.length} nodos`)

  // ----- API local (para la UI/CLI de control) -----

  /** Inicia un emparejamiento: devuelve el token + el contenido para el QR. */
  function startPairing ({ scope = [SCOPE.SIGN, SCOPE.READ], ttlMs, label = '' } = {}) {
    const token = randToken()
    pending.set(token, { exp: Date.now() + PAIRING_TTL_MS, scope, ttlMs, label, used: false })
    const qr = { v: 1, iss: master, proxy: client.url, token }
    return { token, qr, expiresInMs: PAIRING_TTL_MS }
  }
  function stopPairing (token) { pending.delete(token) }

  return {
    identity, client, store, master, fingerprint: fp,
    startPairing, stopPairing,
    listDevices: () => identity.listDelegations(),
    revokeDevice: (nonce) => identity.revokeDelegation(nonce),
    close () { try { client.close() } catch (_) {} identity.destroy() }
  }
}
