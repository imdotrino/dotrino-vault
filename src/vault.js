/**
 * dotrino-vault — núcleo del certificador personal (daemon headless).
 *
 * Custodia la clave MAESTRA del usuario (vía `@dotrino/identity`) y la expone como
 * CA propia. EMPAREJAMIENTO ENDURECIDO (ver docs/pairing-protocol.md): el token de
 * 5 min ya NO es autoridad suficiente — para obtener un cert el dispositivo debe
 * (1) PROBAR posesión de su llave D firmando el ENROLL, y (2) el dueño debe APROBAR
 * en el PC tras comparar un SAS (código de 6 dígitos) entre las dos pantallas. La
 * maestra solo firma el cert DESPUÉS de esa aprobación humana.
 *
 * Toda la cripto es de `@dotrino/identity`. Este módulo solo orquesta.
 */
import { Identity } from '@dotrino/identity/node'
import { verifyChain, verifyDeviceSig, deriveSAS, pubkeyId } from '@dotrino/identity/capabilities'
import { createTransport, masterPubkeyOf } from './transport.js'
import { openStore } from './store.js'
import { dataDir, ensureDir } from './paths.js'
import { MSG, SCOPE } from './protocol.js'

const PAIRING_TTL_MS = 5 * 60 * 1000 // un token de emparejamiento vale 5 min

function randToken () {
  const b = crypto.getRandomValues(new Uint8Array(16))
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}

/** deviceId legible (8 hex agrupados, p.ej. AB12-CD34) a partir del pubkey D. */
async function deviceIdOf (dpub) {
  const id = (await pubkeyId(dpub)).slice(0, 8).toUpperCase()
  return id.slice(0, 4) + '-' + id.slice(4, 8)
}

export async function startVault ({ dir = dataDir(), proxyUrl, log = console.log, onEnrollChallenge } = {}) {
  ensureDir(dir)
  const identity = await Identity.connect({ dir })
  if (!identity.me?.publickey) await identity.setMyNickname('')

  const store = openStore(dir)
  const master = await masterPubkeyOf(identity)
  const fp = (await pubkeyId(master)).slice(0, 16)

  const { client } = await createTransport({ identity, dir, url: proxyUrl })

  // token -> { exp, scope, ttlMs, label, sn, state, dpub?, deviceId?, sas?, from? }
  // state: 'AWAITING_ENROLL' -> 'PENDING_CONFIRM'
  const pending = new Map()

  async function revocationSet () {
    const { revoked } = await identity.listDelegations()
    return new Set(revoked.map((r) => r.nonce))
  }

  const reply = (to, obj) => {
    try { client.send(to, obj) } catch (e) { log('[vault] no se pudo responder:', e.message) }
  }

  // --- ENROLL: el dispositivo prueba posesión de D; NO se firma cert todavía ---
  async function handleEnroll (from, p) {
    const d = p?.data
    if (!d || typeof d.dpub !== 'string' || typeof p.signature !== 'string') {
      return reply(from, { type: MSG.ERROR, error: 'enroll inválido' })
    }
    const pend = pending.get(d.token)
    if (!pend || pend.used || Date.now() > pend.exp) {
      return reply(from, { type: MSG.ERROR, error: 'token de emparejamiento inválido o expirado' })
    }
    if (d.sn !== pend.sn) return reply(from, { type: MSG.ERROR, error: 'sesión inválida' })
    // PRUEBA DE POSESIÓN: la firma de `data` debe verificar contra `dpub`.
    const ok = await verifyDeviceSig({ publickey: d.dpub, data: d, signature: p.signature })
    if (!ok) return reply(from, { type: MSG.ERROR, error: 'firma de dispositivo inválida' })

    const deviceId = await deviceIdOf(d.dpub)
    const sas = await deriveSAS(master, d.dpub, pend.sn)
    pend.state = 'PENDING_CONFIRM'
    pend.dpub = d.dpub
    pend.deviceId = deviceId
    pend.sas = sas
    pend.from = from
    if (d.label) pend.label = String(d.label).slice(0, 60)

    // El dispositivo recibe el reto (mostrará deviceId + SAS en su pantalla).
    reply(from, { type: MSG.ENROLL_CHALLENGE, deviceId, sas })
    // El dueño ve el mismo deviceId + SAS en el PC y decide aprobar.
    log(`\n[vault] Un dispositivo quiere conectarse:`)
    log(`        deviceId: ${deviceId}   ·   código (SAS): ${sas}`)
    log(`        Verificá que coincida con el del dispositivo y aprobá:`)
    log(`          dotrino-vault approve ${deviceId}    (o rechazá: dotrino-vault reject ${deviceId})\n`)
    try { onEnrollChallenge?.({ deviceId, sas, scope: pend.scope }) } catch (_) {}
  }

  // --- handleSign / handleGet: idénticos (verifyChain de la cadena D←maestra) ---
  async function handleSign (from, p) {
    const chk = await verifyChain({
      data: p.data, signature: p.signature, cert: p.cert,
      expectedScope: SCOPE.SIGN, trustedIssuer: master, revoked: await revocationSet()
    })
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const toSign = p.data?.payload
    if (toSign == null) return reply(from, { type: MSG.ERROR, error: 'data.payload requerido' })
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

  // ----- API local (CLI/UI de control) -----

  /** Inicia un emparejamiento: token + nonce de sesión. NO firma nada aún. */
  function startPairing ({ scope = [SCOPE.READ], ttlMs, label = '' } = {}) {
    const token = randToken()
    const sn = randToken()
    pending.set(token, { exp: Date.now() + PAIRING_TTL_MS, scope, ttlMs, label, sn, state: 'AWAITING_ENROLL', used: false })
    const qr = { v: 2, iss: master, proxy: client.url, token, sn }
    return { token, qr, expiresInMs: PAIRING_TTL_MS }
  }
  function stopPairing (token) { pending.delete(token) }

  function findPending (deviceId) {
    for (const [token, pend] of pending) {
      if (pend.deviceId === deviceId && pend.state === 'PENDING_CONFIRM') return { token, pend }
    }
    return null
  }
  function listPending () {
    return [...pending.values()]
      .filter((p) => p.state === 'PENDING_CONFIRM')
      .map((p) => ({ deviceId: p.deviceId, sas: p.sas, scope: p.scope }))
  }

  /** El dueño aprueba un enroll pendiente: SOLO ahora la maestra firma el cert. */
  async function approveDevice (deviceId) {
    const found = findPending(deviceId)
    if (!found) throw new Error('no hay un emparejamiento pendiente con ese deviceId')
    const { token, pend } = found
    const { cert } = await identity.signDelegation(pend.dpub, pend.scope, { ttlMs: pend.ttlMs, label: pend.label })
    pend.used = true
    pending.delete(token)
    reply(pend.from, { type: MSG.ENROLLED, cert, iss: master, sas: pend.sas })
    log(`[vault] dispositivo aprobado: ${deviceId} · scope ${JSON.stringify(pend.scope)}`)
    return { ok: true, deviceId, nonce: cert.nonce }
  }

  /** El dueño rechaza un enroll pendiente. */
  function rejectDevice (deviceId) {
    const found = findPending(deviceId)
    if (!found) return { ok: false }
    reply(found.pend.from, { type: MSG.ERROR, error: 'emparejamiento rechazado' })
    pending.delete(found.token)
    log(`[vault] dispositivo rechazado: ${deviceId}`)
    return { ok: true, deviceId }
  }

  /**
   * Revoca un dispositivo y le emite un MSG.REVOKED FIRMADO por la maestra para que
   * se autoborre (el borrado remoto SOLO se dispara con esta firma, no con un error
   * cualquiera → cierra el wipe-DoS). El proxy lo encola offline 24 h.
   */
  async function emitRevoke (dpub, nonce) {
    const body = { op: 'revoke', sub: dpub, nonce, iat: Date.now(), exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }
    const { signature } = await identity.signData(body)
    try { client.sendByPubkey(dpub, { type: MSG.REVOKED, body, signature }) } catch (e) { log('[vault] no se pudo emitir revoke:', e.message) }
  }
  async function revokeDevice (nonce) {
    const { issued } = await identity.listDelegations()
    const dele = issued.find((d) => d.nonce === nonce)
    const res = await identity.revokeDelegation(nonce)
    if (dele?.sub) await emitRevoke(dele.sub, nonce)
    return res
  }

  return {
    identity, client, store, master, fingerprint: fp,
    startPairing, stopPairing, listPending,
    approveDevice, rejectDevice,
    listDevices: () => identity.listDelegations(),
    revokeDevice,
    close () { try { client.close() } catch (_) {} identity.destroy() }
  }
}
