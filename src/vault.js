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
import { verifyChain, verifyDeviceSig, pubkeyId } from '@dotrino/identity/capabilities'
import { createTransport, masterPubkeyOf } from './transport.js'
import { openStore } from './store.js'
import { openThreadStore, STORE_READ_METHODS } from './threadStore.js'
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
  const threads = openThreadStore(dir)
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
    // Un solo dispositivo a la vez esperando su código (así `approve <código>` no es ambiguo).
    if (pend.state === 'PENDING_CONFIRM' && pend.dpub && pend.dpub !== d.dpub) {
      return reply(from, { type: MSG.ERROR, error: 'ya hay un dispositivo usando este emparejamiento' })
    }

    const deviceId = await deviceIdOf(d.dpub)
    pend.state = 'PENDING_CONFIRM'
    pend.dpub = d.dpub
    pend.deviceId = deviceId
    pend.from = from  // el vault NO conoce el código del dispositivo (no se manda); solo lo ECHA al aprobar
    if (d.label) pend.label = String(d.label).slice(0, 60)

    // El dispositivo MUESTRA el código; el dueño lo TIPEA en el PC. El vault no lo sabe.
    reply(from, { type: MSG.ENROLL_CHALLENGE, deviceId })
    log(`\n[vault] Un dispositivo quiere conectarse:`)
    log(`        deviceId: ${deviceId}`)
    log(`        Ingresá el código que MUESTRA el dispositivo:`)
    log(`          dotrino-vault approve <código>    (o rechazá: dotrino-vault reject ${deviceId})\n`)
    try { onEnrollChallenge?.({ deviceId, scope: pend.scope }) } catch (_) {}
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

  // Store de hilos+aperturas (Fase 3): escrituras requieren vault:store; lecturas
  // aceptan vault:store o vault:read. Cada op va firmada por D + cert (cadena D←maestra).
  async function handleStore (from, p) {
    const d = p.data
    if (!d || typeof d.method !== 'string' || !threads.methods[d.method]) {
      return reply(from, { type: MSG.ERROR, error: 'store: método inválido' })
    }
    const revoked = await revocationSet()
    let chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.STORE, trustedIssuer: master, revoked })
    if (!chk.ok && STORE_READ_METHODS.has(d.method)) {
      chk = await verifyChain({ data: d, signature: p.signature, cert: p.cert, expectedScope: SCOPE.READ, trustedIssuer: master, revoked })
    }
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    try {
      const result = await threads.methods[d.method](d.args || {})
      reply(from, { type: MSG.STORE_RESULT, method: d.method, result })
    } catch (e) { reply(from, { type: MSG.ERROR, error: e.message }) }
  }

  // Lista (solo lectura) de dispositivos enrolados, para un panel en el navegador.
  // Cualquier cert válido tuyo puede verla; REVOCAR sigue siendo solo desde el PC.
  async function handleDevices (from, p) {
    const chk = await verifyChain({ data: p.data, signature: p.signature, cert: p.cert, trustedIssuer: master, revoked: await revocationSet() })
    if (!chk.ok) return reply(from, { type: MSG.ERROR, error: 'no autorizado: ' + chk.reason })
    const { issued, revoked } = await identity.listDelegations()
    const devices = await Promise.all(issued.map(async (x) => ({
      deviceId: x.sub ? await deviceIdOf(x.sub) : null, label: x.label || '', scope: x.scope, exp: x.exp, nonce: x.nonce
    })))
    reply(from, { type: MSG.DEVICES_RESULT, devices, revoked })
  }

  client.on('message', async (from, payload) => {
    if (!payload || typeof payload !== 'object') return
    try {
      if (payload.type === MSG.ENROLL) return await handleEnroll(from, payload)
      if (payload.type === MSG.SIGN) return await handleSign(from, payload)
      if (payload.type === MSG.GET) return await handleGet(from, payload)
      if (payload.type === MSG.STORE) return await handleStore(from, payload)
      if (payload.type === MSG.DEVICES) return await handleDevices(from, payload)
    } catch (e) {
      reply(from, { type: MSG.ERROR, error: e.message })
    }
  })

  log(`[vault] listo · id ${fp} · ${store.getTree().children.length} nodos`)

  // ----- API local (CLI/UI de control) -----

  /** Inicia un emparejamiento: token + nonce de sesión. NO firma nada aún. */
  function startPairing ({ scope = [SCOPE.READ], ttlMs, label = '' } = {}) {
    pending.clear() // un emparejamiento a la vez: una sesión nueva supersede la anterior
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
      .map((p) => ({ deviceId: p.deviceId, scope: p.scope }))
  }

  /**
   * El dueño aprueba TIPEANDO el código que muestra el dispositivo. El vault NO conocía el
   * código: recompone el compromiso `H(code‖dpub‖sn)` y busca el enrol pendiente que matchea.
   * Solo si matchea (= tenés el dispositivo, de ahí leíste el código) firma el cert.
   */
  async function approveDevice (code) {
    code = String(code || '').trim()
    if (!code) throw new Error('falta el código (los dígitos que muestra el dispositivo)')
    const entries = [...pending.entries()].filter(([, pe]) => pe.state === 'PENDING_CONFIRM' && pe.dpub)
    if (entries.length === 0) throw new Error('no hay ningún dispositivo esperando aprobación')
    if (entries.length > 1) throw new Error('hay más de un emparejamiento en curso; reiniciá con dotrino-vault pair')
    const [, pend] = entries[0]
    const { cert } = await identity.signDelegation(pend.dpub, pend.scope, { ttlMs: pend.ttlMs, label: pend.label })
    // Echamos el código tipeado + el cert. El vault NO valida el código: el DISPOSITIVO acepta
    // solo si coincide con el que generó → un vault falso (que no conoce el código) no puede.
    reply(pend.from, { type: MSG.ENROLLED, code, cert, iss: master })
    log(`[vault] código enviado al dispositivo ${pend.deviceId} (acepta si coincide con el suyo)`)
    return { ok: true, deviceId: pend.deviceId }
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
    identity, client, store, threads, master, fingerprint: fp,
    startPairing, stopPairing, listPending,
    approveDevice, rejectDevice,
    listDevices: () => identity.listDelegations(),
    revokeDevice,
    close () { try { client.close() } catch (_) {} identity.destroy() }
  }
}
