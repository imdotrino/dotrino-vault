/**
 * daemon.js — modo SERVICIO del vault. Arranca `startVault` y expone control
 * LOCAL por archivos + señales (sin socket/puerto: nada escucha en red).
 *
 *   state.json          fingerprint + iss + proxy (lo lee el CLI/instalador)
 *   SIGUSR1 → pair.json  inicia un emparejamiento y vuelca el QR
 *   pending-enroll.json  cuando un dispositivo pide enrolarse: { deviceId, sas } a
 *                        comparar/aprobar (emparejamiento ENDURECIDO, ver docs/)
 *   SIGUSR2 → consume approve-request / reject-request / revoke-request y vuelca
 *             devices.json
 *
 * La maestra solo firma el cert de un dispositivo DESPUÉS de `dotrino-vault approve`.
 */
import fs from 'node:fs'
import path from 'node:path'
import { startVault } from './vault.js'
import { dataDir, writeJson, readJson } from './paths.js'

const readJsonSafe = (f) => readJson(f, null)
const rm = (f) => { try { fs.rmSync(f, { force: true }) } catch (_) {} }

export async function runDaemon () {
  const dir = dataDir()
  const proxyUrl = process.env.PROXY_URL || 'wss://proxy.dotrino.com'

  const pendingEnrollFile = path.join(dir, 'pending-enroll.json')
  // Cuando un dispositivo pide enrolarse, exponemos su deviceId+SAS para que el
  // dueño lo compare con el del dispositivo y apruebe.
  const onEnrollChallenge = ({ deviceId, scope }) => {
    writeJson(pendingEnrollFile, { v: 1, at: Date.now(), deviceId, scope })
  }

  const vault = await startVault({ dir, proxyUrl, onEnrollChallenge })

  // --- state.json ---
  const stateFile = path.join(dir, 'state.json')
  const daemonVersion = (typeof __VAULT_VERSION__ !== 'undefined') ? __VAULT_VERSION__ : 'dev'
  writeJson(stateFile, {
    v: 1, version: daemonVersion, fingerprint: vault.fingerprint, iss: vault.master,
    proxy: vault.client.url, pid: process.pid, startedAt: new Date().toISOString()
  })
  console.log(`dotrino-vault · datos en ${dir} · proxy ${proxyUrl}`)
  console.log(`identidad (fingerprint): ${vault.fingerprint} · pid ${process.pid}`)

  // --- SIGUSR1: iniciar emparejamiento ---
  const pairFile = path.join(dir, 'pair.json')
  const pairReqFile = path.join(dir, 'pair-request.json')
  process.on('SIGUSR1', () => {
    try {
      rm(pendingEnrollFile)
      // Pairing manual por CLI = gesto explícito del dueño → cert de identidad completo.
      // ttlMs: 30 días (MAX_DELEGATION_MS). Sin esto caía al default de 24 h, pensado
      // para delegaciones efímeras: los dispositivos emparejados morían al día
      // siguiente en silencio ("no autorizado" en todas las apps). Renovación
      // automática: pendiente (por ahora, re-emparejar al mes).
      const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000
      // `pair --service <ns>` (vía pair-request.json): cert SOLO con
      // vault:secrets:<ns> — para enrolar un SERVICIO (proxy, geo…) que lee sus
      // secretos, sin poder firmar como el usuario ni leer sus datos.
      const pairReq = readJsonSafe(pairReqFile); rm(pairReqFile)
      const isService = typeof pairReq?.service === 'string' && pairReq.service
      const scope = isService ? ['vault:secrets:' + pairReq.service] : ['vault:sign', 'vault:read', 'vault:store']
      const label = pairReq?.label || (isService ? 'servicio:' + pairReq.service : 'cli')
      const { qr, expiresInMs } = vault.startPairing({ scope, label, ttlMs: DEVICE_TTL_MS })
      writeJson(pairFile, { v: 2, qr, expiresAt: Date.now() + expiresInMs })
      // El token es un secreto efímero: no debe quedar en disco más allá de su
      // vida. Se borra al VENCER (aquí) y al APROBARSE (abajo, consumido).
      const tok = qr.token
      setTimeout(() => {
        const cur = readJsonSafe(pairFile)
        if (cur?.qr?.token === tok) rm(pairFile)
      }, expiresInMs + 1000).unref?.()
      console.log('[vault] emparejamiento iniciado (válido %d min)', expiresInMs / 60000)
    } catch (e) {
      console.error('[vault] no se pudo iniciar emparejamiento:', e.message)
    }
  })

  // --- SIGUSR2: approve / reject / revoke + volcado de dispositivos ---
  const devFile = path.join(dir, 'devices.json')
  const approveReqFile = path.join(dir, 'approve-request.json')
  const rejectReqFile = path.join(dir, 'reject-request.json')
  const revokeReqFile = path.join(dir, 'revoke-request.json')
  const secretReqFile = path.join(dir, 'secret-request.json')
  const secretsListFile = path.join(dir, 'secrets-list.json')
  process.on('SIGUSR2', async () => {
    try {
      const appr = readJsonSafe(approveReqFile)
      if (appr?.code) {
        try { const r = await vault.approveDevice(appr.code); rm(pendingEnrollFile); rm(pairFile); console.log('[vault] aprobado %s', r.deviceId) }
        catch (e) { console.error('[vault] aprobación falló:', e.message) }
        rm(approveReqFile)
      }
      const rej = readJsonSafe(rejectReqFile)
      if (rej?.deviceId) {
        try { vault.rejectDevice(rej.deviceId); rm(pendingEnrollFile) } catch (_) {}
        rm(rejectReqFile)
      }
      const req = readJsonSafe(revokeReqFile)
      if (req?.nonce) {
        try { await vault.revokeDevice(req.nonce); console.log('[vault] revocado nonce=%s', req.nonce) }
        catch (e) { console.error('[vault] revocación falló:', e.message) }
        rm(revokeReqFile)
      }
      // Secretos de servicios: `secret set/rm` del CLI. El archivo con el valor
      // vive un instante en el mismo dir 0700 del vault y se borra al consumir.
      const sec = readJsonSafe(secretReqFile)
      if (sec?.op) {
        try {
          if (sec.op === 'set') { vault.setSecret(sec.ns, sec.key, sec.value); console.log('[vault] secreto guardado: %s/%s', sec.ns, sec.key) }
          else if (sec.op === 'rm') { vault.deleteSecret(sec.ns, sec.key); console.log('[vault] secreto borrado: %s/%s', sec.ns, sec.key) }
        } catch (e) { console.error('[vault] secreto falló:', e.message) }
        rm(secretReqFile)
      }
      // Volcado de nombres (nunca valores) para `secret list`.
      writeJson(secretsListFile, { v: 1, at: Date.now(), ns: vault.listSecrets() })
      const list = await vault.listDevices()
      writeJson(devFile, { v: 1, at: Date.now(), ...list })
    } catch (e) {
      console.error('[vault] error en señal de control:', e.message)
    }
  })

  // --- apagado limpio ---
  const shutdown = (sig) => {
    console.log(`\n[vault] ${sig} → deteniendo…`)
    rm(pairFile); rm(pendingEnrollFile)
    try { vault.close() } catch (_) {}
    process.exit(0)
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))

  console.log('[vault] servicio listo.')
  return vault
}
