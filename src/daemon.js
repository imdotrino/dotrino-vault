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
  writeJson(stateFile, {
    v: 1, fingerprint: vault.fingerprint, iss: vault.master,
    proxy: vault.client.url, pid: process.pid, startedAt: new Date().toISOString()
  })
  console.log(`dotrino-vault · datos en ${dir} · proxy ${proxyUrl}`)
  console.log(`identidad (fingerprint): ${vault.fingerprint} · pid ${process.pid}`)

  // --- SIGUSR1: iniciar emparejamiento ---
  const pairFile = path.join(dir, 'pair.json')
  process.on('SIGUSR1', () => {
    try {
      rm(pendingEnrollFile)
      // Pairing manual por CLI = gesto explícito del dueño → cert de identidad completo.
      const { qr, expiresInMs } = vault.startPairing({ scope: ['vault:sign', 'vault:read', 'vault:store'], label: 'cli' })
      writeJson(pairFile, { v: 2, qr, expiresAt: Date.now() + expiresInMs })
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
  process.on('SIGUSR2', async () => {
    try {
      const appr = readJsonSafe(approveReqFile)
      if (appr?.code) {
        try { const r = await vault.approveDevice(appr.code); rm(pendingEnrollFile); console.log('[vault] aprobado %s', r.deviceId) }
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
