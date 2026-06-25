/**
 * daemon.js — modo SERVICIO del vault. Arranca el núcleo (`startVault`) y añade
 * lo que un servicio headless necesita:
 *
 *   1. escribe `state.json` (fingerprint + iss + proxy) en el dir de datos en
 *      cada arranque → el CLI de control y el instalador lo leen sin tocar la
 *      identidad ni abrir puertos/sockets (privacidad: nada escucha).
 *   2. atiende SIGUSR1 → mina un token de emparejamiento y escribe `pair.json`
 *      (0600, efímero) para que `dotrino-vault pair` lo lea y dibuje el QR. Así
 *      el secreto de emparejamiento vive en memoria del daemon y solo se vuelca
 *      a un archivo 0600 a pedido explícito del dueño.
 *   3. apagado limpio con SIGTERM/SIGINT (systemd manda SIGTERM).
 *
 * NO abre sockets de control: el único transporte es el proxy del ecosistema.
 */
import fs from 'node:fs'
import path from 'node:path'
import { startVault } from './vault.js'
import { dataDir, writeJson, readJson } from './paths.js'

const readJsonSafe = (f) => readJson(f, null)

export async function runDaemon () {
  const dir = dataDir()
  const proxyUrl = process.env.PROXY_URL || 'wss://proxy.dotrino.com'

  const vault = await startVault({ dir, proxyUrl })

  // --- 1. state.json: lo lee el CLI/instalador (legible solo por el dueño) ---
  const stateFile = path.join(dir, 'state.json')
  writeJson(stateFile, {
    v: 1,
    fingerprint: vault.fingerprint,
    iss: vault.master,
    proxy: vault.client.url,
    pid: process.pid,
    startedAt: new Date().toISOString()
  })
  console.log(`dotrino-vault · datos en ${dir} · proxy ${proxyUrl}`)
  console.log(`identidad (fingerprint): ${vault.fingerprint} · pid ${process.pid}`)

  // --- 2. emparejamiento a pedido vía SIGUSR1 -------------------------------
  const pairFile = path.join(dir, 'pair.json')
  process.on('SIGUSR1', () => {
    try {
      const { qr, expiresInMs } = vault.startPairing({ label: 'cli' })
      writeJson(pairFile, { v: 1, qr, expiresAt: Date.now() + expiresInMs })
      console.log('[vault] token de emparejamiento generado (válido %d min)', expiresInMs / 60000)
    } catch (e) {
      console.error('[vault] no se pudo generar emparejamiento:', e.message)
    }
  })

  // --- 2b. snapshot de dispositivos a pedido vía SIGUSR2 --------------------
  // El daemon es el ÚNICO proceso que abre la identidad; el CLI no la toca. Para
  // que `dotrino-vault devices` no necesite un socket de control, el daemon
  // vuelca el listado a `devices.json` (0600) cuando recibe SIGUSR2.
  const devFile = path.join(dir, 'devices.json')
  const revokeReqFile = path.join(dir, 'revoke-request.json')
  process.on('SIGUSR2', async () => {
    try {
      // Si hay una orden de revocación pendiente del CLI, ejecutarla primero.
      const req = readJsonSafe(revokeReqFile)
      if (req?.nonce) {
        try { await vault.revokeDevice(req.nonce); console.log('[vault] revocado nonce=%s', req.nonce) }
        catch (e) { console.error('[vault] revocación falló:', e.message) }
        try { fs.rmSync(revokeReqFile, { force: true }) } catch (_) {}
      }
      const list = await vault.listDevices()
      writeJson(devFile, { v: 1, at: Date.now(), ...list })
    } catch (e) {
      console.error('[vault] no se pudo volcar dispositivos:', e.message)
    }
  })

  // --- 3. apagado limpio -----------------------------------------------------
  const shutdown = (sig) => {
    console.log(`\n[vault] ${sig} → deteniendo…`)
    try { fs.rmSync(pairFile, { force: true }) } catch (_) {}
    try { vault.close() } catch (_) {}
    process.exit(0)
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))

  console.log('[vault] servicio listo.')
  return vault
}
