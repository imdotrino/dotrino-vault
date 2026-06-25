#!/usr/bin/env node
/**
 * dotrino-vaultd — entrypoint de DESARROLLO (node directo, sin SEA).
 *
 *   node bin/dotrino-vaultd.js          arranca el vault (modo servicio)
 *   node bin/dotrino-vaultd.js --pair   arranca e imprime un QR de emparejamiento
 *
 * En producción el usuario corre el binario SEA (bin/sea-entry.js → src/daemon.js).
 * Este archivo comparte el mismo núcleo (`runDaemon`) para no divergir.
 *
 * Env:
 *   DOTRINO_VAULT_DIR   dir de datos (default ~/.dotrino/vault)
 *   PROXY_URL           proxy (default wss://proxy.dotrino.com)
 */
import { runDaemon } from '../src/daemon.js'
import { qrToString } from '../src/qr.js'

const vault = await runDaemon()

// Atajo de dev: --pair imprime el QR directo en stdout (en producción se usa el CLI).
if (process.argv.includes('--pair')) {
  const { qr, expiresInMs } = vault.startPairing({ label: 'cli' })
  console.log(`\nEmparejá un dispositivo (válido ${expiresInMs / 60000} min):\n`)
  console.log(qrToString(JSON.stringify(qr)))
  console.log(JSON.stringify(qr))
}

console.log('\n(Ctrl+C para detener)')
