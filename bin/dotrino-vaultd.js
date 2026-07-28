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

const mgr = await runDaemon()

// Atajo de dev: --pair imprime el QR directo en stdout (en producción se usa el CLI).
// Empareja contra el perfil ACTIVO.
if (process.argv.includes('--pair')) {
  const { qr, expiresInMs } = mgr.current().startPairing({ label: 'cli' })
  console.log(`\nEmparejá un dispositivo (válido ${expiresInMs / 60000} min):\n`)
  console.log(qrToString(JSON.stringify(qr)))
  console.log(JSON.stringify(qr))
}

// --tui: la bóveda Y su interfaz en la MISMA ventana. Donde no queda como servicio
// (Windows, macOS) el daemon ocupa la ventana en primer plano, así que abrir la TUI
// obligaba a una segunda ventana y a repetir el PATH de Node. Con esto, una sola.
if (process.argv.includes('--tui')) {
  if (!process.stdout.isTTY) {
    console.error('--tui necesita un terminal interactivo (TTY). La bóveda sigue corriendo sin él.')
  } else {
    const { runTui } = await import('../src/tui/app.js')
    await runTui()          // al salir de la TUI, se para todo: es la misma ventana
    process.exit(0)
  }
}

console.log('\n(Ctrl+C para detener)')
