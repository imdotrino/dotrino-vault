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
import { daemonAlive, pairUrl } from '../src/vaultControl.js'

// `--tui` con una bóveda YA CORRIENDO en otra ventana: se engancha a ella y abre solo la
// interfaz. Antes intentaba levantar una segunda bóveda sobre los mismos datos, chocaba
// con el candado y se cerraba la ventana de golpe — que desde fuera se ve como un crash.
// Es el caso normal, no el raro: la gente deja el daemon en una consola y abre la TUI en
// otra.
if (process.argv.includes('--tui') && daemonAlive()) {
  if (!process.stdout.isTTY) {
    console.error('--tui necesita un terminal interactivo (TTY).')
    process.exit(2)
  }
  const { runTui } = await import('../src/tui/app.js')
  await runTui()
  process.exit(0)
}

const mgr = await runDaemon()

// Atajo de dev: --pair imprime el QR directo en stdout (en producción se usa el CLI).
// Empareja contra el perfil ACTIVO.
if (process.argv.includes('--pair')) {
  // `startPairing` es asíncrono desde que el QR lleva una CITA del proxio (hay
  // que pedírsela) en vez de la dirección de la conexión.
  const { qr, expiresInMs } = await mgr.current().startPairing({ label: 'cli' })
  const { url, b64 } = pairUrl(qr)
  console.log(`\nEmparejá un dispositivo (válido ${expiresInMs / 60000} min):\n`)
  console.log(qrToString(url))
  console.log(url)
  console.log('\nO pegá este código:\n  ' + b64)
}

// --tui: la bóveda Y su interfaz en la MISMA ventana. Donde no queda como servicio
// (Windows, macOS) el daemon ocupa la ventana en primer plano, así que abrir la TUI
// obligaba a una segunda ventana y a repetir el PATH de Node. Con esto, una sola.
if (process.argv.includes('--tui')) {
  if (!process.stdout.isTTY) {
    console.error('--tui necesita un terminal interactivo (TTY). La bóveda sigue corriendo sin él.')
  } else {
    // La TUI se adueña de la pantalla (pantalla alterna + modo crudo). Si el daemon sigue
    // escribiendo sus logs en stdout, se los pinta ENCIMA y la deja ilegible. Se guardan
    // y se sueltan al salir, para no perder un error por el camino.
    const real = { log: console.log, error: console.error, warn: console.warn }
    const buffered = []
    const capture = (level) => (...a) => { buffered.push([level, a]) }
    console.log = capture('log'); console.error = capture('error'); console.warn = capture('warn')

    const { runTui } = await import('../src/tui/app.js')
    try {
      await runTui()        // al salir de la TUI, se para todo: es la misma ventana
    } finally {
      Object.assign(console, real)
      for (const [level, a] of buffered) real[level](...a)
    }
    process.exit(0)
  }
}

console.log('\n(Ctrl+C para detener)')
