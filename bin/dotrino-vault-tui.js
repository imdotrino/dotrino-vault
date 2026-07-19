#!/usr/bin/env node
/**
 * dotrino-vault-tui — interfaz de terminal (pantalla completa) del vault.
 *
 * Entrypoint de DESARROLLO (node directo). En producción el binario SEA expone
 * lo mismo con `dotrino-vaultd --tui` (ver bin/sea-entry.js).
 *
 * NO abre la identidad ni la red: le da órdenes al daemon por archivos + señales
 * (misma vía que la CLI de control). El daemon debe estar corriendo; si no, la
 * TUI ofrece arrancarlo.
 *
 *   node bin/dotrino-vault-tui.js
 *
 * Env:
 *   DOTRINO_VAULT_DIR   dir de datos (default ~/.local/share/dotrino/vault)
 */
import { runTui } from '../src/tui/app.js'

if (!process.stdout.isTTY) {
  console.error('dotrino-vault-tui necesita un terminal interactivo (TTY).')
  process.exit(2)
}

runTui().catch((e) => {
  // El finally de runTui ya restauró el terminal; aquí solo reportamos.
  console.error('error en la TUI:', e?.stack || e?.message || e)
  process.exit(1)
})
