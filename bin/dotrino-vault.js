#!/usr/bin/env node
/**
 * dotrino-vault — el CLI de control, instalado por npm.
 *
 * En el binario autosuficiente (SEA) este mismo CLI vive dentro del ejecutable y se
 * invoca con `dotrino-vaultd --ctl …`; instalado por npm es un `bin` propio, que es lo
 * que espera quien lo corre con `npx` o tras un `npm i -g`.
 *
 * NO abre la identidad ni la red: le da órdenes al daemon escribiendo archivos en el
 * dir de datos (ver `src/vaultControl.js`). Por eso funciona igual en Linux, Windows,
 * macOS y —montando el dir— desde fuera de un contenedor.
 *
 *   dotrino-vault status · pair · approve <código> · members · devices · revoke <nonce>
 *
 * Env:
 *   DOTRINO_VAULT_DIR   dir de datos (default: ver `src/paths.js`)
 */
import { runCtl } from '../src/ctl.js'

runCtl(process.argv.slice(2)).catch((e) => {
  console.error('error:', e?.message || e)
  process.exit(1)
})
