/**
 * sea-entry.js — punto de entrada ÚNICO del binario autosuficiente (SEA).
 *
 * El mismo binario hace de daemon y de CLI de control (multicall):
 *   dotrino-vaultd            → arranca el daemon (modo servicio)
 *   dotrino-vaultd --ctl ...  → CLI de control (status / pair / devices / revoke)
 *
 * El wrapper `dotrino-vault` invoca siempre con `--ctl`. Se usa import dinámico
 * para no cargar el grafo del daemon (transporte/identity) cuando solo quieres
 * un `status` rápido.
 */
const argv = process.argv.slice(2)

if (argv[0] === '--tui') {
  // Interfaz de terminal (pantalla completa). Como la CLI, NO toca la identidad
  // ni el proxy: habla con el daemon por el dir de datos + señales.
  if (!process.stdout.isTTY) { console.error('la TUI necesita un terminal interactivo (TTY).'); process.exit(2) }
  import('../src/tui/app.js').then(({ runTui }) => runTui())
    .catch((e) => { console.error('error en la TUI:', e.message); process.exit(1) })
} else if (argv[0] === '--ctl') {
  // CLI de control: NO toca la identidad ni el proxy; habla con el daemon vía
  // el dir de datos (state.json) y señales (SIGUSR1 para emparejar).
  import('../src/ctl.js').then(({ runCtl }) => runCtl(argv.slice(1)))
    .catch((e) => { console.error('error:', e.message); process.exit(1) })
} else {
  // Modo daemon (servicio).
  import('../src/daemon.js').then(({ runDaemon }) => runDaemon(argv))
    .catch((e) => { console.error('error fatal del daemon:', e.message); process.exit(1) })
}
