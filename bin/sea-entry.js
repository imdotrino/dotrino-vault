/**
 * sea-entry.js — punto de entrada ÚNICO del binario autosuficiente (SEA).
 *
 * El mismo binario hace de daemon y de CLI de control (multicall):
 *   dotrino-vaultd            → arranca el daemon (modo servicio)
 *   dotrino-vaultd --ctl ...  → CLI de control (status / pair / devices / revoke)
 *
 * El wrapper `dotrino-vault` invoca siempre con `--ctl`. Se usa import dinámico
 * para no cargar el grafo del daemon (transporte/identity) cuando solo querés
 * un `status` rápido.
 */
const argv = process.argv.slice(2)

if (argv[0] === '--ctl') {
  // CLI de control: NO toca la identidad ni el proxy; habla con el daemon vía
  // el dir de datos (state.json) y señales (SIGUSR1 para emparejar).
  import('../src/ctl.js').then(({ runCtl }) => runCtl(argv.slice(1)))
    .catch((e) => { console.error('error:', e.message); process.exit(1) })
} else {
  // Modo daemon (servicio).
  import('../src/daemon.js').then(({ runDaemon }) => runDaemon(argv))
    .catch((e) => { console.error('error fatal del daemon:', e.message); process.exit(1) })
}
