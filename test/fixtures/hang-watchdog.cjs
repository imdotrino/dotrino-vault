/**
 * UN ARCHIVO DE PRUEBAS QUE NO SALE SE DICE, Y NO CUELGA LA RELEASE.
 *
 * Con `node --test`, cada archivo corre en su proceso, y el resultado no se imprime hasta que
 * ese proceso sale. Si algo se queda abierto (un socket, un intervalo), las pruebas pasan y el
 * paso de CI se queda esperando para siempre: así se colgaron la 0.186.0 y la 0.186.1, una hora
 * cada una, sin una sola línea que dijera qué.
 *
 * Esto se carga en cada proceso de prueba (`--require`). Apunta dónde se creó cada socket,
 * proceso hijo o intervalo, y si el proceso sigue vivo a los `LIMIT_MS`, imprime lo que lo
 * mantiene vivo con esa pila y sale con error. El proceso que coordina (sin `NODE_TEST_CONTEXT`)
 * no lo lleva.
 */
if (process.env.NODE_TEST_CONTEXT) {
  const asyncHooks = require('node:async_hooks')
  const LIMIT_MS = Number(process.env.TEST_HANG_LIMIT_MS || 240_000)
  const WATCHED = new Set(['TCPWRAP', 'TCPSERVERWRAP', 'PIPEWRAP', 'PIPESERVERWRAP', 'UDPWRAP', 'PROCESSWRAP', 'TTYWRAP', 'FSEVENTWRAP', 'SIGNALWRAP', 'Timeout'])
  const born = new Map()   // asyncId → { res, type, stack }; se borra al destruirse
  const byRes = new WeakMap()

  asyncHooks.createHook({
    init (id, type, _trigger, resource) {
      if (!WATCHED.has(type)) return
      // De los temporizadores, solo los que se repiten: un setTimeout suelto vence solo.
      if (type === 'Timeout' && !resource._repeat) return
      const limit = Error.stackTraceLimit
      Error.stackTraceLimit = 40
      const raw = new Error().stack
      Error.stackTraceLimit = limit
      const stack = raw.split('\n').slice(1).filter((l) => !l.includes('node:internal')).slice(0, 12).join('\n')
      const info = { res: resource, type, stack }
      born.set(id, info); byRes.set(resource, info)
    },
    destroy (id) { born.delete(id) }
  }).enable()

  setTimeout(() => {
    const out = [`[hang-watchdog] ${process.argv.slice(1).join(' ')} still running after ${LIMIT_MS / 1000}s`,
      `[hang-watchdog] active: ${process.getActiveResourcesInfo().join(', ')}`]
    for (const h of process._getActiveHandles()) {
      if (h === process.stdout || h === process.stderr || h === process.stdin) continue
      if (h.hasRef?.() === false || h._handle?.hasRef?.() === false) continue
      const info = byRes.get(h) || (h._handle && byRes.get(h._handle))
      let what = h.constructor?.name || typeof h
      if (what === 'Socket') what += ` ${h.remoteAddress || h._pipeName || ''}:${h.remotePort || ''} destroyed=${h.destroyed}`
      if (what === 'Server') what += ` ${JSON.stringify(h.address?.())}`
      if (what === 'ChildProcess') what += ` ${h.spawnargs?.join(' ')}`
      out.push(`[hang-watchdog] - ${what}${info ? '\n' + info.stack : ' (no creation stack)'}`)
    }
    for (const { res, type, stack } of born.values()) {
      if (type === 'Timeout' && res.hasRef?.() && !res._destroyed) {
        out.push(`[hang-watchdog] - ref'd interval\n${stack}`)
      }
    }
    process.stderr.write(out.join('\n') + '\n', () => process.exit(97))
  }, LIMIT_MS).unref()
}
