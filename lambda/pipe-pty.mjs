/**
 * UNA CONSOLA SIN TERMINAL, para la demo en Lambda (`demo.mjs`).
 *
 * En Lambda no hay pseudoterminales: no existe `/dev/ptmx` y `forkpty` falla (comprobado el
 * 2026-10-23). Esto hace las veces de `node-pty` con tuberías: la shell corre con stdin y stdout
 * normales, y lo que haría el terminal lo hace esto —el eco de lo que se teclea, borrar con la
 * tecla de retroceso, Ctrl-C y Ctrl-D— línea a línea.
 *
 * Lo que NO hay, y se dice: programas de pantalla completa (vim, top, less), autocompletar,
 * historial con las flechas, ni el tamaño de la ventana. Para que quien revisa la app vea una
 * consola de verdad que contesta, basta.
 *
 * Solo implementa lo que usa el agente (`consoles.js`): `onData`, `onExit`, `write`, `resize`,
 * `kill`.
 */
import { spawn as spawnChild } from 'node:child_process'

/** Lo que dice bash al arrancar sin terminal. No es un error de quien la usa: se calla. */
const NOISE = /^bash: (cannot set terminal process group|no job control in this shell).*$/gm

const crlf = (s) => s.replace(NOISE, '').replace(/\r?\n/g, '\r\n')

export function spawn (file, args = [], opts = {}) {
  const child = spawnChild(file, args, {
    cwd: opts.cwd, env: opts.env, stdio: ['pipe', 'pipe', 'pipe'],
    // Su propio grupo: Ctrl-C se manda al grupo entero, que es lo que hace un terminal.
    detached: true
  })
  const dataCbs = []
  const exitCbs = []
  const emit = (s) => { if (s) for (const cb of dataCbs) cb(s) }
  child.stdout.setEncoding('utf8')
  child.stderr.setEncoding('utf8')
  child.stdout.on('data', (d) => emit(crlf(d)))
  child.stderr.on('data', (d) => emit(crlf(d)))
  child.on('exit', (code, signal) => { for (const cb of exitCbs) cb({ exitCode: code ?? 0, signal: signal || undefined }) })
  child.on('error', (e) => emit(`\r\n${e.message}\r\n`))

  let line = ''
  let esc = false
  const send = (s) => { try { child.stdin.write(s) } catch (_) {} }
  const signal = (sig) => { try { process.kill(-child.pid, sig) } catch (_) {} }

  return {
    pid: child.pid,
    onData (cb) { dataCbs.push(cb); return { dispose () { dataCbs.splice(dataCbs.indexOf(cb), 1) } } },
    onExit (cb) { exitCbs.push(cb); return { dispose () { exitCbs.splice(exitCbs.indexOf(cb), 1) } } },
    write (data) {
      for (const ch of String(data)) {
        // Las secuencias de escape (flechas, Inicio…) no tienen dónde ir sin terminal.
        if (esc) { if (/[A-Za-z~]/.test(ch)) esc = false; continue }
        if (ch === '\x1b') { esc = true; continue }
        if (ch === '\r' || ch === '\n') { emit('\r\n'); send(line + '\n'); line = ''; continue }
        if (ch === '\x7f' || ch === '\b') { if (line) { line = [...line].slice(0, -1).join(''); emit('\b \b') } continue }
        if (ch === '\x03') { line = ''; emit('^C\r\n'); signal('SIGINT'); send('\n'); continue }
        if (ch === '\x04') { if (!line) { try { child.stdin.end() } catch (_) {} } continue }
        if (ch < ' ' && ch !== '\t') continue
        line += ch
        emit(ch)
      }
    },
    resize () {},
    kill (sig = 'SIGHUP') { signal(sig); try { child.kill(sig) } catch (_) {} }
  }
}

export default { spawn }
