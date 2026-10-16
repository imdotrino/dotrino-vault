/**
 * service.js — arrancar, reiniciar y dejar arrancando al iniciar sesión el daemon del vault,
 * en los tres sistemas.
 *
 * Lo usan la TUI y la ventana (las dos ofrecen «arrancar el servicio» cuando no está) y el
 * CLI (`dotrino-vault service`). Antes la TUI llamaba a `systemctl --user` a pelo, así que en
 * Windows y macOS el botón de arrancar solo sabía fallar.
 *
 *   Linux    systemd --user si la unidad está instalada (el .deb y el tarball la ponen);
 *            si no, el daemon suelto en segundo plano.
 *   Windows  el daemon suelto, sin ventana. Al iniciar sesión: una entrada en
 *            HKCU\…\Run que lo lanza con `conhost --headless` (sin consola a la vista).
 *   macOS    un LaunchAgent del usuario (`~/Library/LaunchAgents/com.dotrino.vault.plist`)
 *            que lo levanta al entrar y lo relanza si se cae; sin él, el daemon suelto.
 *
 * Todo es DEL USUARIO, sin permisos de administrador: es lo que deja que se actualice solo
 * (CONVENCIONES §15).
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile, spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dataDir, ensureDir } from './paths.js'

const run = (cmd, args, timeout = 15000) => new Promise((resolve) => {
  execFile(cmd, args, { timeout, windowsHide: true }, (err, so, se) => {
    resolve({ ok: !err, out: String(so || ''), err: err ? (String(se || '').trim() || err.message) : '' })
  })
})

/**
 * Cómo se lanza el daemon desde este mismo proceso. En el binario autosuficiente es el
 * propio ejecutable sin argumentos; desde npm, `node bin/dotrino-vaultd.js`.
 */
export function daemonCommand () {
  if (globalThis.__DOTRINO_SEA__) return { cmd: process.execPath, args: [] }
  const here = path.dirname(fileURLToPath(import.meta.url))
  return { cmd: process.execPath, args: [path.join(here, '..', 'bin', 'dotrino-vaultd.js')] }
}

/** Dónde escribe el daemon suelto lo que diría por consola. */
export const daemonLogFile = () => path.join(dataDir(), 'daemon.log')

/** Lanza el daemon suelto, en segundo plano y sin ventana, con su salida a `daemon.log`. */
export function spawnDaemon () {
  const { cmd, args } = daemonCommand()
  ensureDir(dataDir())
  const fd = fs.openSync(daemonLogFile(), 'a', 0o600)
  try {
    const child = spawn(cmd, args, { detached: true, windowsHide: true, stdio: ['ignore', fd, fd] })
    child.unref()
    return { ok: true, err: '', pid: child.pid }
  } catch (e) {
    return { ok: false, err: e.message }
  } finally { fs.closeSync(fd) }
}

// ------------------------------- Linux ------------------------------------

async function hasSystemdUnit () {
  if (process.platform !== 'linux') return false
  return (await run('systemctl', ['--user', 'cat', 'dotrino-vault'], 5000)).ok
}

// ------------------------------- macOS ------------------------------------

const LABEL = 'com.dotrino.vault'
export const launchAgentFile = () => path.join(os.homedir(), 'Library', 'LaunchAgents', LABEL + '.plist')
const guiDomain = () => `gui/${process.getuid?.() ?? 501}`

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

/** El LaunchAgent: lo arranca al entrar y lo relanza si se cae (no si se para a propósito). */
export function launchAgentPlist ({ cmd, args }, log = daemonLogFile()) {
  const argv = [cmd, ...args].map((a) => `    <string>${xml(a)}</string>`).join('\n')
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${argv}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>${xml(log)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(log)}</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
`
}

// ------------------------------- Windows ----------------------------------

const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
const RUN_VALUE = 'DotrinoVault'

/**
 * La línea que se guarda en `Run`. `conhost --headless` (Windows 10 1809 en adelante) corre
 * una aplicación de consola sin abrirle ventana: sin eso, el daemon sacaría una consola
 * negra cada vez que entras.
 */
export function windowsRunLine ({ cmd, args }) {
  const q = (s) => `"${s}"`
  // Con la ventana instalada al lado, ella lanza el daemon sin consola (`--start-daemon`):
  // es una aplicación de ventanas y no depende de `conhost`.
  const gui = path.join(path.dirname(cmd), 'dotrino-vault-desktop.exe')
  if (globalThis.__DOTRINO_SEA__ && fs.existsSync(gui)) return `${q(gui)} --start-daemon`
  return ['conhost.exe', '--headless', q(cmd), ...args.map(q)].join(' ')
}

// ------------------------------- común ------------------------------------

/** ¿Arranca solo al iniciar sesión? `null` = no se sabe en este sistema. */
export async function autostartStatus () {
  if (process.platform === 'linux') {
    if (!(await hasSystemdUnit())) return { on: false, how: 'none' }
    const r = await run('systemctl', ['--user', 'is-enabled', 'dotrino-vault'], 5000)
    return { on: r.out.trim() === 'enabled', how: 'systemd' }
  }
  if (process.platform === 'darwin') return { on: fs.existsSync(launchAgentFile()), how: 'launchd' }
  if (process.platform === 'win32') {
    const r = await run('reg', ['query', RUN_KEY, '/v', RUN_VALUE], 5000)
    return { on: r.ok, how: 'run-key' }
  }
  return { on: null, how: 'unknown' }
}

/** Deja el daemon arrancando al iniciar sesión (y lo arranca ya, si no está). */
export async function enableAutostart () {
  const dc = daemonCommand()
  if (process.platform === 'linux') {
    if (!(await hasSystemdUnit())) return { ok: false, err: 'no systemd user unit installed (install the .deb, .rpm or the tarball)' }
    return run('systemctl', ['--user', 'enable', '--now', 'dotrino-vault'])
  }
  if (process.platform === 'darwin') {
    const file = launchAgentFile()
    ensureDir(path.dirname(file))
    fs.writeFileSync(file, launchAgentPlist(dc), { mode: 0o644 })
    // Si ya hay un daemon suelto corriendo, el agente lo encontraría ocupado y se
    // relanzaría en bucle: el candado del dir de datos solo deja uno.
    await run('launchctl', ['bootout', `${guiDomain()}/${LABEL}`], 5000)
    return run('launchctl', ['bootstrap', guiDomain(), file])
  }
  if (process.platform === 'win32') {
    return run('reg', ['add', RUN_KEY, '/v', RUN_VALUE, '/t', 'REG_SZ', '/d', windowsRunLine(dc), '/f'])
  }
  return { ok: false, err: `unsupported platform: ${process.platform}` }
}

/** Deja de arrancarlo al iniciar sesión. NO lo para: eso es otra decisión. */
export async function disableAutostart () {
  if (process.platform === 'linux') return run('systemctl', ['--user', 'disable', 'dotrino-vault'])
  if (process.platform === 'darwin') {
    const file = launchAgentFile()
    if (!fs.existsSync(file)) return { ok: true, err: '' }
    // `bootout` también lo PARA. Se vuelve a lanzar suelto para no apagarle la bóveda a
    // quien solo quería que no arrancara sola la próxima vez.
    const wasRunning = (await run('launchctl', ['print', `${guiDomain()}/${LABEL}`], 5000)).ok
    await run('launchctl', ['bootout', `${guiDomain()}/${LABEL}`], 5000)
    fs.rmSync(file, { force: true })
    if (wasRunning) spawnDaemon()
    return { ok: true, err: '' }
  }
  if (process.platform === 'win32') {
    const r = await run('reg', ['delete', RUN_KEY, '/v', RUN_VALUE, '/f'])
    // Que no existiera no es un fallo: el resultado es el que se pedía.
    return r.ok || /unable to find|no se puede encontrar|not find/i.test(r.err) ? { ok: true, err: '' } : r
  }
  return { ok: false, err: `unsupported platform: ${process.platform}` }
}

/** Arranca el daemon por el camino de este sistema. */
export async function startDaemonService () {
  if (await hasSystemdUnit()) return run('systemctl', ['--user', 'start', 'dotrino-vault'], 8000)
  if (process.platform === 'darwin' && fs.existsSync(launchAgentFile())) {
    const r = await run('launchctl', ['kickstart', `${guiDomain()}/${LABEL}`], 8000)
    if (r.ok) return r
    // El agente está escrito pero no cargado (se borró a mano de launchctl): se carga.
    return run('launchctl', ['bootstrap', guiDomain(), launchAgentFile()], 8000)
  }
  return spawnDaemon()
}

/**
 * Reinicia el daemon (tras actualizar). Con systemd o launchd lo hace el supervisor; suelto,
 * se le pide que se vaya y se lanza el nuevo cuando ya no está — dos a la vez no pueden,
 * el candado del dir de datos lo impide.
 */
export async function restartDaemonService ({ pid, alive } = {}) {
  if (await hasSystemdUnit()) {
    const r = await run('systemctl', ['--user', 'restart', 'dotrino-vault'], 20000)
    if (!r.ok) throw new Error(r.err)
    return
  }
  if (process.platform === 'darwin' && fs.existsSync(launchAgentFile())) {
    const r = await run('launchctl', ['kickstart', '-k', `${guiDomain()}/${LABEL}`], 20000)
    if (!r.ok) throw new Error(r.err)
    return
  }
  if (pid) {
    try { process.kill(pid, 'SIGTERM') } catch (_) {}
    for (let n = 0; n < 40 && alive?.(); n++) await new Promise((r) => setTimeout(r, 250))
    if (alive?.()) throw new Error('the old daemon did not stop')
  }
  const r = spawnDaemon()
  if (!r.ok) throw new Error(r.err)
}
