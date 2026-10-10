/**
 * EL LANZADOR DEL PAQUETE DEL SISTEMA (.deb / .rpm): `packaging/pkg-launcher.sh`.
 *
 * El paquete no deja la bóveda en /usr/bin: deja un lanzador que la copia a la carpeta del
 * usuario y la corre desde ahí, que es la instalación que se actualiza sola. Lo que aquí se
 * fija es CUÁNDO copia: si copiara de más, deshacería una actualización que la bóveda ya se
 * hizo sola.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { userBinDir, isUserInstall } from '../src/update.js'

const LAUNCHER = fileURLToPath(new URL('../packaging/pkg-launcher.sh', import.meta.url))

/** Un «binario» de mentira que dice su versión, y si se le pide, desde dónde corre. */
const fake = (v) => `#!/bin/sh\nif [ "$1" = "--ctl" ] && [ "$2" = "version" ]; then echo "dotrino-vault ${v}"; exit 0; fi\necho "ran ${v} from $0 $*"\n`

function setup (pkgVersion) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-launcher-'))
  const pkg = path.join(root, 'pkg'); const home = path.join(root, 'home'); const bin = path.join(root, 'bin')
  for (const d of [pkg, home, bin]) fs.mkdirSync(d)
  const put = (v) => {
    fs.writeFileSync(path.join(pkg, 'dotrino-vaultd'), fake(v), { mode: 0o755 })
    fs.writeFileSync(path.join(pkg, 'dotrino-vault'), '#!/bin/sh\nexec "$(dirname "$0")/dotrino-vaultd" --ctl "$@"\n', { mode: 0o755 })
    fs.writeFileSync(path.join(pkg, 'VERSION'), v + '\n')
  }
  put(pkgVersion)
  const script = fs.readFileSync(LAUNCHER, 'utf8').replace(/^PKG=.*$/m, `PKG=${pkg}`)
  assert.ok(script.includes(`PKG=${pkg}`), 'el lanzador declara PKG en una línea propia')
  for (const n of ['dotrino-vaultd', 'dotrino-vault']) fs.writeFileSync(path.join(bin, n), script, { mode: 0o755 })
  const run = (name, ...args) => execFileSync('sh', [path.join(bin, name), ...args], { env: { ...process.env, HOME: home }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
  const app = userBinDir(home)
  return { home, app, put, run, userVersion: () => execFileSync('sh', [path.join(app, 'dotrino-vaultd'), '--ctl', 'version'], { encoding: 'utf8' }).trim(), done: () => fs.rmSync(root, { recursive: true, force: true }) }
}

test('la primera vez copia la bóveda a la carpeta del usuario y la corre DESDE AHÍ', () => {
  const s = setup('1.0.0')
  const out = s.run('dotrino-vaultd', 'hola')
  assert.match(out, new RegExp(`ran 1\\.0\\.0 from ${s.app}/dotrino-vaultd hola`))
  // Es exactamente la carpeta que la bóveda reconoce como instalación de usuario (se actualiza sola).
  assert.equal(isUserInstall(path.join(s.app, 'dotrino-vaultd'), s.home), true)
  assert.equal(s.run('dotrino-vault', 'version').trim(), 'dotrino-vault 1.0.0', 'el CLI también sale de la copia del usuario')
  s.done()
})

test('un paquete MÁS NUEVO repone la copia del usuario', () => {
  const s = setup('1.0.0')
  s.run('dotrino-vault', 'version')
  s.put('1.2.0')
  assert.equal(s.run('dotrino-vault', 'version').trim(), 'dotrino-vault 1.2.0')
  s.done()
})

test('si la bóveda ya se actualizó sola y va POR DELANTE del paquete, el paquete no la pisa', () => {
  const s = setup('1.0.0')
  s.run('dotrino-vault', 'version')
  fs.writeFileSync(path.join(s.app, 'dotrino-vaultd'), fake('1.10.0'), { mode: 0o755 })   // se actualizó sola
  s.put('1.9.0')                                                                           // el paquete llega después, más viejo
  assert.equal(s.run('dotrino-vault', 'version').trim(), 'dotrino-vault 1.10.0', '1.10 es más nueva que 1.9: no es orden alfabético')
  assert.equal(s.userVersion(), 'dotrino-vault 1.10.0')
  s.done()
})

test('una copia que no arranca se repone, y se dice', () => {
  const s = setup('1.0.0')
  s.run('dotrino-vault', 'version')
  fs.writeFileSync(path.join(s.app, 'dotrino-vaultd'), '#!/bin/sh\nexit 1\n', { mode: 0o755 })
  s.put('1.0.1')
  const r = spawnSync('sh', [path.join(path.dirname(s.home), 'bin', 'dotrino-vault'), 'version'], { env: { ...process.env, HOME: s.home }, encoding: 'utf8' })
  assert.match(r.stderr, /does not start; replacing it with 1\.0\.1/)
  assert.equal(r.stdout.trim(), 'dotrino-vault 1.0.1')
  assert.equal(s.userVersion(), 'dotrino-vault 1.0.1')
  s.done()
})

test('los dos paquetes llevan el lanzador, el binario fuera de /usr/bin y la unidad que crea la carpeta', () => {
  const read = (f) => fs.readFileSync(fileURLToPath(new URL('../packaging/' + f, import.meta.url)), 'utf8')
  for (const f of ['build-deb.sh', 'build-rpm.sh']) {
    const s = read(f)
    assert.match(s, /pkg-launcher\.sh/, f)
    assert.match(s, /usr\/lib\/dotrino-vault\/dotrino-vaultd/, f)
    assert.match(s, /dotrino-vault-dir\.service/, f)
  }
  // Sin esa unidad, systemd no arranca la bóveda en un usuario nuevo (226/NAMESPACE).
  const unit = read('dotrino-vault.system.service')
  assert.match(unit, /Requires=dotrino-vault-dir\.service/)
  assert.match(unit, /After=.*dotrino-vault-dir\.service/)
})
