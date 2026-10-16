/**
 * LA VENTANA DE ESCRITORIO (`desktop/`) PINTA LO MISMO QUE LA TUI: el puente (`gui.js`) corre la
 * sesión de la TUI y le manda a la ventana el modelo de cada pantalla. Aquí se comprueba el
 * modelo, el paso de estilos a tramos, el canal (una línea JSON por mensaje) y las piezas de
 * `service.js` que arrancan la bóveda en Windows y macOS.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { PassThrough } from 'node:stream'

// La carpeta de datos se fija ANTES de importar: `vaultControl` la lee al cargar. Vacía = sin daemon.
process.env.DOTRINO_VAULT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gui-bridge-'))

const { makeTheme } = await import('../src/tui/term.js')
const { viewModel, selectRow, __test: V } = await import('../src/tui/app.js')
const { spans, runGuiBridge } = await import('../src/tui/gui.js')
const service = await import('../src/service.js')

const estado = (over = {}) => ({
  lang: 'es', screen: 'profiles',
  sel: { profiles: 0, devices: 0, secrets: 0, caps: 0, devvars: 0, doors: 0, settings: 0 },
  scroll: {},
  profiles: { current: 'p1', profiles: [
    { id: 'p1', name: 'Perfil 1', protected: false, locked: false, current: true, fingerprint: 'fp1', doors: [] },
    { id: 'p2', name: 'Trabajo', protected: true, locked: true, current: false, fingerprint: 'fp2', doors: [] }
  ] },
  devices: { issued: [], revoked: [] }, secrets: { ns: {}, dev: [] },
  state: { version: 'test' }, daemonUp: true, busy: null, flash: null, input: null, confirm: null,
  unlockedHere: new Set(), sessionPwd: new Map(),
  settingsDir: fs.mkdtempSync(path.join(os.tmpdir(), 'gui-settings-')),
  ...over
})

test('los estilos de la TUI pasan a tramos con su color y su negrita', () => {
  const t = makeTheme({ color: true })
  const out = spans(`${t.bold('A')} ${t.muted('b')} ${t.warn('c')}${t.title('T')}`)
  assert.deepEqual(out, [
    { t: 'A', b: true }, { t: ' ' }, { t: 'b', c: 'muted' }, { t: ' ' }, { t: 'c', c: 'warn' }, { t: 'T', c: 'title', b: true }
  ])
  assert.deepEqual(spans('sin estilo'), [{ t: 'sin estilo' }])
  assert.deepEqual(spans(''), [])
})

test('el modelo de Bóvedas trae las MISMAS filas que la TUI, la seleccionada y sus acciones', () => {
  const st = estado()
  const t = makeTheme({ color: true })
  const vm = viewModel(st, t)
  const tui = V.profileRows(st, t)
  assert.equal(vm.rows.length, tui.length)
  assert.deepEqual(vm.rows.map((r) => r.text), tui.map((r) => r.text), 'las filas son las de la TUI, carácter a carácter')
  assert.deepEqual(vm.rows.map((r) => r.idx), [0, 1])
  assert.equal(vm.selected, 0)
  assert.equal(vm.title, 'Bóvedas')
  assert.equal(vm.tabs, null)
  assert.ok(vm.help.includes('p emparejar'), 'las acciones son las de la ayuda de la TUI')
  assert.equal(vm.active.name, 'Perfil 1')
  // Pulsar una fila en la ventana la selecciona en la sesión.
  assert.equal(selectRow(st, 1), true)
  assert.equal(viewModel(st, t).selected, 1)
})

test('dentro de una bóveda, las pestañas; con una pregunta abierta, la pregunta y no la ayuda', () => {
  const t = makeTheme({ color: true })
  const vm = viewModel(estado({ screen: 'devices' }), t)
  assert.deepEqual(vm.tabs.map((x) => x.key), ['devices', 'secrets', 'logins', 'me'])
  assert.equal(vm.tabs.find((x) => x.active).key, 'devices')
  const q = viewModel(estado({ input: { label: 'Nombre', hint: 'h', mask: true, value: '', file: true } }), t)
  assert.deepEqual(q.input, { label: 'Nombre', hint: 'h', mask: true, value: '', file: true })
  assert.deepEqual(q.help, [])
  const c = viewModel(estado({ confirm: { text: '¿Seguro?', defaultYes: false } }), t)
  assert.deepEqual(c.confirm, { text: '¿Seguro?', defaultYes: false })
})

test('emparejar: el QR va como enlace (la ventana lo dibuja) y el texto sin el QR de caracteres', () => {
  const st = estado({ screen: 'pairing', pairing: { url: 'https://vault.dotrino.com/d#v=abc', b64: 'abc', expiresAt: Date.now() + 300000 } })
  const vm = viewModel(st, makeTheme({ color: true }))
  assert.equal(vm.qr, 'https://vault.dotrino.com/d#v=abc')
  assert.equal(vm.code, 'abc')
  assert.ok(!vm.body.some((l) => /[█▀▄]/.test(l)), 'sin bloques del QR de terminal')
  assert.ok(vm.body.some((l) => l.includes('https://vault.dotrino.com/d#v=abc')))
})

test('el puente: sin daemon enseña la pantalla de arrancarlo, y al cerrarse la entrada se despide', async () => {
  const input = new PassThrough()
  const output = new PassThrough()
  const lines = []
  let buf = ''
  output.on('data', (d) => { buf += d; let n; while ((n = buf.indexOf('\n')) >= 0) { lines.push(JSON.parse(buf.slice(0, n))); buf = buf.slice(n + 1) } })
  const done = runGuiBridge({ input, output })
  await new Promise((r) => setTimeout(r, 200))
  input.write('{"key":{"name":"char","ch":"l"}}\n')
  await new Promise((r) => setTimeout(r, 200))
  input.end()
  await done
  const views = lines.filter((m) => m.t === 'view')
  assert.ok(views.length >= 2)
  assert.equal(views[0].v.down, true)
  assert.ok(views[0].v.help.some((h) => h.key === 'S'), 'ofrece arrancar el servicio')
  assert.notEqual(views[0].v.lang, views.at(-1).v.lang, '`l` cambia el idioma también aquí')
  assert.deepEqual(lines.at(-1), { t: 'bye', relaunch: false })
})

test('macOS: el LaunchAgent arranca el daemon al entrar y lo relanza si se cae', () => {
  const plist = service.launchAgentPlist({ cmd: '/Applications/Dotrino Vault.app/Contents/MacOS/dotrino-vaultd', args: [] }, '/tmp/v & log')
  assert.match(plist, /<string>com\.dotrino\.vault<\/string>/)
  assert.match(plist, /<string>\/Applications\/Dotrino Vault\.app\/Contents\/MacOS\/dotrino-vaultd<\/string>/)
  assert.match(plist, /<key>RunAtLoad<\/key>\s*<true\/>/)
  assert.match(plist, /<key>SuccessfulExit<\/key>\s*<false\/>/)
  assert.match(plist, /\/tmp\/v &amp; log/, 'escapa el XML')
})

test('Windows: la entrada de inicio de sesión lanza el daemon sin consola', () => {
  const line = service.windowsRunLine({ cmd: 'C:\\Program Files\\x\\node.exe', args: ['C:\\a b\\dotrino-vaultd.js'] })
  assert.equal(line, 'conhost.exe --headless "C:\\Program Files\\x\\node.exe" "C:\\a b\\dotrino-vaultd.js"')
})

test('ajustes: arrancar al iniciar sesión se ve como frase y Enter lo cambia', async () => {
  let on = false
  const api = {
    autostartStatus: async () => ({ on, how: 'run-key' }),
    enableAutostart: async () => { on = true; return { ok: true } },
    disableAutostart: async () => { on = false; return { ok: true } }
  }
  const st = estado({ autostartApi: api })
  const term = { t: makeTheme(), size: () => ({ cols: 100, rows: 30 }), render: () => {} }
  await V.onKeyProfiles(term, st, { name: 'char', ch: 's' })
  const texto = () => V.settingsRows(st, makeTheme()).map((r) => r.text).join('\n')
  assert.match(texto(), /no arranca sola/)
  await V.onKeySettings(term, st, { name: 'down' })
  await V.onKeySettings(term, st, { name: 'enter' })
  assert.equal(on, true)
  assert.match(texto(), /arranca sola al iniciar sesión/)
  assert.match(st.flash.text, /arranca sola/)
  // La primera fila sigue siendo la de actualizar: Enter ahí no toca el arranque.
  await V.onKeySettings(term, st, { name: 'up' })
  await V.onKeySettings(term, st, { name: 'enter' })
  assert.equal(on, true)
})

test('ajustes en Linux sin la unidad de systemd: se dice cómo conseguirlo, sin casilla muerta', async () => {
  const st = estado({ settings: { updateApproval: false }, autostart: { on: false, how: 'none' } })
  const rows = V.settingsRows(st, makeTheme())
  assert.ok(rows.some((r) => /instálala con el paquete/.test(r.text) && !r.sel))
  assert.equal(rows.filter((r) => r.sel).length, 1)
})

test('la ventana sale con la versión de la bóveda (una sola versión para el producto)', () => {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version
  const cargo = fs.readFileSync(new URL('../desktop/Cargo.toml', import.meta.url), 'utf8').match(/^version = "(.*)"/m)[1]
  assert.equal(cargo, pkg, 'al subir la versión en package.json, súbela también en desktop/Cargo.toml')
})
