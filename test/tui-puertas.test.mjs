/**
 * LA TUI Y LAS PUERTAS DEL PERFIL: ver con qué se abre cada bóveda, entrar a sus llaves, quitar
 * una con confirmación, y abrir sin llave enchufada. Sin daemon y sin YubiKey: lo que la llave
 * hace lo cubren `puertas.test.mjs` y `puertas.e2e.test.mjs`; aquí se prueba la pantalla.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeTheme, widthOf, trunc } from '../src/tui/term.js'
import { __test as V } from '../src/tui/app.js'

function fakeTerm (cols = 90, rows = 24) {
  let last = []
  return {
    t: makeTheme(),
    size: () => ({ cols, rows }),
    render: (lines) => { last = lines.map((l) => trunc(l ?? '', cols)) },
    get last () { return last }
  }
}

const PWD = { id: 'password', kind: 'password' }
const TOQUE = { id: 'aa11', kind: 'fido2', credId: 'Y3JlZA==', hsalt: 'c2FsdA==', label: 'YubiKey', createdAt: Date.parse('2026-10-05') }
const SIN_TOQUE = { id: 'bb22', kind: 'chalresp', challenge: 'ab'.repeat(32), serial: '123', label: 'YubiKey 123' }

function estado (perfil, over = {}) {
  const profiles = { current: perfil.id, profiles: [perfil] }
  return {
    lang: 'es',
    screen: 'profiles',
    sel: { profiles: 0, devices: 0, secrets: 0, caps: 0, devvars: 0, doors: 0 },
    scroll: {},
    profiles,
    devices: { issued: [], revoked: [] },
    secrets: { ns: {}, dev: [] },
    state: { version: 'test' },
    daemonUp: true,
    busy: null,
    flash: null,
    input: null,
    confirm: null,
    unlockedHere: new Set(),
    sessionPwd: new Map(),
    ...over
  }
}
const perfil = (doors, over = {}) => ({ id: 'p1', name: 'Perfil 1', protected: doors.length > 0, locked: false, current: true, fingerprint: 'fp1', doors, ...over })
const tecla = (ch) => ({ name: 'char', ch })
const texto = (rows) => rows.map((r) => r.text).join('\n')

test('la lista de bóvedas dice con qué se abre cada una', () => {
  const st = estado(perfil([PWD, TOQUE]))
  const fila = V.profileRows(st, makeTheme())[0].text
  assert.match(fila, /contraseña o llave \(toque\)/)
  const sin = V.profileRows(estado(perfil([])), makeTheme())[0].text
  assert.match(sin, /sin candado/)
})

test('`y` entra a las llaves de la bóveda, y Esc vuelve', async () => {
  const st = estado(perfil([]))
  const term = fakeTerm()
  await V.onKeyProfiles(term, st, tecla('y'))
  assert.equal(st.screen, 'doors')
  assert.equal(st.doorsFor, 'p1')
  await V.onKeyDoors(term, st, { name: 'escape' })
  assert.equal(st.screen, 'profiles')
})

test('la pantalla de llaves enseña las puertas y lo que se puede añadir, y cabe', () => {
  const st = estado(perfil([PWD, TOQUE, { ...SIN_TOQUE, withPassword: true }]), { screen: 'doors', doorsFor: 'p1' })
  const rows = texto(V.doorRows(st, makeTheme()))
  assert.match(rows, /contraseña/)
  assert.match(rows, /llave \(toque\)\s+YubiKey\s+2026-10-05/)
  assert.match(rows, /llave \(sin toque\) \+ contraseña/)
  for (const accion of ['con toque', 'sin toque', 'con toque y contraseña']) assert.match(rows, new RegExp(`\\+ .*${accion}`))
  for (const [cols, nrows] of [[90, 24], [30, 10]]) {
    const term = fakeTerm(cols, nrows)
    V.render(term, st)
    assert.equal(term.last.length, nrows)
    for (const l of term.last) assert.ok(widthOf(l) <= cols)
  }
})

test('quitar una llave pide confirmación, y la última avisa de que se queda sin candado', async () => {
  const term = fakeTerm()
  const dos = estado(perfil([PWD, TOQUE]), { screen: 'doors', doorsFor: 'p1' })
  dos.sel.doors = 1 // la llave
  await V.onKeyDoors(term, dos, tecla('d'))
  assert.ok(dos.confirm, 'pregunta antes de quitar')
  assert.match(dos.confirm.text, /llave \(toque\)/)
  assert.doesNotMatch(dos.confirm.text, /sin candado/)

  const una = estado(perfil([TOQUE]), { screen: 'doors', doorsFor: 'p1' })
  await V.onKeyDoors(term, una, tecla('d'))
  assert.match(una.confirm.text, /última.*sin candado/)
  una.confirm.onNo()
  assert.equal(una.confirm, null)
})

test('`x` en una bóveda que solo abre con llave no finge quitar una contraseña que no tiene', async () => {
  const st = estado(perfil([TOQUE]))
  await V.onKeyProfiles(fakeTerm(), st, tecla('x'))
  assert.match(st.flash.text, /no tiene contraseña/)
})

test('abrir sin la llave enchufada: con contraseña la pide; sin ella para y dice por qué', async () => {
  // Sin herramientas en el PATH la llave «no está»: es lo mismo que ver la TUI sin YubiKey.
  const path0 = process.env.PATH
  const bin0 = process.env.DOTRINO_HWKEY_BIN
  process.env.PATH = ''
  delete process.env.DOTRINO_HWKEY_BIN
  try {
    let unlocks = 0
    const api = { unlockProfile: async () => { unlocks++ }, listProfiles: async () => ({}) }

    const conClave = perfil([PWD, SIN_TOQUE], { locked: true })
    const a = estado(conClave)
    let entra = 0
    await V.ensureUnlocked(fakeTerm(), a, conClave, () => { entra++ }, null, api)
    assert.ok(a.input, 'cae a la contraseña')
    assert.match(a.input.hint, /La llave no abrió/, 'diciendo por qué')
    assert.equal(entra, 0)

    const soloLlave = perfil([SIN_TOQUE], { locked: true })
    const b = estado(soloLlave)
    await V.ensureUnlocked(fakeTerm(), b, soloLlave, () => { entra++ }, null, api)
    assert.equal(b.input, null, 'no pide una contraseña que no abriría')
    assert.match(b.flash.text, /falta ykinfo/)
    assert.equal(unlocks, 0)
    assert.equal(entra, 0)
  } finally {
    process.env.PATH = path0
    if (bin0 !== undefined) process.env.DOTRINO_HWKEY_BIN = bin0
  }
})
