/**
 * Render headless de la TUI: dibuja cada pantalla en muchos estados (incluidos
 * vacíos/nulos, modo entrada, confirmación y emparejamiento) con un `term` falso.
 * No prueba la interacción; prueba que el dibujo NUNCA lanza y respeta el alto y
 * el ancho del terminal (que es donde se rompen las TUIs).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeTheme, widthOf, trunc } from '../src/tui/term.js'
import { __test as V } from '../src/tui/app.js'

function fakeTerm (cols = 80, rows = 24) {
  let last = []
  return {
    t: makeTheme(), // sin TTY => sin color (texto plano)
    size: () => ({ cols, rows }),
    // Reproduce el recorte del term real (única fuente de recorte, term.js).
    render: (lines) => { last = lines.map((l) => trunc(l ?? '', cols)) },
    get last () { return last }
  }
}

function baseState (over = {}) {
  return {
    screen: 'menu',
    sel: { menu: 0, profiles: 0, devices: 0, secrets: 0 },
    scroll: {},
    profiles: { current: 'p1', profiles: [{ id: 'p1', name: 'Perfil 1', protected: false, locked: false, current: true, fingerprint: 'fp1' }] },
    devices: { issued: [], revoked: [] },
    secrets: {},
    pending: null,
    pairing: null,
    state: { version: 'test' },
    daemonUp: true,
    busy: null,
    flash: null,
    input: null,
    confirm: null,
    ...over
  }
}

function assertClean (term, cols, rows) {
  const lines = term.last
  assert.equal(lines.length, rows, 'devuelve exactamente `rows` líneas')
  for (const l of lines) assert.ok(widthOf(l) <= cols, `línea no excede ${cols}: ${JSON.stringify(l)}`)
  // Las barras (header/ayuda) ocupan TODO el ancho.
  assert.equal(widthOf(lines[0]), cols, 'header bar llena el ancho')
  assert.equal(widthOf(lines[rows - 1]), cols, 'help bar llena el ancho')
}

test('render de todas las pantallas no lanza y respeta el tamaño', () => {
  for (const [cols, rows] of [[80, 24], [40, 12], [120, 40], [30, 10]]) {
    for (const screen of ['menu', 'profiles', 'devices', 'secrets', 'pairing']) {
      const term = fakeTerm(cols, rows)
      const st = baseState({ screen })
      if (screen === 'pairing') st.pairing = { url: 'https://profile.dotrino.com/#vault=AAAA', payload: '{"v":2,"token":"tok"}', expiresAt: Date.now() + 200000 }
      V.render(term, st)
      assertClean(term, cols, rows)
    }
  }
})

test('render con datos ricos + modos (input/confirm/flash/busy)', () => {
  const rich = {
    profiles: {
      current: 'p2',
      profiles: [
        { id: 'p1', name: 'Personal', protected: true, locked: true, current: false, fingerprint: 'aaaa1111' },
        { id: 'p2', name: 'Trabajo', protected: true, locked: false, current: true, fingerprint: 'bbbb2222' },
        { id: 'p3', name: '', protected: false, locked: false, current: false, fingerprint: 'cccc3333' }
      ]
    },
    devices: {
      issued: [
        { deviceId: 'AB12-CD34', label: 'móvil 🔒', scope: ['vault:sign', 'vault:read', 'vault:store'], exp: Date.now() + 8.64e7, nonce: 'n1' },
        { deviceId: 'EF56-7890', label: '', scope: ['vault:secrets:proxy'], exp: null, nonce: 'n2' }
      ],
      revoked: [{ nonce: 'n0' }]
    },
    secrets: { proxy: ['TURN_KEY_ID', 'TURN_SECRET'], geo: ['API_TOKEN'] }
  }
  const modes = [
    { screen: 'profiles', ...rich },
    { screen: 'devices', ...rich, pending: { deviceId: 'ZZ99-YY88' } },
    { screen: 'secrets', ...rich },
    { screen: 'secrets', ...rich, input: { label: 'Valor', value: 'topsecret', mask: true, hint: 'no se muestra' } },
    { screen: 'devices', ...rich, confirm: { text: '¿Revocar AB12-CD34?' } },
    { screen: 'menu', ...rich, flash: { text: 'Guardado', kind: 'ok', at: Date.now() } },
    { screen: 'menu', ...rich, flash: { text: 'Error grave', kind: 'danger', at: Date.now() } },
    { screen: 'profiles', ...rich, busy: 'Cargando…' }
  ]
  for (const over of modes) {
    const term = fakeTerm(80, 24)
    V.render(term, baseState(over))
    assertClean(term, 80, 24)
  }
})

test('terminal muy pequeño: no lanza y no desborda', () => {
  for (const [cols, rows] of [[20, 6], [10, 4], [80, 8]]) {
    const term = fakeTerm(cols, rows)
    V.render(term, baseState({ screen: 'profiles' }))
    assert.ok(term.last.length <= Math.max(rows, 2))
    for (const l of term.last) assert.ok(widthOf(l) <= cols)
  }
})

test('render sin datos cargados todavía (todo null)', () => {
  const term = fakeTerm(80, 24)
  const st = baseState({ profiles: null, devices: null, secrets: null })
  for (const screen of ['menu', 'profiles', 'devices', 'secrets']) {
    st.screen = screen
    V.render(term, st)
    assertClean(term, 80, 24)
  }
})
