/**
 * LA TUI Y LOS AJUSTES DE LA BÓVEDA: se entra con `s` desde Bóvedas, la regla se lee como una
 * frase con su estado, Enter la cambia, y un ajuste ilegible se DICE (no se pinta apagado).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { makeTheme, widthOf, trunc } from '../src/tui/term.js'
import { __test as V } from '../src/tui/app.js'
import { readSettings, writeSettings, SETTINGS_FILE } from '../src/settings.js'

function fakeTerm (cols = 100, rows = 24) {
  let last = []
  return { t: makeTheme(), size: () => ({ cols, rows }), render: (lines) => { last = lines.map((l) => trunc(l ?? '', cols)) }, get last () { return last } }
}
const estado = (over = {}) => ({
  lang: 'es', screen: 'profiles',
  sel: { profiles: 0, devices: 0, secrets: 0, caps: 0, devvars: 0, doors: 0, settings: 0 },
  scroll: {},
  profiles: { current: 'p1', profiles: [{ id: 'p1', name: 'Perfil 1', protected: false, locked: false, current: true, fingerprint: 'fp1', doors: [] }] },
  devices: { issued: [], revoked: [] }, secrets: { ns: {}, dev: [] },
  state: { version: 'test' }, daemonUp: true, busy: null, flash: null, input: null, confirm: null,
  unlockedHere: new Set(), sessionPwd: new Map(),
  settingsDir: fs.mkdtempSync(path.join(os.tmpdir(), 'tui-settings-')),
  ...over
})
const tecla = (ch) => ({ name: 'char', ch })
const texto = (rows) => rows.map((r) => r.text).join('\n')

test('`s` entra a los ajustes, dice la regla como frase, y Esc vuelve', async () => {
  const st = estado()
  const term = fakeTerm()
  await V.onKeyProfiles(term, st, tecla('s'))
  assert.equal(st.screen, 'settings')
  const rows = texto(V.settingsRows(st, makeTheme()))
  assert.match(rows, /Esta bóveda se actualiza sola, sin pedir aprobación\./, 'por defecto se actualiza sola')
  assert.match(rows, /todos los perfiles/, 'dice que es global')
  assert.match(rows, /ningún perfil tiene un aparato con «aprueba», la bóveda se actualiza sola/)
  V.render(term, st)
  assert.match(term.last[3], /Ajustes de esta bóveda/)
  for (const [cols, nrows] of [[100, 24], [30, 10]]) {
    const chico = fakeTerm(cols, nrows)
    V.render(chico, st)
    assert.equal(chico.last.length, nrows)
    for (const l of chico.last) assert.ok(widthOf(l) <= cols)
  }
  await V.onKeySettings(term, st, { name: 'escape' })
  assert.equal(st.screen, 'profiles')
})

test('Enter (o espacio) alterna el ajuste y lo guarda', async () => {
  const st = estado()
  const term = fakeTerm()
  await V.onKeyProfiles(term, st, tecla('s'))
  await V.onKeySettings(term, st, { name: 'enter' })
  assert.equal(readSettings(st.settingsDir).updateApproval, true)
  assert.match(texto(V.settingsRows(st, makeTheme())), /Esta bóveda pide aprobación antes de actualizarse\./)
  assert.match(st.flash.text, /pide aprobación/)
  await V.onKeySettings(term, st, tecla(' '))
  assert.equal(readSettings(st.settingsDir).updateApproval, false)
  assert.match(texto(V.settingsRows(st, makeTheme())), /se actualiza sola/)
})

test('un ajuste ilegible se dice, no se pinta apagado; Enter lo vuelve a guardar pidiendo aprobación', async () => {
  const st = estado()
  writeSettings(st.settingsDir, { updateApproval: true })
  fs.writeFileSync(path.join(st.settingsDir, SETTINGS_FILE), 'basura')
  await V.onKeyProfiles(fakeTerm(), st, tecla('s'))
  const rows = texto(V.settingsRows(st, makeTheme()))
  assert.match(rows, /no se pudo leer/)
  assert.doesNotMatch(rows, /se actualiza sola, sin pedir/)
  await V.onKeySettings(fakeTerm(), st, { name: 'enter' })
  assert.equal(readSettings(st.settingsDir).updateApproval, true)
})

test('en inglés dice lo mismo', async () => {
  const st = estado({ lang: 'en' })
  await V.onKeyProfiles(fakeTerm(), st, tecla('s'))
  assert.match(texto(V.settingsRows(st, makeTheme())), /This vault updates on its own, without asking for approval\./)
})
