/**
 * EL RESPALDO EN LA TUI (y por lo tanto en la ventana, que pinta el mismo modelo).
 *
 * Lo que se prueba es lo que decide la pantalla sin hablar con el daemon: marcar cajones,
 * decidir cada choque, y que no se importe nada mientras quede uno sin decidir.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

process.env.DOTRINO_VAULT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'tui-respaldo-'))

const { makeTheme } = await import('../src/tui/term.js')
const { viewModel, __test: V } = await import('../src/tui/app.js')

const t = makeTheme()
const term = { t, gui: () => {}, size: () => ({ cols: 100, rows: 40 }), render: () => {} }
const enter = { name: 'enter' }
const down = { name: 'down' }
const key = (ch) => ({ name: 'char', ch })

const estado = (over = {}) => ({
  lang: 'es', screen: 'backup', sel: { backup: 0, backupplan: 0 }, scroll: {},
  profiles: { current: 'p1', profiles: [{ id: 'p1', name: 'P', current: true, doors: [] }] },
  state: { version: 'test' }, daemonUp: true, members: [{ id: 'AB12-CD34', pub: 'PUB-B' }],
  ...over
})

test('respaldo: se marcan los cajones con Enter, y sin marcar ninguno van todos', async () => {
  const st = estado({ backup: { drawers: [{ owner: 'ns:proxy', count: 2 }, { owner: 'passwords', count: 5 }], chosen: new Set() } })
  assert.ok(V.backupRows(st, t).some((r) => /se exportan todos/.test(r.text)))
  await V.onKeyBackup(term, st, enter)
  assert.deepEqual([...st.backup.chosen], ['ns:proxy'])
  await V.onKeyBackup(term, st, down)
  await V.onKeyBackup(term, st, enter)
  assert.deepEqual([...st.backup.chosen].sort(), ['ns:proxy', 'passwords'])
  await V.onKeyBackup(term, st, enter)
  assert.deepEqual([...st.backup.chosen], ['ns:proxy'])
  // La ventana ve las mismas filas, con las acciones de la pantalla.
  const vm = viewModel(st, makeTheme({ color: true }))
  assert.equal(vm.title, 'Respaldo')
  assert.ok(vm.help.includes('g exportar') && vm.help.includes('i importar'))
})

test('respaldo: exportar pide dónde guardar con el diálogo de GUARDAR', async () => {
  const st = estado({ backup: { drawers: [{ owner: 'ns:proxy', count: 2 }], chosen: new Set() } })
  await V.onKeyBackup(term, st, key('g'))
  assert.equal(st.input.file, true)
  assert.equal(st.input.save, true)
  assert.match(st.input.value, /dotrino-vault-backup-\d{4}-\d{2}-\d{2}\.json$/)
})

const plan = () => ({
  drawers: [{
    from: 'ns:proxy', to: 'ns:proxy', status: 'ok',
    items: [{ key: 'A', status: 'new' }, { key: 'B', status: 'conflict' }, { key: 'C', status: 'conflict' }]
  }],
  counts: { new: 1, same: 0, conflict: 2, skipped: 0 }
})

test('respaldo: cada choque se decide, y con uno sin decidir no se importa', async () => {
  const st = estado({ screen: 'backupplan', backupPlan: { path: '/tmp/r.json', file: {}, pwd: 'x', plan: plan(), map: {}, decisions: {} } })
  await V.onKeyBackupPlan(term, st, key('g'))
  assert.equal(st.confirm, undefined, 'preguntó si importar con choques sin decidir')
  assert.equal(st.flash.kind, 'warn')
  // Filas elegibles: «Todos los choques», el cajón, B, C.
  st.sel.backupplan = 2
  await V.onKeyBackupPlan(term, st, enter)
  assert.equal(st.backupPlan.decisions['ns:proxy B'], 'keep')
  await V.onKeyBackupPlan(term, st, enter)
  assert.equal(st.backupPlan.decisions['ns:proxy B'], 'replace')
  await V.onKeyBackupPlan(term, st, key('g'))
  assert.equal(st.confirm, undefined, 'C sigue sin decidir')
})

test('respaldo: «Todos los choques» decide todos de una vez', async () => {
  const st = estado({ screen: 'backupplan', backupPlan: { path: '/tmp/r.json', file: {}, pwd: 'x', plan: plan(), map: {}, decisions: {} } })
  st.sel.backupplan = 0
  await V.onKeyBackupPlan(term, st, enter)
  assert.deepEqual(st.backupPlan.decisions, { 'ns:proxy B': 'keep', 'ns:proxy C': 'keep' })
  await V.onKeyBackupPlan(term, st, enter)
  assert.deepEqual(st.backupPlan.decisions, { 'ns:proxy B': 'replace', 'ns:proxy C': 'replace' })
  await V.onKeyBackupPlan(term, st, key('g'))
  assert.match(st.confirm.text, /Importar 3 cambio/)
})

test('respaldo: Esc en el plan lo descarta (y la contraseña con él)', async () => {
  const st = estado({ screen: 'backupplan', backup: { drawers: [], chosen: new Set() }, backupPlan: { path: '/tmp/r.json', file: {}, pwd: 'x', plan: plan(), map: {}, decisions: {} } })
  await V.onKeyBackupPlan(term, st, { name: 'escape' })
  assert.equal(st.backupPlan, null)
  assert.equal(st.screen, 'backup')
})
