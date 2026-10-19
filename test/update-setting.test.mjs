/**
 * EL AJUSTE DE ACTUALIZACIÓN (`src/settings.js`): por defecto la bóveda se actualiza sola, y
 * pedir aprobación es algo que el dueño enciende. Un ajuste que existe y no se puede leer NO
 * es «el valor por defecto» — eso sería saltarse la aprobación que pidió.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { readSettings, writeSettings, SETTINGS_FILE } from '../src/settings.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'settings-'))

test('sin ajuste, se actualiza sola', () => {
  assert.deepEqual(readSettings(tmp()), { updateApproval: false })
})

test('lo que se enciende se lee, se puede apagar, y no queda en claro', () => {
  const dir = tmp()
  writeSettings(dir, { updateApproval: true })
  assert.equal(readSettings(dir).updateApproval, true)
  assert.ok(!fs.readFileSync(path.join(dir, SETTINGS_FILE), 'utf8').includes('updateApproval'), 'cifrado en reposo')
  writeSettings(dir, { updateApproval: false })
  assert.equal(readSettings(dir).updateApproval, false)
})

test('un ajuste ilegible no es «sin ajuste»: se lanza', () => {
  const dir = tmp()
  writeSettings(dir, { updateApproval: true })
  fs.writeFileSync(path.join(dir, SETTINGS_FILE), 'basura')
  assert.throws(() => readSettings(dir), (e) => e.code === 'settings-unreadable')
  fs.writeFileSync(path.join(dir, SETTINGS_FILE), '')
  assert.throws(() => readSettings(dir), (e) => e.code === 'settings-unreadable')
})

test('solo se guarda sí o no', () => {
  assert.throws(() => writeSettings(tmp(), { updateApproval: 'on' }), (e) => e.code === 'bad-setting')
})
