/**
 * LA LISTA DE BLOQUEADOS (`src/blocked.js`): se guarda cifrada, se carga una vez y un
 * archivo que no se puede leer NO es «nadie bloqueado».
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openBlocked, BLOCKED_FILE } from '../src/blocked.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'blocked-'))
const atRest = { encrypt: (t) => 'enc.' + Buffer.from(t).toString('base64'), decrypt: (t) => t.startsWith('enc.') ? Buffer.from(t.slice(4), 'base64').toString() : t }

test('bloquear, listar, desbloquear; y lo escrito no va en claro', () => {
  const dir = tmp()
  let t = 1000
  const b = openBlocked({ dir, atRest, now: () => t })
  assert.deepEqual(b.list(), [])
  const e = b.block({ pub: 'PUB-A', deviceId: 'AAAA-0001', label: 'portátil', by: 'BBBB-0002', reason: 'bad-code' })
  assert.equal(e.since, 1000)
  assert.ok(b.has('PUB-A'))
  t = 2000
  assert.equal(b.block({ pub: 'PUB-A' }).since, 1000, 'bloquear dos veces no mueve el «desde cuándo»')
  assert.deepEqual(b.pubs(), ['PUB-A'])
  const raw = fs.readFileSync(path.join(dir, BLOCKED_FILE), 'utf8')
  assert.ok(raw.startsWith('enc.') && !raw.includes('PUB-A'), 'cifrado en reposo')
  assert.equal((fs.statSync(path.join(dir, BLOCKED_FILE)).mode & 0o777), 0o600)
  // Otra instancia lee lo mismo.
  assert.deepEqual(openBlocked({ dir, atRest }).list()[0].deviceId, 'AAAA-0001')
  assert.equal(b.unblock('PUB-A'), true)
  assert.equal(b.unblock('PUB-A'), false)
  assert.deepEqual(openBlocked({ dir, atRest }).list(), [])
})

test('un archivo ilegible lanza, no vacía la lista', () => {
  const dir = tmp()
  fs.writeFileSync(path.join(dir, BLOCKED_FILE), 'enc.' + Buffer.from('{"v":7}').toString('base64'))
  assert.throws(() => openBlocked({ dir, atRest }), (e) => e.code === 'blocked-unreadable')
  fs.writeFileSync(path.join(dir, BLOCKED_FILE), 'esto no es json')
  assert.throws(() => openBlocked({ dir, atRest }), (e) => e.code === 'blocked-unreadable')
})
