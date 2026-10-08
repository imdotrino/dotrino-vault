/**
 * QUÉ APROBADORES PUEDEN RECIBIR AVISOS (`src/notifiable.js`): lo dice cada uno, caduca, y
 * un archivo que no se puede leer NO es «nadie puede». Es un dato que se enseña: no decide.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openNotifiable, NOTIFIABLE_FILE, NOTIFIABLE_TTL_MS } from '../src/notifiable.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'notifiable-'))
const atRest = { encrypt: (t) => 'enc.' + Buffer.from(t).toString('base64'), decrypt: (t) => t.startsWith('enc.') ? Buffer.from(t.slice(4), 'base64').toString() : t }

test('quien lo dice cuenta, quien lo apaga deja de contar, y lo escrito no va en claro', () => {
  const dir = tmp()
  let t = 1000
  const n = openNotifiable({ dir, atRest, now: () => t })
  assert.equal(n.since('PUB-A'), null, 'sin declarar no cuenta')
  n.declare('PUB-A', true)
  assert.equal(n.since('PUB-A'), 1000)
  const raw = fs.readFileSync(path.join(dir, NOTIFIABLE_FILE), 'utf8')
  assert.ok(raw.startsWith('enc.') && !raw.includes('PUB-A'), 'cifrado en reposo')
  assert.equal((fs.statSync(path.join(dir, NOTIFIABLE_FILE)).mode & 0o777), 0o600)
  assert.equal(openNotifiable({ dir, atRest, now: () => t }).since('PUB-A'), 1000, 'sobrevive a un reinicio')
  n.declare('PUB-A', undefined)
  assert.equal(n.since('PUB-A'), 1000, 'un cliente que no dice nada no borra lo dicho')
  n.declare('PUB-A', false)
  assert.equal(n.since('PUB-A'), null)
  assert.equal(openNotifiable({ dir, atRest, now: () => t }).since('PUB-A'), null)
})

test('caduca: una app que deja de renovarlo sale sola', () => {
  const dir = tmp()
  let t = 1000
  const n = openNotifiable({ dir, atRest, now: () => t })
  n.declare('PUB-A', true)
  t = 1000 + NOTIFIABLE_TTL_MS - 1
  assert.equal(n.since('PUB-A'), 1000)
  t = 1000 + NOTIFIABLE_TTL_MS
  assert.equal(n.since('PUB-A'), null)
  n.declare('PUB-A', true)
  assert.equal(n.since('PUB-A'), t, 'y renovarlo lo vuelve a contar')
})

test('un archivo ilegible no es «nadie puede recibir avisos»: se lanza', () => {
  const dir = tmp()
  fs.writeFileSync(path.join(dir, NOTIFIABLE_FILE), 'enc.' + Buffer.from('{no es json').toString('base64'))
  assert.throws(() => openNotifiable({ dir, atRest }), (e) => e.code === 'notifiable-unreadable')
  fs.writeFileSync(path.join(dir, NOTIFIABLE_FILE), 'enc.' + Buffer.from(JSON.stringify({ v: 9 })).toString('base64'))
  assert.throws(() => openNotifiable({ dir, atRest }), (e) => e.code === 'notifiable-unreadable')
})
