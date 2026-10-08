/**
 * LO QUE LA BÓVEDA LE CUENTA A QUIEN APRUEBA Y NO ES UN PEDIDO (`src/notices.js`): hoy, que
 * se actualizó. Dura 24 h, va cifrado, y un archivo ilegible no es «no pasó nada».
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openNotices, NOTICES_FILE, NOTICE_TTL_MS } from '../src/notices.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'notices-'))
const atRest = { encrypt: (t) => 'enc.' + Buffer.from(t).toString('base64'), decrypt: (t) => { if (!t.startsWith('enc.')) throw new Error('not encrypted'); return Buffer.from(t.slice(4), 'base64').toString() } }

test('lo apuntado se lista, sobrevive a un reinicio y no va en claro', () => {
  const dir = tmp()
  const t = 1000
  const n = openNotices({ dir, atRest, now: () => t })
  assert.deepEqual(n.list(), [])
  const a = n.updated({ version: '0.147.0', from: '0.146.0' })
  assert.deepEqual({ ...a, id: 'x' }, { id: 'x', ev: 'updated', product: '@dotrino/vaultd', version: '0.147.0', from: '0.146.0', ts: 1000 })
  const b = n.updated({ version: '1.2.3', product: '@dotrino/terminal-agent', deviceId: 'AB12-CD34', label: 'portátil' })
  assert.deepEqual([b.product, b.deviceId, b.label, b.from], ['@dotrino/terminal-agent', 'AB12-CD34', 'portátil', null], 'el de un aparato dice cuál')
  assert.match(a.id, /^[0-9a-f]{16}$/)
  const raw = fs.readFileSync(path.join(dir, NOTICES_FILE), 'utf8')
  assert.ok(raw.startsWith('enc.') && !raw.includes('0.147.0'), 'cifrado en reposo')
  assert.equal((fs.statSync(path.join(dir, NOTICES_FILE)).mode & 0o777), 0o600)
  assert.deepEqual(openNotices({ dir, atRest, now: () => t }).list(), [a, b])
})

test('caduca a las 24 h', () => {
  const dir = tmp()
  let t = 1000
  const n = openNotices({ dir, atRest, now: () => t })
  n.updated({ version: '0.147.0' })
  t += NOTICE_TTL_MS - 1
  assert.equal(n.list().length, 1)
  t += 1
  assert.equal(n.list().length, 0, 'una noticia de ayer ya no se cuenta')
  n.updated({ version: '0.148.0' })
  assert.deepEqual(n.list().map((x) => x.version), ['0.148.0'], 'y lo caducado no se arrastra en el disco')
})

test('un archivo ilegible no es «sin avisos»: se lanza', () => {
  const dir = tmp()
  openNotices({ dir, atRest }).updated({ version: '0.147.0' })
  fs.writeFileSync(path.join(dir, NOTICES_FILE), 'basura')
  assert.throws(() => openNotices({ dir, atRest }), (e) => e.code === 'notices-unreadable')
})

test('sin versión no hay aviso', () => {
  assert.throws(() => openNotices({ dir: tmp(), atRest }).updated({}), (e) => e.code === 'bad-notice')
})
