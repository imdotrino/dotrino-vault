/**
 * LO QUE LA BÓVEDA LE CUENTA A QUIEN APRUEBA Y NO ES UN PEDIDO (`src/notices.js`): hoy, que
 * se actualizó. Dura 24 h, va cifrado, y un archivo ilegible no es «no pasó nada».
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openNotices, NOTICES_FILE, NOTICE_TTL_MS } from '../lib/src/core/notices.js'
import { nodeDisk } from '../src/disk.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'notices-'))
const atRest = { encrypt: (t) => 'enc.' + Buffer.from(t).toString('base64'), decrypt: (t) => { if (!t.startsWith('enc.')) throw new Error('not encrypted'); return Buffer.from(t.slice(4), 'base64').toString() } }

test('lo apuntado se lista, sobrevive a un reinicio y no va en claro', () => {
  const dir = tmp()
  const t = 1000
  const n = openNotices({ disk: nodeDisk(dir, { atRest }), now: () => t })
  assert.deepEqual(n.list(), [])
  const a = n.updated({ version: '0.147.0', from: '0.146.0' })
  assert.deepEqual({ ...a, id: 'x' }, { id: 'x', ev: 'updated', product: '@dotrino/vaultd', version: '0.147.0', from: '0.146.0', ts: 1000 })
  const b = n.updated({ version: '1.2.3', product: '@dotrino/terminal-agent', deviceId: 'AB12-CD34', label: 'portátil' })
  assert.deepEqual([b.product, b.deviceId, b.label, b.from], ['@dotrino/terminal-agent', 'AB12-CD34', 'portátil', null], 'el de un aparato dice cuál')
  assert.match(a.id, /^[0-9a-f]{16}$/)
  const raw = fs.readFileSync(path.join(dir, NOTICES_FILE), 'utf8')
  assert.ok(raw.startsWith('enc.') && !raw.includes('0.147.0'), 'cifrado en reposo')
  assert.equal((fs.statSync(path.join(dir, NOTICES_FILE)).mode & 0o777), 0o600)
  assert.deepEqual(openNotices({ disk: nodeDisk(dir, { atRest }), now: () => t }).list(), [a, b])
})

test('caduca a las 24 h', () => {
  const dir = tmp()
  let t = 1000
  const n = openNotices({ disk: nodeDisk(dir, { atRest }), now: () => t })
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
  openNotices({ disk: nodeDisk(dir, { atRest }) }).updated({ version: '0.147.0' })
  fs.writeFileSync(path.join(dir, NOTICES_FILE), 'basura')
  assert.throws(() => openNotices({ disk: nodeDisk(dir, { atRest }) }), (e) => e.code === 'notices-unreadable')
})

test('sin versión no hay aviso', () => {
  assert.throws(() => openNotices({ disk: nodeDisk(tmp(), { atRest }) }).updated({}), (e) => e.code === 'bad-notice')
})

test('«necesita permisos de administrador» es otro aviso, con las mismas reglas; uno desconocido no entra', () => {
  const n = openNotices({ disk: nodeDisk(tmp(), { atRest }), now: () => 7 })
  const a = n.add('update-needs-root', { version: '0.148.0', from: '0.147.0' })
  assert.deepEqual({ ...a, id: 'x' }, { id: 'x', ev: 'update-needs-root', product: '@dotrino/vaultd', version: '0.148.0', from: '0.147.0', ts: 7 })
  const b = n.add('update-needs-root', { version: '1.3.0', product: '@dotrino/terminal-agent', deviceId: 'AB12-CD34', label: 'servidor' })
  assert.deepEqual([b.ev, b.deviceId, b.label], ['update-needs-root', 'AB12-CD34', 'servidor'])
  assert.throws(() => n.add('whatever', { version: '1.0.0' }), (e) => e.code === 'bad-notice')
})

test('pairing-contested: el incidente lleva los dos aparatos y no pide versión', async () => {
  const { openNotices } = await import('../lib/src/core/notices.js')
  const files = new Map()
  const disk = { atRest: { encrypt: (s) => s, decrypt: (s) => s }, exists: (f) => files.has(f), read: (f) => files.get(f), write: (f, d) => files.set(f, d) }
  const n = openNotices({ disk })
  const it = n.add('pairing-contested', { devices: [{ deviceId: 'AB12-CD34', machine: { os: 'android' } }, { deviceId: 'EF56-7890', machine: null }] })
  assert.equal(it.ev, 'pairing-contested')
  assert.deepEqual(it.devices.map((d) => d.deviceId), ['AB12-CD34', 'EF56-7890'])
  assert.equal(n.list().length, 1)
  assert.throws(() => n.add('pairing-contested', { devices: [{ deviceId: 'x' }] }), { code: 'bad-notice' })
})

test('delivered: un aparato desatendido se llevó claves o una contraseña; pide cajón, aparato y un kind conocido', () => {
  const n = openNotices({ disk: nodeDisk(tmp(), { atRest }), now: () => 9 })
  const a = n.add('delivered', { kind: 'passwords', ns: 'passwords', deviceId: 'AB12-CD34', label: 'servidor' })
  assert.deepEqual({ ...a, id: 'x' }, { id: 'x', ev: 'delivered', kind: 'passwords', ns: 'passwords', deviceId: 'AB12-CD34', label: 'servidor', ts: 9 })
  assert.equal(n.add('delivered', { kind: 'secrets', ns: 'proxy', deviceId: 'EF56-7890' }).label, '')
  assert.throws(() => n.add('delivered', { kind: 'other', ns: 'proxy', deviceId: 'EF56-7890' }), (e) => e.code === 'bad-notice')
  assert.throws(() => n.add('delivered', { kind: 'secrets', deviceId: 'EF56-7890' }), (e) => e.code === 'bad-notice')
  assert.throws(() => n.add('delivered', { kind: 'secrets', ns: 'proxy' }), (e) => e.code === 'bad-notice')
})

test('un pedido cerrado deja su rastro: qué, de quién, cómo acabó y quién lo contestó', () => {
  const n = openNotices({ disk: nodeDisk(tmp(), { atRest }), now: () => 5 })
  const a = n.add('answered', { outcome: 'approved', kind: 'read', ns: 'claude', deviceId: 'AB12-CD34', label: 'portátil', by: 'EF56-GH78', byLabel: 'teléfono', request: 'r1' })
  assert.deepEqual({ ...a, id: 'x' }, { id: 'x', ev: 'answered', outcome: 'approved', kind: 'read', ns: 'claude', deviceId: 'AB12-CD34', label: 'portátil', by: 'EF56-GH78', byLabel: 'teléfono', request: 'r1', ts: 5 })
  const c = n.add('answered', { outcome: 'expired', kind: 'update', ns: 'vault', deviceId: null })
  assert.equal(c.by, null, 'lo que caducó no lo contestó nadie')
  assert.throws(() => n.add('answered', { outcome: 'maybe', kind: 'read' }), { code: 'bad-notice' })
  assert.throws(() => n.add('answered', { outcome: 'denied' }), { code: 'bad-notice' })
  assert.deepEqual(n.list().map((x) => x.outcome), ['approved', 'expired'])
})

