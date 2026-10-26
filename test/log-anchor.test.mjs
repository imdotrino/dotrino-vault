/**
 * EL ANCLA DE LA BITÁCORA (modelo de amenazas §4.3, dueño 2026-10-26): la cabeza sellada por
 * el signer va a los aprobadores, que la guardan. Aquí se prueba lo que decide cada lado.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { compareAnchor, sealHead, hexToB64url } from '../lib/src/core/logAnchor.js'
import { openNotices } from '../lib/src/core/notices.js'

const HEAD_A = 'a'.repeat(64)
const HEAD_B = 'b'.repeat(64)

test('el aprobador ve el corte: logSeq menor, o mismo logSeq con otra cabeza', () => {
  assert.equal(compareAnchor(null, { logSeq: 5, head: HEAD_A }), 'first')
  assert.equal(compareAnchor({ logSeq: 5, head: HEAD_A }, { logSeq: 9, head: HEAD_B }), 'advanced')
  assert.equal(compareAnchor({ logSeq: 5, head: HEAD_A }, { logSeq: 5, head: HEAD_A }), 'same')
  assert.equal(compareAnchor({ logSeq: 9, head: HEAD_B }, { logSeq: 5, head: HEAD_A }), 'truncated')
  assert.equal(compareAnchor({ logSeq: 9, head: HEAD_B }, { logSeq: 9, head: HEAD_A }), 'forked')
  assert.throws(() => compareAnchor(null, { head: HEAD_A }), (e) => e.code === 'anchor-malformed')
})

test('al signer va solo el hash, en base64url, y su recibo se comprueba', async () => {
  const hash = hexToB64url(HEAD_A)
  assert.equal(hash.length, 43)
  let sent = null
  const fetchFn = async (url, opts) => {
    sent = { url, body: JSON.parse(opts.body) }
    return { ok: true, json: async () => ({ v: 1, op: 'seal', hash: sent.body.hash, ts: 123, alg: 'ES256', signature: 'sig', pubkey: 'k' }) }
  }
  const r = await sealHead(HEAD_A, { fetchFn, signerUrl: 'https://signer.test' })
  assert.equal(sent.url, 'https://signer.test/seal')
  assert.deepEqual(Object.keys(sent.body), ['hash'], 'nada más que el hash')
  assert.equal(r.hash, hash)
})

test('sin signer, o con un recibo de otra cosa, no hay ancla: se lanza con código', async () => {
  const caido = async () => { throw new Error('ECONNREFUSED') }
  await assert.rejects(() => sealHead(HEAD_A, { fetchFn: caido }), (e) => e.code === 'anchor-signer-unreachable')
  const otro = async () => ({ ok: true, json: async () => ({ op: 'seal', hash: 'otro', ts: 1, signature: 's' }) })
  await assert.rejects(() => sealHead(HEAD_A, { fetchFn: otro }), (e) => e.code === 'anchor-signer-bad-receipt')
  const mal = async () => ({ ok: false, status: 503 })
  await assert.rejects(() => sealHead(HEAD_A, { fetchFn: mal }), (e) => e.code === 'anchor-signer-error')
})

test('el aviso del ancla guarda solo la última', () => {
  const mem = new Map()
  const disk = {
    atRest: { encrypt: (t) => t, decrypt: (t) => t },
    exists: (f) => mem.has(f), read: (f) => mem.get(f), write: (f, t) => mem.set(f, t)
  }
  const n = openNotices({ disk })
  n.add('log-anchor', { logSeq: 1, head: HEAD_A, tsa: { signature: 's' } })
  n.add('log-anchor', { logSeq: 2, head: HEAD_B, tsa: { signature: 's' } })
  const anchors = n.list().filter((x) => x.ev === 'log-anchor')
  assert.equal(anchors.length, 1)
  assert.equal(anchors[0].logSeq, 2)
  assert.throws(() => n.add('log-anchor', { logSeq: 3, head: HEAD_A }), (e) => e.code === 'bad-notice', 'sin recibo del signer no entra')
})

test('anclar no escribe en la bitácora (cambiaría la cabeza que ancla)', () => {
  const src = fs.readFileSync(fileURLToPath(new URL('../lib/src/core/vault.js', import.meta.url)), 'utf8')
  const i = src.indexOf('async function anchorLog')
  const cuerpo = src.slice(i, src.indexOf('\n  }\n', i))
  assert.ok(i !== -1)
  assert.ok(!/\baudit\(/.test(cuerpo), 'anchorLog no llama a audit()')
  assert.match(cuerpo, /quiet: true/, 'y va callado: no hace sonar el teléfono')
})
