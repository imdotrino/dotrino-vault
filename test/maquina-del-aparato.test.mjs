/**
 * DÓNDE CORRE CADA APARATO, en la lista de la bóveda (dueño, 2026-10-15: «necesito ver más
 * información para identificar el dispositivo: el hostname, el SO, si es navegador, app iOS
 * o Android»).
 *
 * Tres mitades: el aparato lo dice al emparejarse y entra al acta; lo repite en cada pedido
 * firmado y la bóveda guarda lo último (cifrado); y la TUI lo pinta pegado al nombre.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { makeDeviceKey, signWithDevice, makePairingCode, commitCode, signDelegationWith } from '@dotrino/identity/capabilities'
import { createEnrollDesk } from '../lib/src/enroll.js'
import { selfMachine } from '../lib/src/proc.js'
import { openMachines, MACHINES_FILE } from '../src/machines.js'
import { atRestFor } from '../src/atrest.js'
import { __test as V } from '../src/tui/app.js'
import { makeTheme } from '../src/tui/term.js'

test('selfMachine: un proceso de Node dice su hostname y su sistema', () => {
  const m = selfMachine()
  assert.equal(m.kind, 'node')
  assert.equal(m.name, os.hostname().slice(0, 64))
  assert.ok(m.os.length > 0)
})

test('al emparejarse, lo que dice el aparato entra en el acta con él', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const iss = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey))
  const acta = { v: 5, profileId: iss, sealedBy: iss, seq: 1, members: [{ pub: iss, caps: ['sign', 'read', 'store', 'sealer'] }], renounced: [] }
  const admitidos = []
  const identity = {
    async profileActa () { return { acta, isMaster: true } },
    async admitMember (m) { admitidos.push(m); acta.members.push({ pub: m.pub, caps: m.caps }); acta.seq++; return { ok: true, seq: acta.seq } },
    async signDelegation (sub, scope) { return { cert: await signDelegationWith(pair.privateKey, iss, { sub, scope, iat: Date.now(), seq: acta.seq, nonce: crypto.randomUUID() }) } },
    async listDelegations () { return { issued: [], revoked: [] } },
    async revokeDelegation () { return { ok: true } }
  }
  const retos = []
  const desk = createEnrollDesk({ identity, iss, proxy: 'wss://test.invalid', send: () => {}, sendByPubkey: () => {}, onChallenge: (c) => retos.push(c) })
  const { qr } = await desk.startPairing({ scope: ['vault:sign'], ttlMs: 60000 })
  const device = await makeDeviceKey({ label: 'x' })
  const code = makePairingCode()
  const commit = await commitCode({ code, dpub: device.publickey, sn: qr.sn })
  const data = { op: 'enroll', dpub: device.publickey, token: qr.token, sn: qr.sn, commit, label: 'x', machine: { kind: 'android', os: 'Android 14', name: '', sobra: 1 }, ts: Date.now() }
  const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
  await desk.handleEnroll('tok', { type: 'vault.enroll', data, signature })

  const esperado = { kind: 'android', os: 'Android 14', name: '' }
  assert.deepEqual(desk.listPending()[0].machine, esperado, 'se ve al aprobar')
  assert.deepEqual(retos[0].machine, esperado)
  await desk.approve(code)
  assert.deepEqual(admitidos[0].machine, esperado, 'y entra al acta, limpio')
})

test('la bóveda guarda lo último que dijo cada aparato, cifrado, y solo reescribe si cambia', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'machines-'))
  const atRest = atRestFor(dir)
  const m = openMachines({ dir, atRest })
  assert.equal(m.of('P'), null)
  assert.equal(m.note('P', { kind: 'node', os: 'Linux 6.1', name: 'pc' }), true)
  assert.equal(m.note('P', { kind: 'node', os: 'Linux 6.1', name: 'pc' }), false, 'lo mismo no se reescribe')
  assert.equal(m.note('P', 'basura'), false, 'lo que no tiene forma no borra lo que había')
  assert.equal(m.note('P', { kind: 'node', os: 'Linux 7.0', name: 'pc' }), true)
  const raw = fs.readFileSync(path.join(dir, MACHINES_FILE), 'utf8')
  assert.equal(raw.includes('Linux'), false, 'no queda nada en claro en el disco')
  // Sobrevive a reiniciar la bóveda.
  assert.equal(openMachines({ dir, atRest }).of('P').os, 'Linux 7.0')
  fs.writeFileSync(path.join(dir, MACHINES_FILE), 'roto')
  assert.throws(() => openMachines({ dir, atRest }), (e) => e.code === 'machines-unreadable')
})

test('la TUI pinta dónde corre cada aparato, pegado a su nombre', () => {
  const t = makeTheme(false)
  const members = [
    { pub: 'PUB-A', id: 'AAAA-1111', label: 'Santiago', caps: ['sign'], machine: { kind: 'node', os: 'Linux 7.0.0', name: 'escritorio' } },
    { pub: 'PUB-B', id: 'BBBB-2222', label: 'Santiago', caps: ['sign'], machine: { kind: 'ios', os: 'iOS 18', name: '' } },
    { pub: 'PUB-C', id: 'CCCC-3333', label: 'Santiago', caps: ['sign'] }
  ]
  const issued = members.map((m, i) => ({ sub: m.pub, deviceId: m.id, label: m.label, scope: ['vault:sign'], exp: Date.now() + 8.64e7, nonce: 'n' + i }))
  const st = { lang: 'es', screen: 'devices', members, devices: { issued, revoked: [] }, capsDrafts: {}, blocked: [], profiles: [], activeIdx: 0 }
  const filas = V.deviceRows(st, t).filter((r) => r.sel).map((r) => r.text)
  assert.match(filas[0], /Santiago {2}node · Linux 7\.0\.0 · escritorio/)
  assert.match(filas[1], /ios · iOS 18/)
  assert.doesNotMatch(filas[2], /·/, 'sin dato, no se inventa nada')
})
