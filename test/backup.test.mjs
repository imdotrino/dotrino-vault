/**
 * EL RESPALDO: un archivo cifrado con contraseña con los valores de los cajones y las
 * contraseñas, y una importación que NUNCA pisa en silencio.
 *
 * Se prueban las tres piezas por separado, con criptografía de verdad:
 *   · el archivo (`sealBackup`/`openBackup`): sin la contraseña no se lee nada, ni los nombres;
 *   · el plan y los conflictos (`planImport`/`resolvePlan`/`writesOf`): sin decidir, no se
 *     escribe nada; y un privado no se vuelve público por importar;
 *   · el almacén: un cajón sale entero y entra en OTRA bóveda, también el del perfil, y las
 *     contraseñas se vuelven a sellar con las llaves de la otra bóveda.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {
  sealBackup, openBackup, planImport, resolvePlan, writesOf, itemRef, PASSWORDS_DRAWER
} from '../lib/src/core/backup.js'
import { openSecretsStore, PROFILE_OWNER } from '../lib/src/core/secretsStore.js'
import { makeSealer } from '../lib/src/core/sealer.js'
import { openSealedPasswords, exportPasswordEntries, importPasswordEntries } from '../lib/src/core/passwords.js'
import { nodeDisk } from '../src/disk.js'
import { makeEncKeypair } from '@dotrino/passmanager'
import { openWrap } from '@dotrino/identity/content'
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'

const PWD = 'una contraseña larga de respaldo'

const payloadDe = (drawers) => ({ v: 1, createdAt: 1, account: 'AB12', drawers })

// --- el archivo ------------------------------------------------------------------

test('respaldo: el archivo se abre con su contraseña y con ninguna otra', async () => {
  const p = payloadDe([{ owner: 'ns:proxy', vars: { TOKEN: { value: 's3cr3t', public: false } } }])
  const file = await sealBackup(p, PWD)
  const texto = JSON.stringify(file)
  // Ni el valor ni el NOMBRE del cajón salen en claro: el archivo puede acabar en cualquier sitio.
  assert.ok(!texto.includes('s3cr3t'))
  assert.ok(!texto.includes('proxy'))
  assert.deepEqual(await openBackup(file, PWD), p)
  await assert.rejects(() => openBackup(file, 'otra contraseña distinta'), (e) => e.code === 'WRONG_PASSWORD')
})

test('respaldo: una contraseña corta no sirve y un archivo ajeno se reconoce', async () => {
  await assert.rejects(() => sealBackup(payloadDe([]), 'corta'), (e) => e.code === 'WEAK_PASSWORD')
  await assert.rejects(() => openBackup({ hola: 1 }, PWD), (e) => e.code === 'NOT_A_BACKUP')
})

// --- el plan ---------------------------------------------------------------------

const respaldo = payloadDe([
  { owner: 'ns:proxy', vars: { A: { value: '1', public: false }, B: { value: '2', public: true }, C: { value: 'nuevo', public: false } } },
  { owner: 'dev:PUB-X', vars: { PORT: { value: '80', public: false } } }
])
const actual = { 'ns:proxy': { A: { value: '1', public: false }, B: { value: 'otro', public: false } } }

test('respaldo: el plan dice qué es nuevo, qué es igual y qué choca', () => {
  const plan = planImport(respaldo, { current: actual, devices: ['PUB-X'] })
  const proxy = plan.drawers.find((d) => d.to === 'ns:proxy')
  const st = Object.fromEntries(proxy.items.map((i) => [i.key, i.status]))
  assert.deepEqual(st, { A: 'same', B: 'conflict', C: 'new' })
  assert.deepEqual(plan.counts, { new: 2, same: 1, conflict: 1, skipped: 0 })
})

test('respaldo: con un choque sin decidir no se escribe NADA', () => {
  const plan = planImport(respaldo, { current: actual, devices: ['PUB-X'] })
  assert.throws(() => resolvePlan(plan), (e) => e.code === 'BACKUP_CONFLICTS' && e.conflicts.length === 1 && e.conflicts[0].key === 'B')
})

test('respaldo: keep deja lo de la bóveda, replace pone lo del respaldo', () => {
  const keep = writesOf(resolvePlan(planImport(respaldo, { current: actual, devices: ['PUB-X'] }), { onConflict: 'keep' }), respaldo)
  assert.deepEqual(keep.vars.map((w) => w.key).sort(), ['C', 'PORT'])
  const rep = writesOf(resolvePlan(planImport(respaldo, { current: actual, devices: ['PUB-X'] }), { onConflict: 'replace' }), respaldo)
  assert.deepEqual(rep.vars.map((w) => w.key).sort(), ['B', 'C', 'PORT'])
})

test('respaldo: una decisión por choque manda sobre la general', () => {
  const plan = planImport(respaldo, { current: actual, devices: ['PUB-X'] })
  const w = writesOf(resolvePlan(plan, { onConflict: 'replace', decisions: { [itemRef('ns:proxy', 'B')]: 'keep' } }), respaldo)
  assert.ok(!w.vars.some((x) => x.key === 'B'))
})

test('respaldo: un privado de la bóveda no se vuelve público por importar', () => {
  const plan = resolvePlan(planImport(respaldo, { current: actual, devices: ['PUB-X'] }), { onConflict: 'replace' })
  const b = writesOf(plan, respaldo).vars.find((x) => x.key === 'B')
  assert.equal(b.public, false)
  assert.equal(b.keptPrivate, true)
})

test('respaldo: un cajón de un aparato que no está aquí no entra, y se puede mover', () => {
  const sin = planImport(respaldo, { current: actual, devices: [], selected: ['dev:PUB-X'] })
  assert.equal(sin.drawers[0].status, 'no-device')
  assert.equal(writesOf(resolvePlan(sin), respaldo).vars.length, 0)
  const movido = planImport(respaldo, { current: {}, devices: ['PUB-Y'], selected: ['dev:PUB-X'], map: { 'dev:PUB-X': 'dev:PUB-Y' } })
  assert.deepEqual(writesOf(resolvePlan(movido), respaldo).vars, [{ to: 'dev:PUB-Y', key: 'PORT', value: '80', public: false }])
})

test('respaldo: pedir un cajón que no está es un error, no «nada que hacer»', () => {
  assert.throws(() => planImport(respaldo, { selected: ['ns:nada'] }), (e) => e.code === 'NO_SUCH_DRAWER')
})

// --- el almacén: de una bóveda a otra ----------------------------------------------

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-backup-'))
function almacen () {
  const key = new Uint8Array(crypto.randomBytes(32))
  return openSecretsStore(nodeDisk(tmp()), { sealer: makeSealer(), recipients: async () => [], defaultKey: () => key })
}

test('respaldo: un cajón sale entero y entra en OTRA bóveda, también el perfil', async () => {
  const a = almacen()
  await a.set('proxy', 'TOKEN', 'abc', false)
  await a.set('proxy', 'URL', 'https://x', true)
  await a.profilePutPublic('nickname', 'santi')
  await a.importValue(PROFILE_OWNER, 'telefono', '0999', false)

  const b = almacen()
  for (const owner of a.owners()) {
    const vars = await a.exportDrawer(owner)
    for (const [k, v] of Object.entries(vars)) await b.importValue(owner, k, v.value, v.public)
  }
  assert.deepEqual(await b.exportDrawer('ns:proxy'), { TOKEN: { value: 'abc', public: false }, URL: { value: 'https://x', public: true } })
  assert.deepEqual(await b.exportDrawer(PROFILE_OWNER), { nickname: { value: 'santi', public: true }, telefono: { value: '0999', public: false } })
  // Un cajón que no existe no es un cajón vacío.
  assert.equal(await b.exportDrawer('ns:nada'), null)
})

// --- las contraseñas --------------------------------------------------------------

function memStore () {
  const m = new Map()
  return { async get (k) { return m.get(k) }, async set (k, v) { m.set(k, v) } }
}
async function bovedaDeContrasenas () {
  const rec = await makeEncKeypair()
  const firma = await makeDeviceKey({ label: 'maestra' })
  const sealed = openSealedPasswords({ store: memStore(), members: () => [], canWrite: (pub) => pub === firma.publickey })
  return {
    sealed,
    openRecovery: (wrap) => openWrap({ wrap, myEncPrivateKey: rec.privateKey }),
    recipients: { recoveryPub: rec.encPub, main: [], passkeys: [] },
    author: { publickey: firma.publickey, sign: (body) => signWithDevice({ privateJwk: firma.privateJwk, publickey: firma.publickey, data: body }) }
  }
}

test('respaldo: las contraseñas salen de una bóveda y se vuelven a sellar en otra', async () => {
  const a = await bovedaDeContrasenas()
  const entrada = { id: 'e1', title: 'Salesforce', sites: ['salesforce.com'], username: 'yo@dotrino.com', secret: 'hunter2' }
  await importPasswordEntries({ ...a, writes: [{ entry: entrada, replaces: null }] })
  const out = await exportPasswordEntries(a)
  assert.equal(out.unreadable, 0)
  assert.equal(out.entries.length, 1)
  assert.equal(out.entries[0].secret, 'hunter2')

  const b = await bovedaDeContrasenas()
  // La otra bóveda ya tiene esa credencial con otra contraseña: choca, y replace la pisa EN SU SITIO.
  await importPasswordEntries({ ...b, writes: [{ entry: { ...entrada, id: 'local', secret: 'vieja' }, replaces: null }] })
  const payload = payloadDe([{ owner: PASSWORDS_DRAWER, entries: out.entries }])
  const plan = planImport(payload, { passwords: { entries: (await exportPasswordEntries(b)).entries } })
  assert.equal(plan.drawers[0].items[0].status, 'conflict')
  const { entries } = writesOf(resolvePlan(plan, { onConflict: 'replace' }), payload)
  await importPasswordEntries({ ...b, writes: entries })
  const final = (await exportPasswordEntries(b)).entries
  assert.equal(final.length, 1)
  assert.equal(final[0].id, 'local')
  assert.equal(final[0].secret, 'hunter2')
})
