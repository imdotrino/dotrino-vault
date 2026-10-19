/**
 * EL RESPALDO DE PUNTA A PUNTA: dos bóvedas de verdad, con su proxio. Se exporta de una, se
 * cierra con la contraseña del respaldo, se abre y se importa en la otra — que tiene OTRAS
 * llaves y otra copia de recuperación, así que nada viaja como sobre: se vuelve a sellar.
 *
 * Y las dos reglas que no se negocian:
 *   · con la bóveda cerrada no se exporta ni se importa;
 *   · un choque sin decidir no escribe nada.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { sealBackup, openBackup, PASSWORDS_DRAWER } from '../lib/src/core/backup.js'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
const PWD = 'contraseña del respaldo de prueba'

let proxy, a, b
let locked = false

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  const proxyUrl = `ws://127.0.0.1:${port}`
  const { startVault } = await import('../src/vault.js')
  const log = process.env.VAULT_LOG ? console.error : () => {}
  a = await startVault({ dir: tmp('backup-a-'), proxyUrl, log, isLocked: () => locked })
  b = await startVault({ dir: tmp('backup-b-'), proxyUrl, log })
})

after(async () => {
  try { a?.close() } catch (_) {}
  try { b?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

const viaArchivo = async (payload) => openBackup(JSON.parse(JSON.stringify(await sealBackup(payload, PWD))), PWD)

test('respaldo e2e: un cajón pasa de una bóveda a otra, y choca lo que ya había', async () => {
  await a.setSecret('proxy', 'TOKEN', 'del-respaldo')
  await a.setSecret('proxy', 'URL', 'https://a', true)
  await a.setSecret('geo', 'DB', 'postgres://a')
  await b.setSecret('proxy', 'TOKEN', 'de-aqui')

  // Solo el cajón proxy: mover UN cajón es la mitad de lo que esto tiene que hacer.
  const { payload, summary } = await a.exportBackup({ drawers: ['ns:proxy'] })
  assert.deepEqual(summary.drawers.map((d) => d.owner), ['ns:proxy'])
  const abierto = await viaArchivo(payload)

  // Sin decidir: no se escribe NADA, tampoco lo que no chocaba.
  await assert.rejects(() => b.importBackup(abierto), (e) => e.code === 'BACKUP_CONFLICTS' && e.conflicts[0].key === 'TOKEN')
  assert.deepEqual(b.listSecrets().proxy.map((x) => x.key), ['TOKEN'])

  const r = await b.importBackup(abierto, { onConflict: 'keep' })
  assert.equal(r.written, 1)
  assert.equal(r.kept, 1)
  assert.equal(await b.revealSecret('ns:proxy', 'TOKEN'), 'de-aqui')
  assert.equal(await b.revealSecret('ns:proxy', 'URL'), 'https://a')
  assert.equal(b.listSecrets().geo, undefined, 'entró un cajón que no se pidió')

  await b.importBackup(abierto, { onConflict: 'replace' })
  assert.equal(await b.revealSecret('ns:proxy', 'TOKEN'), 'del-respaldo')
})

test('respaldo e2e: un cajón se puede importar con OTRO nombre', async () => {
  const { payload } = await a.exportBackup({ drawers: ['ns:geo'] })
  await b.importBackup(await viaArchivo(payload), { map: { 'ns:geo': 'ns:geo-viejo' } })
  assert.equal(await b.revealSecret('ns:geo-viejo', 'DB'), 'postgres://a')
})

test('respaldo e2e: las contraseñas se vuelven a sellar en la otra bóveda', async () => {
  const entrada = { id: 'e-1', title: 'Correo', sites: ['correo.ejemplo'], username: 'yo', secret: 'hunter2' }
  await a.importBackup({ v: 1, createdAt: 1, drawers: [{ owner: PASSWORDS_DRAWER, entries: [entrada] }] })
  const { payload } = await a.exportBackup({ drawers: [PASSWORDS_DRAWER] })
  assert.equal(payload.drawers[0].entries[0].secret, 'hunter2')

  await b.importBackup(await viaArchivo(payload))
  const deB = await b.exportBackup({ drawers: [PASSWORDS_DRAWER] })
  assert.equal(deB.payload.drawers[0].entries[0].secret, 'hunter2')
  assert.equal(deB.payload.drawers[0].entries[0].username, 'yo')
})

test('respaldo e2e: con la bóveda cerrada no se exporta ni se importa', async () => {
  locked = true
  try {
    await assert.rejects(() => a.exportBackup(), (e) => e.code === 'VAULT_LOCKED')
    await assert.rejects(() => a.importBackup({ v: 1, drawers: [] }), (e) => e.code === 'VAULT_LOCKED')
  } finally { locked = false }
})
