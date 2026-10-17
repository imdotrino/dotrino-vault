/**
 * LA BÓVEDA QUE ATIENDE PETICIONES (prueba de concepto de `lambda/`).
 *
 * Lo que se fija aquí es lo que hace falta para poner la bóveda en una Lambda:
 *
 *   1. un servicio lee sus secretos por HTTP (`DOTRINO_VAULT_URL`), sin pasar por el proxio,
 *      con las mismas comprobaciones de siempre;
 *   2. el perfil sobrevive a un ARRANQUE EN FRÍO: se tira el directorio local, se baja del
 *      almacén a otro vacío, y el servicio sigue leyendo;
 *   3. lo que llega al almacén va cifrado (el valor del secreto no aparece);
 *   4. dos escritores no se pisan: el segundo choca y lo dice.
 *
 * Proxio real (repo hermano `dotrino-proxy`) para enrolar, porque enrolar espera una
 * aprobación que llega después y eso todavía no va por HTTP. El KMS es el de mentira.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { openDesk, answerHttp } from '../lambda/desk.mjs'
import { createMirror, memoryStore } from '../lambda/mirror.mjs'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(here, '..', '..', 'dotrino-proxy', 'server.js')
const FAKE_KMS = path.join(here, 'fixtures', 'fake-kms.mjs')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
const log = process.env.VAULT_LOG ? console.error : () => {}

let proxy, proxyUrl, server, deskUrl, current
let deskHits = 0
const store = memoryStore()

/** El mostrador abre como lo hace la Lambda: desde el almacén, sobre un directorio nuevo. */
async function coldStart () {
  const { startVault } = await import('../src/vault.js')
  current = await openDesk({ store, dir: tmp('vault-lambda-'), startVault, proxyUrl, log })
  return current
}

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  process.env.DOTRINO_KEK_CMD = FAKE_KMS
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`

  // El HTTP que en AWS pone la Function URL: aquí, el mismo `answerHttp` detrás de un server.
  server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', async () => {
      deskHits++
      const r = await answerHttp(async () => current, { method: req.method, body }, { log })
      res.writeHead(r.statusCode, { 'content-type': 'application/json' })
      res.end(JSON.stringify(r.body))
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  deskUrl = `http://127.0.0.1:${server.address().port}/`
})

after(async () => {
  delete process.env.DOTRINO_VAULT_URL
  delete process.env.DOTRINO_KEK_CMD
  try { current?.close() } catch (_) {}
  await new Promise((resolve) => server?.close(resolve))
  try { await proxy?.stop() } catch (_) {}
})

test('un servicio lee sus secretos por HTTP, y siguen ahí después de un arranque en frío', async () => {
  const { vault } = await coldStart()
  assert.ok(store.objects.has('atrest.json'), 'el perfil nuevo nace con la llave fuera de la máquina')
  await vault.setSecret('demo', 'API_KEY', 'valor-que-no-debe-verse')

  // Enrolar va por el proxio: espera la aprobación, que llega después.
  const { enrollService, fetchSecrets } = await import('../lib/src/service.js')
  const svcDir = tmp('svc-lambda-')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:demo'], label: 'service:demo', ttlMs: 60_000 })
  let permiso = null
  await enrollService({
    qr, ns: 'demo', dir: svcDir,
    onCode: ({ code }) => {
      permiso = (async () => {
        const r = await vault.approveDevice(code)
        const m = (await vault.identity.profileActa()).acta.members.find((x) => x.pub === r.cert.sub)
        await vault.setCaps(r.cert.sub, [...new Set([...(m?.caps || []), 'unattended'])])
      })()
    }
  })
  await permiso
  // Lo de arriba cambió el perfil fuera de una petición (es la consola, no el mostrador).
  await current.sync()

  process.env.DOTRINO_VAULT_URL = deskUrl
  try {
    const first = await fetchSecrets({ dir: svcDir })
    assert.ok(deskHits > 0, 'el pedido fue por el mostrador HTTP, no por el proxio')
    assert.equal(first.API_KEY, 'valor-que-no-debe-verse')

    // ARRANQUE EN FRÍO: el contenedor se va con su /tmp. Lo único que queda es el almacén.
    current.close()
    await coldStart()
    const again = await fetchSecrets({ dir: svcDir })
    assert.equal(again.API_KEY, 'valor-que-no-debe-verse', 'el perfil volvió entero desde el almacén')
  } finally {
    delete process.env.DOTRINO_VAULT_URL
  }

  const plano = [...store.objects.values()].some((o) => o.body.toString('utf8').includes('valor-que-no-debe-verse'))
  assert.equal(plano, false, 'ningún objeto del almacén lleva el secreto en claro')
})

test('dos escritores sobre el mismo perfil: el segundo choca y lo dice', async () => {
  const s = memoryStore()
  const a = tmp('mirror-a-'); const b = tmp('mirror-b-')
  fs.writeFileSync(path.join(a, 'vault.json'), 'uno')
  await createMirror({ store: s, dir: a }).push()

  const ma = createMirror({ store: s, dir: a }); await ma.pull()
  const mb = createMirror({ store: s, dir: b }); await mb.pull()
  fs.writeFileSync(path.join(a, 'vault.json'), 'dos')
  await ma.push()
  fs.writeFileSync(path.join(b, 'vault.json'), 'tres')
  await assert.rejects(mb.push(), (e) => e.code === 'store-conflict')
  assert.equal(s.objects.get('vault.json').body.toString(), 'dos', 'lo del primero no se perdió')
})

test('sin servicio de llaves, un perfil nuevo no nace', async () => {
  const antes = process.env.DOTRINO_KEK_CMD
  delete process.env.DOTRINO_KEK_CMD
  try {
    const { startVault } = await import('../src/vault.js')
    await assert.rejects(openDesk({ store: memoryStore(), dir: tmp('vault-sin-kms-'), startVault, proxyUrl, log }), (e) => e.code === 'no-kms')
  } finally {
    process.env.DOTRINO_KEK_CMD = antes
  }
})
