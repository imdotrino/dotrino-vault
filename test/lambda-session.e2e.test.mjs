/**
 * LA BÓVEDA QUE DUERME (prueba de concepto de `lambda/`).
 *
 * Proxio real (repo hermano `dotrino-proxy`, ≥ 1.7.0), almacén en memoria y KMS de mentira.
 * Lo que tiene que pasar, de punta a punta:
 *
 *   1. al crear la pila, la primera sesión da de alta al administrador y termina;
 *   2. con la bóveda dormida, alguien entra con `admin@…` y la contraseña: el proxio ve el
 *      canal de la cuenta vacío, la despierta, la sesión arranca y le deja entrar;
 *   3. sin mensajes, la sesión se apaga sola y deja el perfil en el almacén;
 *   4. mientras una sesión tiene el cerrojo, otra no arranca.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { runSession, vaultStarter, wakeSecret, sameSecret } from '../lambda/session.mjs'
import { ensureAdmin } from '../lambda/bootstrap.mjs'
import { memoryStore, acquireLease } from '../lambda/mirror.mjs'

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(here, '..', '..', 'dotrino-proxy', 'server.js')
const FAKE_KMS = path.join(here, 'fixtures', 'fake-kms.mjs')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))
const log = process.env.VAULT_LOG ? console.error : () => {}
const PASSWORD = 'una contraseña de prueba bastante larga'

let proxy, proxyUrl, server, wakeBase, startVault
const store = memoryStore()
const sesiones = []   // las que arrancó el despertar

/** Una sesión como la de la Lambda, con un tope corto y la inactividad en 1,5 s. */
const sesion = ({ onReady, ...opts } = {}) => runSession({
  store, dir: tmp('vault-sesion-'), start: vaultStarter({ startVault, onReady }), proxyUrl, wakeBase,
  deadline: Date.now() + 60_000, idleMs: 1500, log, ...opts
})

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  // El KMS de mentira por el mismo camino que el de AWS (`node <script>`): así no depende de
  // que el archivo tenga permiso de ejecución, que git no guarda en todos los discos.
  process.env.DOTRINO_KMS_KEY_ID = 'test'
  process.env.DOTRINO_KMS_SCRIPT = FAKE_KMS
  process.env.DOTRINO_VAULT_NOTICE_MS = '150'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  ;({ startVault } = await import('../src/vault.js'))

  // Lo que en AWS es la Function URL: comprueba el secreto y arranca una sesión.
  server = http.createServer((req, res) => {
    req.resume()
    req.on('end', async () => {
      const u = new URL(req.url, 'http://x')
      const ok = u.pathname === '/wake' && sameSecret(u.searchParams.get('k'), await wakeSecret(store))
      res.writeHead(ok ? 202 : 403); res.end()
      if (ok) sesiones.push(sesion())
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  wakeBase = `http://127.0.0.1:${server.address().port}`
})

after(async () => {
  delete process.env.DOTRINO_KMS_KEY_ID
  delete process.env.DOTRINO_KMS_SCRIPT
  await Promise.allSettled(sesiones)
  await new Promise((resolve) => server?.close(resolve))
  try { await proxy?.stop() } catch (_) {}
})

test('la bóveda dormida se despierta para que entre el administrador, y se vuelve a dormir', async () => {
  // 1. La pila: primera sesión, sin esperar mensajes.
  const { ready, reason } = await sesion({
    idleMs: 0,
    onReady: (vault) => ensureAdmin(vault, { user: 'admin', password: async () => PASSWORD })
  })
  assert.equal(reason, 'idle')
  assert.equal(ready.created, true)
  assert.match(ready.address, /^admin@[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/)
  assert.match(ready.account, /^[0-9a-f]{64}$/)
  assert.ok(ready.account.toUpperCase().startsWith(ready.address.slice(6).replace(/-/g, '')))
  assert.ok(store.objects.has('.wake'), 'el secreto de despertar quedó guardado')
  assert.equal(store.objects.has('.lease'), false, 'y el cerrojo, quitado')

  // 2. Alguien entra desde un equipo sin llaves, con la bóveda dormida.
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const { loginWithPassword } = await import('../lib/src/loginClient.js')
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  try {
    const entrada = await loginWithPassword({ transport: c, address: ready.address, password: PASSWORD, label: 'consola' })
    assert.equal(sesiones.length, 1, 'el canal vacío la despertó una vez')
    assert.ok(entrada.cert?.sig, 'y dejó entrar: el aparato sale con su certificado')
    assert.ok(entrada.keys.sign?.d, 'el paquete se abrió con la contraseña')
    assert.deepEqual(entrada.caps.sort(), ['admin', 'approve', 'read', 'sign', 'store'], 'con los permisos del administrador')
  } finally { c.close() }

  // 3. Sin más mensajes se apaga sola, y el perfil queda en el almacén.
  const fin = await sesiones[0]
  assert.equal(fin.reason, 'idle')
  assert.equal(store.objects.has('.lease'), false)
  const plano = [...store.objects.values()].some((o) => o.body.toString('utf8').includes(PASSWORD))
  assert.equal(plano, false, 'la contraseña no está en ningún objeto')
})

test('volver a desplegar no cambia la contraseña de nadie', async () => {
  let pedida = false
  const { ready } = await sesion({
    idleMs: 0,
    onReady: (vault) => ensureAdmin(vault, { user: 'admin', password: async () => { pedida = true; return 'otra' } })
  })
  assert.equal(ready.created, false)
  assert.equal(pedida, false, 'si el administrador ya existe, ni se lee la contraseña')
})

test('con una sesión en marcha, otra no arranca', async () => {
  const s = memoryStore()
  const a = await acquireLease(s, { owner: 'a', ttlMs: 60_000 })
  await assert.rejects(acquireLease(s, { owner: 'b', ttlMs: 60_000 }), (e) => e.code === 'lease-busy')
  await a.release()
  const b = await acquireLease(s, { owner: 'b', ttlMs: 60_000 })
  await b.release()
})

test('un cerrojo vencido se toma: un contenedor que murió no deja la bóveda cerrada', async () => {
  const s = memoryStore()
  let t = 1000
  await acquireLease(s, { owner: 'muerto', ttlMs: 10, now: () => t })
  t = 5000
  const nuevo = await acquireLease(s, { owner: 'vivo', ttlMs: 60_000, now: () => t })
  assert.match(s.objects.get('.lease').body.toString(), /vivo/)
  await nuevo.release()
})

// LO QUE LA BÓVEDA NO ATIENDE NO LA MANTIENE DESPIERTA (2026-10-25). La app Terminal sondea a
// todos los miembros del acta cada 30 s con un `ra.ping`, bóvedas incluidas; contaba como
// trabajo y la sesión de la Lambda duraba siempre sus 15 minutos.
test('un sondeo que la bóveda no atiende no la mantiene despierta', async () => {
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  const dir = tmp('vault-sondeo-')
  let timer = null
  let sent = 0
  try {
    const t0 = Date.now()
    const r = await sesion({
      dir, deadline: Date.now() + 15_000,
      onReady: () => {
        // A la cuenta: la llave pública del perfil está en claro en `key.json`.
        const pub = fs.readdirSync(dir, { recursive: true }).filter((f) => String(f).endsWith('key.json'))
          .map((f) => { try { return JSON.parse(fs.readFileSync(path.join(dir, String(f)), 'utf8')).pub } catch (_) { return null } })
          .find(Boolean)
        assert.ok(pub, 'la llave pública de la cuenta')
        timer = setInterval(() => { try { c.sendByPubkey(pub, { type: 'ra.ping', n: String(++sent) }, { ephemeral: true }) } catch (_) {} }, 300)
      }
    })
    assert.equal(r.reason, 'idle', 'se apagó por inactividad y no por el tope')
    assert.ok(sent >= 4, `el sondeo siguió llegando mientras tanto (${sent})`)
    assert.ok(Date.now() - t0 < 12_000)
  } finally { clearInterval(timer); c.close() }
})
