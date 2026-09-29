/**
 * UN SERVICIO GUARDA VARIABLES EN SU CAJÓN (dueño, 2026-09-29: «para facilitar la migración
 * de ENVs a Dotrino»). Es lo que hay detrás de `dotrino-env import`.
 *
 * Los límites que fija esta suite, dichos por el dueño:
 *   · sin nadie que apruebe, no se pide aprobación y solo se AÑADE: lo que ya existe no se toca;
 *   · con quien apruebe, se pide SIEMPRE —`unattended` no exime— y con el sí también se EDITA;
 *   · un servicio solo escribe en SU cajón.
 *
 * Bóveda propia en este archivo: la suite grande añade un aprobador que se queda para siempre,
 * y aquí hace falta ver primero la cuenta SIN ninguno.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

let proxy, proxyUrl, vault, svcDir

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  process.env.DOTRINO_VAULT_NOTICE_MS = '150'
  proxy = require(proxyServerPath)
  proxyUrl = `ws://127.0.0.1:${await proxy.start(0)}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-store-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  svcDir = tmp('svc-store-')

  // El servicio `mig`, enrolado como cualquier servicio de dotrino-env.
  const { enrollService } = await import('../lib/src/service.js')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:mig'], label: 'service:mig', ttlMs: 60_000 })
  let ok = null
  await enrollService({ qr, ns: 'mig', dir: svcDir, onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

const lib = () => import('../lib/src/service.js')
const servicePub = async () => (await lib()).readServiceIdentity(svcDir).device.publickey
const guardadas = () => Object.fromEntries((vault.listSecrets().mig || []).map((k) => [k.key, k.public]))

test('sin nadie que apruebe: se guarda en el acto, públicas y privadas, y el servicio las lee', async () => {
  const { storeVars, fetchSecrets } = await lib()
  const r = await storeVars({ dir: svcDir, vars: [{ key: 'DB_URL', value: 'postgres://uno' }, { key: 'SITE', value: 'https://x', public: true }] })
  assert.equal(r.pending, null, 'sin aprobadores no hay pedido')
  assert.equal(r.approval, false)
  assert.deepEqual(r.keys.sort(), ['DB_URL', 'SITE'])
  assert.deepEqual(guardadas(), { DB_URL: false, SITE: true }, 'la visibilidad es la que se pidió')
  assert.deepEqual(await fetchSecrets({ dir: svcDir }), { DB_URL: 'postgres://uno', SITE: 'https://x' })
})

test('`dotrino-env import` sube un .env: privadas por defecto, públicas las que se digan', async () => {
  const { execFile } = await import('node:child_process')
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'lib', 'bin', 'dotrino-env.js')
  const correr = (args) => new Promise((resolve) => {
    execFile(process.execPath, [cli, ...args], { env: { ...process.env, DOTRINO_ENV_DIR: svcDir, DOTRINO_NS: 'mig' } },
      (err, stdout, stderr) => resolve({ code: err?.code ?? 0, out: stdout + stderr }))
  })
  const env = path.join(tmp('env-'), '.env')
  fs.writeFileSync(env, '# migrado\nAPI_KEY="s3cr3t con espacios"\nexport PUBLIC_URL=https://y\n')
  const r = await correr(['import', env, '--public', 'PUBLIC_URL'])
  assert.equal(r.code, 0, r.out)
  assert.match(r.out, /Guardadas: API_KEY, PUBLIC_URL/)
  assert.ok(!r.out.includes('s3cr3t'), 'nunca imprime un valor')
  assert.equal(guardadas().API_KEY, false)
  assert.equal(guardadas().PUBLIC_URL, true)
  const { fetchSecrets } = await lib()
  assert.equal((await fetchSecrets({ dir: svcDir })).API_KEY, 's3cr3t con espacios')

  // Una línea mal escrita: no se sube NADA, y se dice cuál.
  fs.writeFileSync(env, 'BIEN=1\nesto no es una variable\n')
  const mal = await correr(['import', env])
  assert.notEqual(mal.code, 0)
  assert.match(mal.out, /línea 2/)
  assert.equal(guardadas().BIEN, undefined)
})

test('sin nadie que apruebe: lo que ya existe NO se toca, ni con `unattended`', async () => {
  const { storeVars, fetchSecrets } = await lib()
  await assert.rejects(storeVars({ dir: svcDir, vars: [{ key: 'DB_URL', value: 'postgres://pisado' }] }), (e) => e.code === 'exists')
  const pub = await servicePub()
  await vault.setCaps(pub, ['secrets', 'unattended'])
  await assert.rejects(storeVars({ dir: svcDir, vars: [{ key: 'DB_URL', value: 'postgres://pisado' }] }), (e) => e.code === 'exists')
  assert.equal((await fetchSecrets({ dir: svcDir })).DB_URL, 'postgres://uno')
  // Y todo o nada: si una de la tanda ya existe, no se guarda ninguna.
  await assert.rejects(storeVars({ dir: svcDir, vars: [{ key: 'NUEVA', value: 'n' }, { key: 'DB_URL', value: 'x' }] }), (e) => e.code === 'exists')
  assert.equal(guardadas().NUEVA, undefined, 'media carga aplicada es una configuración que nadie quiso')
})

test('un servicio no escribe en el cajón de otro', async () => {
  const { storeVars } = await lib()
  await assert.rejects(storeVars({ dir: svcDir, ns: 'otro', vars: [{ key: 'X', value: 'y' }] }), /unauthorized/)
})

test('con quien apruebe: se pide SIEMPRE (también con `unattended`), y al aprobar puede EDITAR', async () => {
  const { storeVars, fetchSecrets, enrollWithVault } = await lib()
  const { signWithDevice } = await import('@dotrino/identity/capabilities')
  const { requestRenew } = await import('@dotrino/identity/vault/remote.js')
  const { MSG } = await import('../src/protocol.js')

  // El teléfono que aprueba.
  const inv = await vault.startPairing({ scope: ['vault:sign'], label: 'phone', ttlMs: 60_000 })
  let ok = null
  const phone = await enrollWithVault({ qr: inv.qr, label: 'phone', onCode: ({ code }) => { ok = vault.approveDevice(code) } })
  await ok
  await vault.setCaps(phone.device.publickey, ['sign', 'approve'])
  const phoneCert = (await requestRenew({ master: vault.master, proxy: proxyUrl, device: phone.device, cert: phone.cert })).cert
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const aprobar = async (id) => {
    const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
    await c.connect()
    try {
      const data = { op: 'approve', id, publickey: phone.device.publickey, ts: Date.now() }
      const { signature } = await signWithDevice({ privateJwk: phone.device.privateJwk, data })
      const res = new Promise((resolve, reject) => {
        c.on('message', (_f, p) => { if (p?.type === MSG.SECRETS_RESULT) resolve(p); else if (p?.type === MSG.ERROR) reject(new Error(p.error)) })
        setTimeout(() => reject(new Error('timeout')), 8000)
      })
      c.sendByPubkey(vault.master, { type: MSG.SECRETS, data, signature, cert: phoneCert })
      return (await res).body
    } finally { c.close() }
  }

  // El servicio sigue con `unattended` (de la prueba anterior): aun así, se pide.
  const r = await storeVars({ dir: svcDir, vars: [{ key: 'DB_URL', value: 'postgres://dos' }, { key: 'OTRA', value: 'o' }] })
  assert.ok(r.pending, 'con aprobador, queda en espera aunque el servicio sea desatendido')
  assert.equal(r.approval, true)
  assert.deepEqual(r.keys, [], 'todavía no se guardó nada')
  assert.equal((await fetchSecrets({ dir: svcDir })).DB_URL, 'postgres://uno')
  const [pedido] = vault.listApprovals().filter((p) => p.id === r.pending)
  assert.equal(pedido.kind, 'write')

  assert.equal((await aprobar(r.pending)).ok, true)
  const ahora = await fetchSecrets({ dir: svcDir })
  assert.equal(ahora.DB_URL, 'postgres://dos', 'con el sí de quien aprueba, EDITA')
  assert.equal(ahora.OTRA, 'o')
})
