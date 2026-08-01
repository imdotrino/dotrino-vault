/**
 * E2E de SECRETOS de servicios: proxy real (repo hermano dotrino-proxy) +
 * daemon del vault + cliente de servicio (@dotrino/vault/service).
 *
 *   vault: secret set proxy TURN_KEY_ID …  →  pair --service proxy
 *   servicio: enrollService (aprobación programática) → fetchSecrets
 *
 * Correr:  npm test   (node --test test/)
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
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`

  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-e2e-'), proxyUrl, log: () => {} })
  svcDir = tmp('svc-e2e-')
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('flujo completo: set → pair --service → enroll → fetchSecrets', async () => {
  vault.setSecret('proxy', 'TURN_KEY_ID', 'k-123')
  vault.setSecret('proxy', 'TURN_KEY_API_TOKEN', 't-456')
  assert.deepEqual(vault.listSecrets(), { proxy: ['TURN_KEY_ID', 'TURN_KEY_API_TOKEN'] })

  // pair --service proxy (mismo scope que arma el daemon)
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:proxy'], label: 'servicio:proxy', ttlMs: 24 * 60 * 60 * 1000 })

  const { enrollService, fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const { device, cert } = await enrollService({
    qr, ns: 'proxy', dir: svcDir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })
  assert.ok(device?.publickey && cert?.sig)
  assert.deepEqual(cert.scope, ['vault:secrets:proxy'])
  assert.equal(readServiceIdentity(svcDir)?.ns, 'proxy')

  const secrets = await fetchSecrets({ dir: svcDir })
  assert.deepEqual(secrets, { TURN_KEY_ID: 'k-123', TURN_KEY_API_TOKEN: 't-456' })
})

test('loadEnv() inyecta los secretos en process.env y PISA el .env', async () => {
  delete process.env.TURN_KEY_ID
  delete process.env.DOTRINO_ENV_OVERRIDE
  // Esto es lo que deja un `.env` cargado antes: un valor viejo ya en el entorno.
  // El vault tiene que ganarle, o rotar la llave no sirve de nada mientras quede
  // una copia rancia en la máquina.
  process.env.TURN_KEY_API_TOKEN = 'la-vieja-del-env'

  const { loadEnv } = await import('../lib/src/env.js')
  const { ns, injected, overridden, skipped } = await loadEnv({ ns: 'proxy', dir: svcDir, wait: false })

  assert.equal(ns, 'proxy')
  assert.equal(process.env.TURN_KEY_ID, 'k-123')
  assert.equal(process.env.TURN_KEY_API_TOKEN, 't-456', 'el vault manda sobre el entorno')
  assert.deepEqual(injected.sort(), ['TURN_KEY_API_TOKEN', 'TURN_KEY_ID'])
  assert.deepEqual(overridden, ['TURN_KEY_API_TOKEN'], 'se reporta lo pisado')
  assert.deepEqual(skipped, [])

  // La escotilla de depuración devuelve la precedencia clásica sin tocar código.
  process.env.TURN_KEY_API_TOKEN = 'la-del-operador'
  await loadEnv({ ns: 'proxy', dir: svcDir, wait: false, override: false })
  assert.equal(process.env.TURN_KEY_API_TOKEN, 'la-del-operador')

  // required: si falta una clave, no arranca
  await assert.rejects(
    loadEnv({ ns: 'proxy', dir: svcDir, wait: false, required: ['NO_EXISTE'] }),
    /faltan secretos/
  )
})

test('enrolar acepta la invitación TAL COMO la imprime el vault (no JSON)', async () => {
  // `enrollService` hacía `JSON.parse` del string, pero el vault no imprime JSON
  // desde que existe la marca de formato: emite la URL del QR y el código
  // compacto. O sea que enrolar un servicio pegando lo que el vault te da fallaba
  // siempre con «qr inválido: no es JSON». No lo cazaba nadie porque el único
  // servicio enrolado del ecosistema lo hizo cuando el formato aún era JSON.
  const { encodeInvite, inviteUrl } = await import('../lib/src/invite.js')
  const { enrollService } = await import('../lib/src/service.js')

  for (const [nombre, comoLoDa] of [['código compacto', encodeInvite], ['URL del QR', inviteUrl]]) {
    const ns = nombre === 'código compacto' ? 'compacto' : 'urlqr'
    vault.setSecret(ns, 'API_KEY', 'v-' + ns)
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'servicio:' + ns, ttlMs: 60000 })
    const dir = tmp('svc-' + ns + '-')

    await enrollService({
      qr: comoLoDa(qr), ns, dir,                       // ← un STRING, como lo pega un humano
      onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
    })
    assert.deepEqual(await fetchSecretsFrom(dir), { API_KEY: 'v-' + ns }, `falló pegando la ${nombre}`)
  }

  await assert.rejects(
    enrollService({ qr: 'esto no es una invitación', ns: 'proxy', dir: tmp('svc-basura-') }),
    /no parece una invitación del vault/
  )
})

test('un agente tiene UNA identidad: re-enrolar reemplaza y avisa qué descarta', async () => {
  // A diferencia de un aparato (que lleva varios perfiles y puede meter su cuenta
  // al vault por adopción), un agente no acumula identidades ni transfiere la
  // suya: el vault le cede una y la anterior deja de existir. Enrolar dos veces
  // no es un error a bloquear, es la forma de ROTAR la identidad de un agente.
  const { enrollService, readServiceIdentity } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const ns = 'rotable'
  vault.setSecret(ns, 'API_KEY', 'v1')
  const dir = tmp('svc-rot-')

  const enrolar = async (onReplace) => {
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'servicio:' + ns, ttlMs: 60000 })
    return enrollService({
      qr: encodeInvite(qr), ns, dir, onReplace,
      onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
    })
  }

  const primera = await enrolar()
  assert.equal(primera.replaced, null, 'la primera vez no hay nada que descartar')
  const llaveVieja = readServiceIdentity(dir).device.publickey

  let avisado = null
  const segunda = await enrolar((prev) => { avisado = prev })
  assert.ok(avisado, 're-enrolar tiene que avisar que descarta la identidad anterior')
  assert.equal(avisado.ns, ns)
  assert.match(avisado.deviceId, /^[0-9A-F]{8}$/)
  assert.deepEqual(segunda.replaced, avisado)

  // Reemplazo, no convivencia: en disco queda UNA identidad, la nueva.
  const guardada = readServiceIdentity(dir)
  assert.notEqual(guardada.device.publickey, llaveVieja, 'la llave tiene que ser otra')
  assert.equal(guardada.device.publickey, segunda.device.publickey)
  assert.deepEqual(await fetchSecretsFrom(dir), { API_KEY: 'v1' }, 'la identidad nueva sirve para leer')
})

test('un agente NUNCA adopta: el camino de transferir identidad se rechaza de entrada', async () => {
  // El emparejamiento tiene dos modos y los declara la bóveda en la invitación:
  // `join` (el que se enrola entra a la cuenta de la bóveda) y `adopt` (la bóveda
  // se queda con la cuenta que trae el aparato). El segundo es para APARATOS. Un
  // agente no transfiere identidad: la suya se la cede el vault, así que este
  // camino no se negocia. Y se corta ACÁ, al pegar la invitación, no después de
  // un viaje que termina en un «intent-mismatch» que no le explica nada a nadie.
  const { enrollService } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:adoptame'], label: 'x', ttlMs: 60000, mode: 'adopt' })
  assert.equal(qr.m, 'adopt', 'la bóveda declara el modo en la propia invitación')

  await assert.rejects(
    enrollService({ qr: encodeInvite(qr), ns: 'adoptame', dir: tmp('svc-adopt-') }),
    /un agente no transfiere su identidad/
  )
})

test('la bóveda AVISA al agente cuando su configuración cambia (agrupado)', async () => {
  // Guardar un secreto no sirve de nada si quien lo usa no se entera. El aviso no
  // lleva valores: solo dice «el ns cambió», y el agente reacciona saliendo para
  // que su supervisor lo levante limpio — así lee todo fresco y, sobre todo, el
  // valor viejo deja de existir en su memoria (en JS un string no se puede borrar).
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const avisos = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => avisos.push(i)
  })
  try {
    // Los tests anteriores también guardaron secretos de este ns, y su aviso
    // agrupado puede seguir en vuelo: se deja pasar la ventana y se cuenta desde
    // cero, o se estaría midiendo el eco de otra prueba.
    await new Promise((r) => setTimeout(r, 4000))
    avisos.length = 0

    vault.setSecret('proxy', 'TURN_KEY_ID', 'rotada-1')
    // AGRUPADO: tres escrituras seguidas son UN cambio de configuración, no tres.
    vault.setSecret('proxy', 'TURN_KEY_API_TOKEN', 'rotada-2')
    vault.setSecret('proxy', 'OTRA', 'rotada-3')

    await esperarA(() => avisos.length > 0, 'el aviso de cambio')
    await new Promise((r) => setTimeout(r, 1500))
    assert.equal(avisos.length, 1, 'tres `secret set` seguidos avisan UNA vez, no tres')
    assert.equal(avisos[0].ns, 'proxy')
  } finally { w.stop() }
})

test('el aviso de otro namespace no le llega a este agente', async () => {
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const avisos = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => avisos.push(i)
  })
  try {
    // El aviso dice QUÉ ns cambió, así que mandárselo a un agente ajeno sería
    // contarle que ese namespace existe. Se manda solo a los del ns.
    vault.setSecret('geo', 'DB_URL', 'nada-que-ver')
    await new Promise((r) => setTimeout(r, 1500))
    assert.equal(avisos.length, 0, 'el agente del ns «proxy» no se entera de lo de «geo»')
  } finally { w.stop() }
})

test('un aviso mal firmado NO reinicia a nadie (sería un ataque de denegación)', async () => {
  // Es la defensa que hace que esto no sea un arma: si cualquiera pudiera mandar
  // el aviso, cualquiera podría reiniciar la flota ajena cuando quisiera.
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const { MSG } = await import('../lib/src/protocol.js')
  const { makeDeviceKey, signWithDevice } = await import('@dotrino/identity/capabilities')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')

  const avisos = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => avisos.push(i)
  })
  try {
    // Un impostor con llave propia y bien formada: firma de verdad, pero NO es la
    // maestra que este agente tiene pineada.
    const impostor = await makeDeviceKey({ label: 'impostor' })
    const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
    await c.connect()
    const body = { op: 'secrets.changed', ns: 'proxy', ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: impostor.privateJwk, data: body })
    const yo = await readServiceIdentitySync()
    c.sendByPubkey(yo.device.publickey, { type: MSG.SECRETS_CHANGED, body, signature })
    await new Promise((r) => setTimeout(r, 1500))
    c.close()
    assert.equal(avisos.length, 0, 'un aviso que no viene de TU bóveda se ignora')
  } finally { w.stop() }
})

// El archivo va CIFRADO en reposo (ligado a la máquina), así que se lee por el
// mismo camino que el servicio, no con un JSON.parse a pelo.
async function readServiceIdentitySync () {
  const { readServiceIdentity } = await import('../lib/src/service.js')
  return readServiceIdentity(svcDir)
}

async function esperarA (fn, que, timeoutMs = 8000) {
  const t = Date.now() + timeoutMs
  while (Date.now() < t) {
    if (await fn()) return true
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('se agotó la espera de ' + que)
}

test('el scope corta el acceso a otro namespace', async () => {
  vault.setSecret('geo', 'DB_PASSWORD', 'nope')
  await assert.rejects(
    fetchNsWithSavedCert('geo'),
    /no autorizado: scope/
  )
})

test('un cert revocado deja de poder leer', async () => {
  const { issued } = await vault.listDevices()
  const mine = issued.find((d) => d.label === 'servicio:proxy')
  assert.ok(mine, 'el servicio enrolado aparece en delegations')
  await vault.revokeDevice(mine.nonce)
  await assert.rejects(fetchNsWithSavedCert('proxy'), /no autorizado: revoked/)
})

async function fetchSecretsFrom (dir) {
  const { fetchSecrets } = await import('../lib/src/service.js')
  return fetchSecrets({ dir })
}

async function fetchNsWithSavedCert (ns) {
  const { fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const saved = readServiceIdentity(svcDir)
  return fetchSecrets({ ns, proxyUrl: saved.proxy, masterPubkey: saved.iss, device: saved.device, cert: saved.cert })
}
