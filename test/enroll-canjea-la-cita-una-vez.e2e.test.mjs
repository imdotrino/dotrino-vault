/**
 * REGRESIÓN: el enrolamiento canjea la cita UNA sola vez.
 *
 * La cita del proxio es de un solo uso — `pairing-cita.e2e` ya lo prueba del lado del
 * protocolo (`assert.equal(other.ok, false, 'la cita tiene que quemarse al usarse')`).
 * Lo que faltaba probar es que el CLIENTE lo respete.
 *
 * Qué pasó (2026-09-03): al añadir «sin --vault, preguntale el nombre de la cuenta a la
 * bóveda», la CLI empezó a llamar `vaultAccountName()` antes de enrolar. Esa función hace
 * el hello —y por tanto CANJEA la cita— y descartaba el `qr` enriquecido; después
 * `enrollService()` recibía el `qr` original y volvía a canjear una cita ya quemada.
 *
 * El error resultante era `código no válido o ya usado`, que señala a la invitación
 * cuando quien la había gastado era el propio comando un segundo antes. Costó horas de
 * diagnóstico porque solo ocurre SIN `--vault`, y con `--vault` (el camino de los tests
 * y el de la costumbre) todo seguía bien.
 *
 * Este test cuenta los canjes de una invitación real contra un proxio real: si alguien
 * vuelve a meter una llamada de red antes del enroll, falla acá y no en la máquina de
 * alguien a las once de la noche.
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'
import { encodeInvite } from '../lib/src/invite.js'

const require = createRequire(import.meta.url)
const HERE = path.dirname(fileURLToPath(import.meta.url))
const proxyServerPath = path.join(HERE, '..', '..', 'dotrino-proxy', 'server.js')
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

function fakeNodeIdentity (dir) {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicJwk = kp.publicKey.export({ format: 'jwk' })
  const privateJwk = kp.privateKey.export({ format: 'jwk' })
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'service-identity.json'), JSON.stringify({
    v: 1, ns: 'proxy', iss: 'test', enrolledAt: Date.now(),
    device: { publickey: JSON.stringify(publicJwk), privateJwk, publicJwk, label: 'test', createdAt: Date.now() }
  }))
  return dir
}

let proxy, proxyUrl, vault

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  process.env.VAULT_SERVICE_DIR = fakeNodeIdentity(path.join(tmp('proxy-node-'), 'vault-service'))
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`
  const { startVault } = await import('../src/vault.js')
  vault = await startVault({ dir: tmp('vault-canje-'), proxyUrl, log: () => {} })
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

/** Un cliente del proxio, para comprobar el estado de una cita desde fuera. */
async function clienteProxio () {
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await c.connect()
  return c
}

test('preguntar el nombre de la cuenta NO deja la cita inservible para enrolar', async () => {
  const { qr } = await vault.startPairing({ label: 'agente' })
  const invitacion = encodeInvite(qr)
  const { vaultHello, sayHello } = await import('../lib/src/service.js')

  // Paso 1 de la CLI sin `--vault`: preguntar la cuenta. Esto CANJEA la cita.
  const enriquecido = await vaultHello(invitacion)
  assert.ok(enriquecido.iss, 'el hello devuelve la llave de la bóveda para poder reusarse')
  assert.equal(enriquecido.conn, qr.conn, 'el qr enriquecido conserva la cita original')

  // Y se gastó de verdad: nadie más puede canjearla. Esto es lo que hacía fallar
  // al enrolamiento cuando volvía a intentarlo con el qr sin enriquecer.
  const c = await clienteProxio()
  try {
    const r = await c.redeemPairingCode(qr.conn)
    assert.equal(r.ok, false, 'la cita tenía que quedar quemada tras el primer hello')
  } finally { c.close() }

  // Paso 2: enrolar. Con el qr enriquecido NO puede volver a la red — se le pasa
  // `null` como cliente a propósito: si intentara canjear, reventaría aquí.
  const listo = await sayHello(null, enriquecido)
  assert.equal(listo.iss, enriquecido.iss, 'el segundo paso reusa el hello en vez de repetirlo')
})

test('`vaultHello` devuelve el qr enriquecido, no solo el nombre', async () => {
  // Es lo que permite reusar el hello. Si alguien lo cambia por un `string`, la CLI
  // vuelve a quedarse sin `iss` y el enrolamiento vuelve a canjear dos veces.
  const { qr } = await vault.startPairing({ label: 'agente' })
  const { vaultHello } = await import('../lib/src/service.js')
  const r = await vaultHello(encodeInvite(qr))
  assert.equal(typeof r, 'object', 'devuelve el qr, no el nombre suelto')
  assert.ok(r.iss, 'trae la llave maestra')
  assert.ok(r.proxy, 'trae el proxio')
})

test('un qr que ya trae `iss` no vuelve a salir a la red', async () => {
  const { qr } = await vault.startPairing({ label: 'agente' })
  const { vaultHello } = await import('../lib/src/service.js')
  const enriquecido = await vaultHello(encodeInvite(qr))
  // Sin red disponible el resultado tiene que ser el mismo: con `iss` puesto se corta
  // antes de conectar. Es la salida en la que se apoya todo el arreglo.
  const otra = await vaultHello(enriquecido)
  assert.equal(otra.iss, enriquecido.iss)
  assert.equal(otra.conn, qr.conn)
})

/**
 * EL CAMINO DE VERDAD: la CLI, entera, sin `--vault`.
 *
 * Los tests de arriba prueban las funciones de la librería; el bug estaba en cómo el
 * COMANDO las componía. Sin esto, alguien puede volver a meter una llamada de red antes
 * del enroll y los otros tres seguirían en verde.
 */
test('e2e: `dotrino-env enroll` sin --vault enrola de punta a punta', async () => {
  // `account` es lo que la bóveda contesta en el hello y de lo que la CLI saca la
  // etiqueta cuando no se pasa `--vault`. Sin él, el comando pide la etiqueta y sale —
  // que es el comportamiento correcto, pero no ejercita el camino que rompió.
  // `scope`: la misma forma que arma el daemon para `pair --service` — una lista, y con
  // el prefijo `vault:`. Un agente entra con permiso sobre SU cajón y nada más; con otro
  // alcance el cliente rechaza el cert (bien rechazado, pero no es lo que se ejercita acá).
  const { qr } = await vault.startPairing({ label: 'agente-e2e', account: 'cepi-test', scope: ['vault:secrets:agente-e2e'], ttlMs: 60000 })
  const dir = tmp('enroll-e2e-')
  const cli = path.join(HERE, '..', 'lib', 'bin', 'dotrino-env.js')

  const hijo = spawn(process.execPath, [cli, 'enroll', '--ns', 'agente-e2e', '--code', encodeInvite(qr), '--dir', dir],
    { stdio: ['ignore', 'pipe', 'pipe'] })

  let salida = ''
  const terminado = new Promise((resolve) => hijo.on('close', (code) => resolve(code)))
  hijo.stdout.on('data', async (b) => {
    salida += String(b)
    // Se aprueba en cuanto el aparato muestra su código, igual que haría un humano.
    const m = salida.match(/dotrino-vault approve (\d{6})/)
    if (m && !hijo._aprobado) {
      hijo._aprobado = true
      // `approveDevice(code)`: la bóveda NO conoce el código, lo lee del aparato — igual
      // que el humano que lo tipea. Es la misma puerta que usa el daemon.
      try { await vault.approveDevice(m[1]) } catch (e) { salida += `\n[test] approve falló: ${e.message}` }
    }
  })
  hijo.stderr.on('data', (b) => { salida += String(b) })

  const t = setTimeout(() => hijo.kill('SIGKILL'), 60000)
  const code = await terminado
  clearTimeout(t)

  assert.doesNotMatch(salida, /no válido o ya usado/,
    'canjeó la cita dos veces: preguntar la cuenta la gasta, y el enroll se queda sin nada que canjear')
  assert.equal(code, 0, `la CLI salió con ${code}. Salida:\n${salida}`)
  assert.ok(fs.existsSync(path.join(dir, 'service-identity.json')),
    'un enrolamiento correcto deja la identidad del servicio en disco')
})
