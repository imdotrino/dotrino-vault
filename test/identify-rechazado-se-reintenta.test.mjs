/**
 * UN `identify` RECHAZADO NO PUEDE DEJAR LA BÓVEDA FUERA DE LA RED PARA SIEMPRE.
 *
 * Lo que pasó de verdad el 2026-09-10: la máquina arrancó con el reloj 35 minutos
 * atrasado (el `systemd-timesyncd` no contactó el servidor de hora hasta media hora
 * después), el proxio rechazó el sobre con «identify ts fuera de la ventana ±5min» y ese
 * error subía por `createTransport` hasta `startVault`: **el perfil no se abría**. Cada
 * petición contestaba `profile is not open`, el `status` enseñaba el perfil sin huella y
 * nadie reintentaba nunca —`identify` solo vuelve a correr al RECONECTAR, y el socket
 * estaba perfectamente conectado—. Con la bóveda fuera de la red no hay a quién timbrar:
 * el teléfono no recibió un solo pedido de aprobación en toda la tarde, y desde fuera eso
 * se ve igual que «no hay nada que aprobar».
 *
 * Las dos mitades que se comprueban aquí: que el perfil ARRANCA igual, y que vuelve solo
 * en cuanto el otro lado deja de decir que no.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createTransport } from '../src/transport.js'

const COMM = 'comm-pub'

/** Lo mínimo que `identify` mira: el acta que nombra a la llave de comunicación. */
const identityDoble = () => ({
  me: { publickey: 'master-pub' },
  profileActa: async () => ({ acta: { seq: 7, members: [{ pub: COMM }] } }),
  signData: async () => ({ publickey: 'master-pub' })
})

const commDoble = () => ({ pub: () => COMM, sign: async () => 'firma' })

/** Cliente de mentira: el sitio donde se decide si el proxio dice que sí o que no. */
function clienteDoble (identifyAs) {
  return { token: 'tok', connect: async () => {}, on: () => {}, identifyAs }
}

function dirTemporal () {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-identify-'))
  test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {} })
  return dir
}

test('el proxio rechaza el identify y el perfil arranca igual (no se cae)', async () => {
  const lineas = []
  const t = await createTransport({
    identity: identityDoble(),
    dir: dirTemporal(),
    commKey: commDoble(),
    log: (m) => lineas.push(String(m)),
    makeClient: () => clienteDoble(async () => { throw new Error('identify ts fuera de la ventana ±5min') })
  })
  assert.ok(t?.client, 'createTransport tiene que resolver: si tira, el perfil no se abre')
  assert.equal(t.isIdentified(), false, 'y tiene que reconocer que NO está alcanzable')
  const aviso = lineas.find((l) => /could not identify on the proxy/.test(l))
  assert.ok(aviso, 'el fallo se dice en voz alta, no se traga')
  assert.match(aviso, /unreachable/, 'y dice lo que significa: que nadie puede alcanzarla')
})

test('cuando el otro lado deja de decir que no, vuelve sola', async () => {
  const lineas = []
  let rechaza = true
  const t = await createTransport({
    identity: identityDoble(),
    dir: dirTemporal(),
    commKey: commDoble(),
    log: (m) => lineas.push(String(m)),
    makeClient: () => clienteDoble(async () => { if (rechaza) throw new Error('identify ts fuera de la ventana ±5min') })
  })
  assert.equal(t.isIdentified(), false)

  // El reloj se corrigió: el mismo sobre ya entra. No hace falta esperar al reintento —lo
  // que se comprueba es que reintentar SIRVE, no cuántos segundos tarda.
  rechaza = false
  await t.identify()
  assert.equal(t.isIdentified(), true, 'se identifica sin que nadie reinicie el servicio')
  assert.ok(lineas.some((l) => /identified on the proxy after 2 attempt\(s\)/.test(l)),
    'y se dice que volvió, que es lo que cierra el incidente en el log')
})

test('identificarse nunca tira: quien lo llama no tiene que protegerse', async () => {
  const t = await createTransport({
    identity: identityDoble(),
    dir: dirTemporal(),
    commKey: commDoble(),
    makeClient: () => clienteDoble(async () => { throw new Error('proxy down') })
  })
  // `vault.js` lo llama al meter la llave de comunicación en el acta; si tirara, se llevaría
  // por delante el camino que lo llamó.
  await assert.doesNotReject(() => t.identify())
})
