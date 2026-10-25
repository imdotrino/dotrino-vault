/**
 * UNA CAÍDA NO SE DA POR VUELTA SOLO PORQUE QUEDA UN TOKEN.
 *
 * El 2026-10-15 la bóveda de Dotrino perdió el latido con el proxio, dijo «back on the proxy
 * after 50s» al minuto y pasó hora y media fuera: el vigilante miraba `client.token`, que es el
 * de la conexión anterior y no se borra al caerse. Como se creía conectada, no volvió a marcar.
 * Lo único que lo delataba era el aviso de cada 10 minutos de que no podía anunciarse.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createTransport } from '../lib/src/core/transport.js'

const COMM = 'comm-pub'
const identityDoble = () => ({
  me: { publickey: 'master-pub' },
  profileActa: async () => ({ acta: { seq: 7, members: [{ pub: COMM }] } }),
  signData: async () => ({ publickey: 'master-pub' })
})
const commDoble = () => ({ pub: () => COMM, sign: async () => 'firma' })

test('caído con el token viejo: no dice que volvió y vuelve a marcar', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-down-'))
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {} })
  const oyentes = {}
  const cliente = {
    token: 'tok', isConnected: true, marcadas: 0,
    connect: async () => { cliente.marcadas++ },
    on: (ev, fn) => { oyentes[ev] = fn },
    // Como el cliente de verdad: sin socket, identificarse o publicar falla.
    identifyAs: async () => { if (!cliente.isConnected) throw new Error('WebSocket not connected') },
    publish: async () => { if (!cliente.isConnected) throw new Error('WebSocket not connected') }
  }
  const lineas = []
  const tr = await createTransport({
    identity: identityDoble(), dir, commKey: commDoble(), log: (l) => lineas.push(l),
    recheckMs: 10, patienceMs: 30, makeClient: () => cliente
  })
  assert.equal(tr.isIdentified(), true)
  const antes = cliente.marcadas

  // Se cae: el socket se cierra y el token se queda como estaba.
  cliente.isConnected = false
  oyentes.disconnect({ code: 4000, reason: 'heartbeat timeout' })
  await new Promise((r) => setTimeout(r, 200))

  assert.equal(tr.isIdentified(), false, 'sigue diciéndose identificada sin socket')
  assert.ok(!lineas.some((l) => l.includes('back on the proxy')), 'dijo que volvió sin volver: ' + lineas.join(' | '))
  assert.ok(cliente.marcadas > antes, 'no volvió a marcar: ' + lineas.join(' | '))
})

// CERRADO ES CERRADO (2026-10-25). La Lambda reusa el contenedor: el vigilante de una sesión
// terminada seguía marcando al proxio en la siguiente, con una identidad ya destruida.
test('cerrado, el vigilante no vuelve a marcar', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-closed-'))
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {} })
  const oyentes = {}
  const cliente = {
    token: 'tok', isConnected: true, marcadas: 0,
    connect: async () => { cliente.marcadas++ },
    on: (ev, fn) => { oyentes[ev] = fn },
    identifyAs: async () => { if (!cliente.isConnected) throw new Error('WebSocket not connected') },
    publish: async () => {}
  }
  const lineas = []
  const tr = await createTransport({
    identity: identityDoble(), dir, commKey: commDoble(), log: (l) => lineas.push(l),
    recheckMs: 10, patienceMs: 30, makeClient: () => cliente
  })
  const antes = cliente.marcadas
  tr.close()
  cliente.isConnected = false
  oyentes.disconnect({ code: 1000 })
  await new Promise((r) => setTimeout(r, 200))
  assert.equal(cliente.marcadas, antes, 'marcó después de cerrar: ' + lineas.join(' | '))
  assert.ok(!lineas.some((l) => l.includes('dialling again')), lineas.join(' | '))
})
