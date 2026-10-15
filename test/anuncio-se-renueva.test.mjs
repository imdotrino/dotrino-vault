/**
 * EL ANUNCIO DE LA CUENTA SE RENUEVA.
 *
 * El proxio borra una entrada de canal a los 20 minutos de publicada. La bóveda se anunciaba
 * solo al identificarse, así que entrar con usuario y contraseña funcionaba los primeros 20
 * minutos y después contestaba «no hay ninguna bóveda encendida en esa dirección» con la
 * bóveda encendida e identificada (2026-10-12, la demo de los revisores de las tiendas).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createTransport } from '../src/transport.js'

const COMM = 'comm-pub'
const identityDoble = () => ({
  me: { publickey: 'master-pub' },
  profileActa: async () => ({ acta: { seq: 7, members: [{ pub: COMM }] } }),
  signData: async () => ({ publickey: 'master-pub' })
})
const commDoble = () => ({ pub: () => COMM, sign: async () => 'firma' })

test('la bóveda vuelve a anunciarse sin que nadie la reinicie', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-announce-'))
  test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {} })
  const publicados = []
  await createTransport({
    identity: identityDoble(), dir, commKey: commDoble(), announce: 'dotrino-vault-AB12-CD34-EF56',
    recheckMs: 20, reannounceMs: 40,
    makeClient: () => ({ token: 'tok', isConnected: true, connect: async () => {}, on: () => {}, identifyAs: async () => {}, publish: async (c) => { publicados.push(c) } })
  })
  assert.equal(publicados.length, 1, 'se anuncia al identificarse')
  await new Promise((r) => setTimeout(r, 300))
  assert.ok(publicados.length >= 3, 'y lo renueva sola: ' + publicados.length + ' anuncio(s)')
  assert.ok(publicados.every((c) => c === 'dotrino-vault-AB12-CD34-EF56'))
})
