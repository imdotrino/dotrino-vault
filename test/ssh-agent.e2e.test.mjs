/**
 * El agente SSH sirve llaves que SOLO están en memoria: las lee de un cajón de la bóveda
 * (variables SSH_KEY_*, el archivo en base64) y firma en local. Aquí se generan tres
 * llaves con ssh-keygen/openssl, se meten en el cajón, se cargan como lo hace
 * `dotrino-env ssh-agent` y se comprueba con `ssh-add -L` real y verificando las firmas.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import net from 'node:net'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { createPublicKey, verify, generateKeyPairSync } from 'node:crypto'

const execFileP = promisify(execFile)
const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

function agentCall (sock, type, payload = Buffer.alloc(0)) {
  return new Promise((resolve, reject) => {
    const c = net.connect(sock)
    let buf = Buffer.alloc(0)
    c.on('connect', () => { const body = Buffer.concat([Buffer.from([type]), payload]); const len = Buffer.alloc(4); len.writeUInt32BE(body.length); c.write(Buffer.concat([len, body])) })
    c.on('data', (d) => { buf = Buffer.concat([buf, d]); if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) { c.end(); resolve({ type: buf[4], payload: buf.subarray(5, 4 + buf.readUInt32BE(0)) }) } })
    c.on('error', reject)
    setTimeout(() => reject(new Error('agent timeout')), 10000)
  })
}
const sshStr = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]) }
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b }

test('llaves del cajón en memoria: ed25519 (OpenSSH), ECDSA y RSA (PEM); lista y firma como ssh-agent', async () => {
  const { loadPrivateKey, publicLine, readStrings } = await import('../lib/src/sshKeys.js')
  const { startSshAgent } = await import('../lib/src/sshAgent.js')
  const dir = tmp('sshkeys-')

  // ed25519 como lo deja ssh-keygen (formato OpenSSH, sin frase).
  await execFileP('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'ed', '-f', path.join(dir, 'ed')])
  // ECDSA y RSA en PEM (lo que Node lee).
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' })
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' })

  // Lo que haría `dotrino-env ssh-agent` con el cajón: base64 → texto → llave en memoria.
  const secrets = {
    SSH_KEY_ED: Buffer.from(fs.readFileSync(path.join(dir, 'ed'))).toString('base64'),
    SSH_KEY_EC: Buffer.from(ec).toString('base64'),
    SSH_KEY_RSA: Buffer.from(rsa).toString('base64'),
    OTHER: 'x'
  }
  const keys = Object.entries(secrets).filter(([k]) => /^SSH_KEY_/.test(k))
    .map(([k, v]) => loadPrivateKey(Buffer.from(v, 'base64').toString('utf8'), k.toLowerCase().replace(/_/g, '-')))
  assert.deepEqual(keys.map((k) => k.type), ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'])
  // La pública del ed25519 coincide con la que escribió ssh-keygen.
  const pubFile = fs.readFileSync(path.join(dir, 'ed.pub'), 'utf8').trim().split(' ').slice(0, 2).join(' ')
  assert.equal(publicLine(keys[0]).split(' ').slice(0, 2).join(' '), pubFile)

  const sock = path.join(tmp('sock-'), 'a.sock')
  const agent = startSshAgent({ socketPath: sock, keys: () => keys, log: () => {} })
  await new Promise((r) => setTimeout(r, 100))
  try {
    // Lista: tres llaves, y `ssh-add -L` real las ve.
    const r = await agentCall(sock, 11)
    assert.equal(r.type, 12); assert.equal(r.payload.readUInt32BE(0), 3)
    try {
      const { stdout } = await execFileP('ssh-add', ['-L'], { env: { ...process.env, SSH_AUTH_SOCK: sock }, encoding: 'utf8' })
      assert.match(stdout, /ssh-ed25519 .* ssh-key-ed/); assert.match(stdout, /ssh-rsa /)
    } catch (e) { if (e.code !== 'ENOENT') throw e }

    const data = Buffer.from('session-id-and-stuff')
    // ed25519
    let s = await agentCall(sock, 13, Buffer.concat([sshStr(keys[0].blob), sshStr(data), u32(0)]))
    assert.equal(s.type, 14)
    let [sigBlob] = readStrings(s.payload, 1); let [algo, sig] = readStrings(sigBlob, 2)
    assert.equal(algo.toString(), 'ssh-ed25519')
    assert.equal(verify(null, data, createPublicKey(keys[0].privateKey), sig), true)
    // RSA con bandera rsa-sha2-256 (RFC 8332), como pide OpenSSH.
    s = await agentCall(sock, 13, Buffer.concat([sshStr(keys[2].blob), sshStr(data), u32(2)]))
    assert.equal(s.type, 14)
    ;[sigBlob] = readStrings(s.payload, 1); [algo, sig] = readStrings(sigBlob, 2)
    assert.equal(algo.toString(), 'rsa-sha2-256')
    assert.equal(verify('sha256', data, createPublicKey(keys[2].privateKey), sig), true)
    // Una llave que no está: FAILURE. Y añadir llaves (ssh-add de un archivo) tampoco.
    const other = loadPrivateKey(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }))
    assert.equal((await agentCall(sock, 13, Buffer.concat([sshStr(other.blob), sshStr(data), u32(0)]))).type, 5)
    assert.equal((await agentCall(sock, 17)).type, 5)
  } finally { agent.close() }
})

test('una llave con frase se rechaza con un mensaje claro (la bóveda es el candado)', async () => {
  const { loadPrivateKey } = await import('../lib/src/sshKeys.js')
  const dir = tmp('sshkeys2-')
  await execFileP('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'secreta', '-f', path.join(dir, 'k')])
  assert.throws(() => loadPrivateKey(fs.readFileSync(path.join(dir, 'k'), 'utf8')), /passphrase/)
})
