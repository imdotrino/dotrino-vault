#!/usr/bin/env node
/**
 * KMS de mentira para las pruebas: cumple el contrato de `kek.js` (base64 por la entrada,
 * base64 por la salida) con una llave fija. No pretende ser seguro; pretende comportarse
 * como un KMS de verdad — incluida la parte de caerse cuando se lo pides.
 *
 * Uso:  fake-kms.mjs wrap|unwrap
 * Env:  FAKE_KMS_DOWN=1   simula «no hay red / credenciales caducadas»
 *       FAKE_KMS_KEY=hex  otra llave (para probar que un KMS ajeno NO abre lo nuestro)
 */
import crypto from 'node:crypto'

const MODE = process.argv[2]
if (process.env.FAKE_KMS_DOWN) {
  process.stderr.write('fake-kms: could not reach the key service\n')
  process.exit(7)
}

const key = Buffer.from(process.env.FAKE_KMS_KEY || '00'.repeat(32), 'hex')
let input = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (c) => { input += c })
process.stdin.on('end', () => {
  const data = Buffer.from(input.trim(), 'base64')
  try {
    if (MODE === 'wrap') {
      const iv = crypto.randomBytes(12)
      const c = crypto.createCipheriv('aes-256-gcm', key, iv)
      const ct = Buffer.concat([c.update(data), c.final()])
      process.stdout.write(Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'))
    } else if (MODE === 'unwrap') {
      const d = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12))
      d.setAuthTag(data.subarray(12, 28))
      process.stdout.write(Buffer.concat([d.update(data.subarray(28)), d.final()]).toString('base64'))
    } else {
      process.stderr.write('fake-kms: unknown mode\n'); process.exit(2)
    }
  } catch (e) {
    process.stderr.write('fake-kms: ' + e.message + '\n'); process.exit(3)
  }
})
