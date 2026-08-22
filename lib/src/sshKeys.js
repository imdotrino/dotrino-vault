/**
 * LLAVES SSH como secretos de la bóveda. La llave privada vive sellada en un cajón
 * (variables `SSH_KEY_*`, valor = el archivo de la llave en base64) y solo existe en claro
 * en la memoria del agente que la pidió (`dotrino-env ssh-agent`). Aquí: leerla, sacar su
 * pública en el formato de `authorized_keys` y firmar como manda SSH (RFC 4253/8332/5656).
 *
 *   · ed25519: formato OpenSSH («-----BEGIN OPENSSH PRIVATE KEY-----»), parseado a mano
 *     (Node no lo lee) — solo sin frase.
 *   · RSA / ECDSA P-256: PEM (PKCS#8 o tradicional), vía `node:crypto`.
 *
 * Puro: sin disco ni red.
 */
import { createPrivateKey, createPublicKey, sign as nodeSign, createHash } from 'node:crypto'

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b }
export const sshString = (buf) => Buffer.concat([u32(buf.length), Buffer.from(buf)])
export function sshMpint (bytes) {
  let b = Buffer.from(bytes)
  while (b.length > 1 && b[0] === 0) b = b.subarray(1)
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
  return sshString(b)
}
export function readStrings (buf, max = 16) {
  const out = []; let o = 0
  while (o + 4 <= buf.length && out.length < max) {
    const n = buf.readUInt32BE(o); o += 4
    if (o + n > buf.length) throw new Error('ssh: truncated string')
    out.push(buf.subarray(o, o + n)); o += n
  }
  return out
}
export const fingerprint = (blob) => 'SHA256:' + createHash('sha256').update(Buffer.from(blob)).digest('base64').replace(/=+$/, '')

const OPENSSH_MAGIC = 'openssh-key-v1\0'

/** Llave ed25519 en formato OpenSSH sin frase → { type, privateKey (KeyObject), blob }. */
function parseOpenSsh (text) {
  const b64 = text.replace(/-----(BEGIN|END) OPENSSH PRIVATE KEY-----/g, '').replace(/\s+/g, '')
  const buf = Buffer.from(b64, 'base64')
  if (buf.subarray(0, OPENSSH_MAGIC.length).toString('latin1') !== OPENSSH_MAGIC) throw new Error('ssh: not an OpenSSH private key')
  // string cipher · string kdf · string kdfoptions · uint32 nkeys · string pub · string priv
  let body = buf.subarray(OPENSSH_MAGIC.length)
  const [cipher, kdf, kdfopts] = readStrings(body, 3)
  body = body.subarray(12 + cipher.length + kdf.length + kdfopts.length)
  if (cipher.toString() !== 'none' || kdf.toString() !== 'none') throw new Error('ssh: passphrase-protected keys are not supported (store the key without one; the vault is the lock)')
  const [pubBlob, priv] = readStrings(body.subarray(4), 2)
  const [type] = readStrings(pubBlob, 1)
  if (type.toString() !== 'ssh-ed25519') {
    // Otros tipos en formato OpenSSH: conviértelos a PEM (`ssh-keygen -p -m PEM`).
    throw new Error(`ssh: ${type.toString()} in OpenSSH format is not supported; convert it with ssh-keygen -p -m PEM`)
  }
  // priv: uint32 check ×2, string type, string pub(32), string priv(64 = seed‖pub), string comment
  const [t2, , sk] = readStrings(priv.subarray(8), 3)
  if (t2.toString() !== 'ssh-ed25519' || sk.length !== 64) throw new Error('ssh: malformed ed25519 key')
  const seed = sk.subarray(0, 32)
  // PKCS#8 de ed25519: prefijo fijo + semilla de 32 bytes.
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  return { type: 'ssh-ed25519', privateKey, blob: Buffer.from(pubBlob) }
}

/** Blob público SSH de una KeyObject RSA / P-256 / ed25519. */
export function publicBlob (privateKey) {
  const pub = createPublicKey(privateKey)
  const jwk = pub.export({ format: 'jwk' })
  if (jwk.kty === 'RSA') {
    return Buffer.concat([sshString(Buffer.from('ssh-rsa')), sshMpint(Buffer.from(jwk.e, 'base64url')), sshMpint(Buffer.from(jwk.n, 'base64url'))])
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')])
    return Buffer.concat([sshString(Buffer.from('ecdsa-sha2-nistp256')), sshString(Buffer.from('nistp256')), sshString(point)])
  }
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(Buffer.from(jwk.x, 'base64url'))])
  }
  throw new Error('ssh: unsupported key type ' + jwk.kty + '/' + (jwk.crv || ''))
}

/**
 * Lee una llave privada (texto del archivo: OpenSSH ed25519 o PEM RSA/P-256) y devuelve
 * lo que el agente necesita: `{ type, privateKey, blob, id, comment }`.
 */
export function loadPrivateKey (text, comment = '') {
  const t = String(text || '').trim()
  let privateKey, blob
  if (t.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) ({ privateKey, blob } = parseOpenSsh(t))
  else { privateKey = createPrivateKey(t); blob = publicBlob(privateKey) }
  const [type] = readStrings(blob, 1)
  return { type: type.toString(), privateKey, blob, id: fingerprint(blob), comment }
}

/** Línea `authorized_keys` de una llave cargada. */
export const publicLine = (k) => `${k.type} ${k.blob.toString('base64')}${k.comment ? ' ' + k.comment : ''}`

const SSH_AGENT_RSA_SHA2_256 = 2
const SSH_AGENT_RSA_SHA2_512 = 4

/** Firma `data` como manda SSH para ese tipo de llave; devuelve el blob de firma. */
export function signSsh (k, data, flags = 0) {
  if (k.type === 'ssh-ed25519') {
    return Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(nodeSign(null, Buffer.from(data), k.privateKey))])
  }
  if (k.type === 'ecdsa-sha2-nistp256') {
    const raw = nodeSign('sha256', Buffer.from(data), { key: k.privateKey, dsaEncoding: 'ieee-p1363' })
    const rs = Buffer.concat([sshMpint(raw.subarray(0, 32)), sshMpint(raw.subarray(32))])
    return Buffer.concat([sshString(Buffer.from('ecdsa-sha2-nistp256')), sshString(rs)])
  }
  if (k.type === 'ssh-rsa') {
    // Sin flags es el `ssh-rsa` (SHA-1) histórico, que los servidores modernos rechazan;
    // OpenSSH pide rsa-sha2-256/512 con las banderas del agente (RFC 8332).
    const algo = (flags & SSH_AGENT_RSA_SHA2_512) ? 'rsa-sha2-512' : (flags & SSH_AGENT_RSA_SHA2_256) ? 'rsa-sha2-256' : 'ssh-rsa'
    const hash = algo === 'rsa-sha2-512' ? 'sha512' : algo === 'rsa-sha2-256' ? 'sha256' : 'sha1'
    return Buffer.concat([sshString(Buffer.from(algo)), sshString(nodeSign(hash, Buffer.from(data), k.privateKey))])
  }
  throw new Error('ssh: cannot sign with ' + k.type)
}

export default { loadPrivateKey, publicBlob, publicLine, signSsh, sshString, sshMpint, readStrings, fingerprint }
