/**
 * LLAVES SSH del teléfono — solo la parte PÚBLICA, que es lo único que vive en esta
 * máquina. La privada nace y muere en el aparato que aprueba (WebCrypto no extraíble hoy;
 * el llavero del sistema en la app nativa): firmar un reto SSH es un pedido de aprobación
 * más, y la firma vuelve con el «sí». Así la llave SSH no está en el disco del PC, que
 * era exactamente lo que había que sacar de aquí.
 *
 * Formatos (RFC 4253 / 5656): el blob de una llave `ecdsa-sha2-nistp256` es
 * string(tipo) string("nistp256") string(0x04‖X‖Y); su firma es string(tipo) string(mpint r ‖ mpint s).
 * Puro: sin disco ni red — quien guarda es `vault.js`.
 */
import { createPublicKey, createHash, verify as nodeVerify } from 'node:crypto'

export const ECDSA_P256 = 'ecdsa-sha2-nistp256'

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b }
export const sshString = (buf) => Buffer.concat([u32(buf.length), Buffer.from(buf)])
export function sshMpint (bytes) {
  let b = Buffer.from(bytes)
  while (b.length > 1 && b[0] === 0) b = b.subarray(1)
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
  return sshString(b)
}
/** Lee strings SSH encadenados: `[Buffer, …]`. */
export function readStrings (buf, max = 16) {
  const out = []; let o = 0
  while (o + 4 <= buf.length && out.length < max) {
    const n = buf.readUInt32BE(o); o += 4
    if (o + n > buf.length) throw new Error('ssh: truncated string')
    out.push(buf.subarray(o, o + n)); o += n
  }
  return out
}

/** Blob de llave pública a partir de las coordenadas (base64url JWK). */
export function p256Blob ({ x, y }) {
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')])
  return Buffer.concat([sshString(Buffer.from(ECDSA_P256)), sshString(Buffer.from('nistp256')), sshString(point)])
}

/**
 * Acepta una línea `authorized_keys` (`ecdsa-sha2-nistp256 AAAA… comentario`) y devuelve
 * lo que se guarda: tipo, blob, comentario y JWK pública. Solo P-256: es lo que firma
 * WebCrypto y el llavero del teléfono; RSA no entra.
 */
export function parsePublicKey (line) {
  const [type, b64, ...rest] = String(line || '').trim().split(/\s+/)
  if (type !== ECDSA_P256 || !b64) throw new Error(`ssh: only ${ECDSA_P256} keys are accepted`)
  const blob = Buffer.from(b64, 'base64')
  const [t, curve, point] = readStrings(blob, 3)
  if (t.toString() !== ECDSA_P256 || curve.toString() !== 'nistp256' || point.length !== 65 || point[0] !== 4) throw new Error('ssh: malformed key blob')
  const jwk = { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') }
  return { type, blob: blob.toString('base64'), comment: rest.join(' '), jwk, id: fingerprint(blob) }
}

/** `SHA256:…` como lo imprime `ssh-keygen -l`. */
export function fingerprint (blob) {
  return 'SHA256:' + createHash('sha256').update(Buffer.from(blob)).digest('base64').replace(/=+$/, '')
}

/**
 * Comprueba la firma cruda del teléfono (`r‖s`, 64 bytes, SHA-256 sobre `data`) y la
 * convierte al blob de firma SSH. Una firma que no cuadra NO se convierte: devolver un
 * blob inválido dejaría al `ssh` del usuario con un error opaco y a nosotros sin bitácora.
 */
export function sshSignature ({ jwk, data, rawSig }) {
  const sig = Buffer.from(rawSig, 'base64')
  if (sig.length !== 64) throw new Error('ssh: raw signature must be 64 bytes (r||s)')
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' })
  const ok = nodeVerify('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' }, sig)
  if (!ok) throw new Error('ssh: the signature does not verify against the registered key')
  const rs = Buffer.concat([sshMpint(sig.subarray(0, 32)), sshMpint(sig.subarray(32))])
  return Buffer.concat([sshString(Buffer.from(ECDSA_P256)), sshString(rs)])
}

export default { ECDSA_P256, parsePublicKey, p256Blob, sshSignature, sshString, sshMpint, readStrings, fingerprint }
