/**
 * La invitación de emparejamiento: el formato COMPACTO y la marca de formato.
 *
 * Lo que se defiende aquí es el tamaño y la exactitud a la vez. El tamaño porque el
 * QR se mide en filas de terminal: el JSON pesaba ~340 caracteres (la llave maestra
 * es una JWK serializada, 182 de ellos) y comprimido son ~100 → el QR bajó de 69
 * módulos a 41. La exactitud porque la llave maestra es la DIRECCIÓN de la bóveda en
 * el proxy, que direcciona por esa string exacta: si al rearmarla se mueve una coma,
 * el dispositivo le habla a nadie.
 *
 * Y el caso viejo que hay que seguir cubriendo: el navegador PERCENT-CODIFICA el JSON
 * de un fragmento (`{` `}` `"` no son legales en una URI), así que un enlace de los
 * que llevaban JSON crudo no llega igual que como salió. Pasó de verdad, medido en un
 * navegador (2026-07-28). El compacto no tiene ese problema —base64url ya es seguro en
 * una URL— pero los enlaces viejos siguen por ahí.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeInvite, inviteUrl, parseInvite, FMT_JSON, FMT_B64, FMT_COMPACT, PAIR_URL } from '../lib/src/invite.js'

const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('')

/** Una llave maestra de verdad: sin curva válida no hay forma compacta que valga. */
async function jwkPub () {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
}

async function qrReal (extra = {}) {
  return {
    v: 2,
    iss: await jwkPub(),
    proxy: 'wss://proxy.dotrino.com',
    token: hex(12),
    sn: hex(12),
    m: 'join',
    acct: 'Perfil 1',
    ...extra
  }
}

const URL_LONG = 'https://vault.dotrino.com/dispositivos#vault='

test('por defecto emite la forma compacta, y se lee de vuelta', async () => {
  const qr = await qrReal()
  const inv = encodeInvite(qr)
  assert.equal(inv[0], FMT_COMPACT)
  assert.match(inv.slice(1), /^[A-Za-z0-9_-]+$/, 'una sola palabra: ni comillas, ni llaves, ni %')
  assert.deepEqual(parseInvite(inv), qr)
})

test('el compacto es MUCHO más corto que las formas largas', async () => {
  const qr = await qrReal()
  const c = encodeInvite(qr, FMT_COMPACT)
  const b = encodeInvite(qr, FMT_B64)
  const j = encodeInvite(qr, FMT_JSON)
  assert.ok(c.length < j.length / 2, `compacto ${c.length} vs JSON ${j.length}`)
  assert.ok(c.length < b.length / 3, `compacto ${c.length} vs base64 ${b.length}`)
  // El enlace entero, que es lo que de verdad entra en el QR.
  assert.ok(inviteUrl(qr).length < 140, `enlace de ${inviteUrl(qr).length} caracteres`)
})

test('la llave maestra vuelve BYTE A BYTE igual (el proxy direcciona por esa string)', async () => {
  // Muchas llaves: la coordenada `y` se recupera resolviendo la curva y la paridad
  // tiene que salir bien las dos veces de cada dos.
  for (let i = 0; i < 40; i++) {
    const qr = await qrReal()
    const back = parseInvite(encodeInvite(qr))
    assert.equal(back.iss, qr.iss, 'la JWK rearmada difiere de la original')
    assert.deepEqual(back, qr)
  }
})

test('las dos formas de JWK del ecosistema (Node y navegador) se comprimen igual', async () => {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const { x, y } = await crypto.subtle.exportKey('jwk', par.publicKey)
  const forms = [
    // WebCrypto de Node (el daemon del PC)
    `{"key_ops":["verify"],"ext":true,"kty":"EC","x":"${x}","y":"${y}","crv":"P-256"}`,
    // WebCrypto de navegador (Chrome/Firefox/Safari: alfabético)
    `{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"${x}","y":"${y}"}`
  ]
  for (const iss of forms) {
    const qr = await qrReal({ iss })
    const inv = encodeInvite(qr)
    assert.equal(inv[0], FMT_COMPACT, 'esta forma de JWK debería comprimirse')
    assert.equal(parseInvite(inv).iss, iss)
  }
})

test('lo que no se pueda comprimir SIN PERDER NADA cae a la forma larga', async () => {
  const iss = await jwkPub()
  const cases = {
    'JWK con una forma desconocida': { iss: JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'AAA', y: 'BBB' }) },
    'token que no es hex': { token: 'tok1' },
    'un campo que el codec no sabe escribir': { extra: 'no perder esto' },
    'nombre de cuenta imposible de largo': { acct: 'x'.repeat(300) },
    'modo desconocido': { m: 'otra-cosa' }
  }
  for (const [que, extra] of Object.entries(cases)) {
    const qr = { v: 2, iss, proxy: 'wss://proxy.dotrino.com', token: hex(12), sn: hex(12), m: 'join', ...extra }
    const inv = encodeInvite(qr)
    assert.equal(inv[0], FMT_B64, que)
    assert.deepEqual(parseInvite(inv), qr, `${que}: la forma larga no pierde nada`)
  }
})

test('proxy propio y cuenta sin nombre viajan bien', async () => {
  for (const extra of [{ proxy: 'wss://proxy.casa.example:8443/ws' }, { acct: undefined }, { m: 'adopt' }]) {
    const qr = await qrReal(extra)
    if (extra.acct === undefined) delete qr.acct
    assert.deepEqual(parseInvite(encodeInvite(qr)), qr, JSON.stringify(extra))
  }
})

test('token de 16 bytes (bóvedas anteriores) también comprime', async () => {
  const qr = await qrReal({ token: hex(16), sn: hex(16) })
  assert.equal(encodeInvite(qr)[0], FMT_COMPACT)
  assert.deepEqual(parseInvite(encodeInvite(qr)), qr)
})

test('el enlace del QR es seguro en una URL: el navegador no lo toca', async () => {
  const qr = await qrReal()
  const url = inviteUrl(qr)
  assert.ok(url.startsWith(PAIR_URL))
  assert.equal(encodeURI(url), url, 'nada que percent-codificar')
  assert.deepEqual(parseInvite(url), qr)
  assert.deepEqual(parseInvite(encodeURI(url)), qr)
})

test('lee la invitación dentro de una URL (corta o larga) y suelta', async () => {
  const qr = await qrReal()
  const inv = encodeInvite(qr)
  assert.deepEqual(parseInvite(PAIR_URL + inv), qr, 'enlace corto /d#v=')
  assert.deepEqual(parseInvite(URL_LONG + inv), qr, 'enlace largo /dispositivos#vault=')
  assert.deepEqual(parseInvite(inv), qr, 'código suelto')
  assert.deepEqual(parseInvite('  ' + inv + '  '), qr, 'con espacios alrededor')
})

test('los formatos VIEJOS se siguen leyendo', async () => {
  const qr = await qrReal({ token: 'a'.repeat(32), sn: 'b'.repeat(32) })
  const json = JSON.stringify(qr)
  const b64 = Buffer.from(json, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  assert.deepEqual(parseInvite(URL_LONG + b64), qr, 'base64 sin marca (0.7.6 y antes)')
  assert.deepEqual(parseInvite(json), qr, 'JSON pegado a pelo')
  assert.deepEqual(parseInvite(URL_LONG + json), qr, 'JSON crudo sin marca (0.7.8/0.7.9)')
  assert.deepEqual(parseInvite(URL_LONG + 'j' + json), qr, 'JSON crudo con marca (0.8.0)')
  assert.deepEqual(parseInvite(encodeURI(URL_LONG + 'j' + json)), qr, 'ese mismo, tras el navegador')
  assert.deepEqual(parseInvite(URL_LONG + 'b' + b64), qr, 'base64 con marca (0.8.0)')
})

test('lo que no es una invitación devuelve null, no explota', () => {
  const junkCases = ['', null, undefined, 'hola', '{roto', 'b###', 'j{no es json}', URL_LONG, PAIR_URL, '#vault=', '#v=',
    'c', 'cAAAA', 'c' + 'A'.repeat(200)]
  for (const junk of junkCases) assert.equal(parseInvite(junk), null, JSON.stringify(junk))
})

test('un punto que no está en la curva no se acepta como llave', async () => {
  const qr = await qrReal()
  const inv = encodeInvite(qr)
  // Estropear un byte de la coordenada `x`: casi nunca cae en la curva, y cuando
  // cae da otra llave — en los dos casos NO puede devolver la original.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  let broken = 0
  for (let i = 2; i < 20; i++) {
    const ch = inv[i]
    const other = alphabet[(alphabet.indexOf(ch) + 7) % alphabet.length]
    const tampered = inv.slice(0, i) + other + inv.slice(i + 1)
    const back = parseInvite(tampered)
    assert.notEqual(back?.iss, qr.iss, 'una invitación tocada no puede dar la llave original')
    if (back === null) broken++
  }
  assert.ok(broken > 0, 'al menos algunos puntos tocados se rechazan por no estar en la curva')
})

/**
 * La invitación CORTA (`t`): dirección + nonce, sin la llave. Es la que va a dejar el
 * QR en ~39×20; el mostrador de la bóveda ya la sabe servir (`vault.hello`) pero no la
 * emite hasta que el lado del dispositivo sepa pedirla — un QR no puede llevar las dos
 * formas, así que los dos lados tienen que ir juntos.
 */
test('la invitación corta lleva solo dirección y nonce', () => {
  const qr = { v: 2, conn: 'K7aB3x', sn: '0123456789abcdef', m: 'join', proxy: 'wss://proxy.dotrino.com' }
  const inv = encodeInvite(qr)
  assert.equal(inv[0], 't')
  // 21 caracteres, no 19: la cita del proxio pasó de 4 a 6 caracteres (lleva
  // delante el prefijo del nodo, que es lo que la hace resoluble desde otro
  // proxio). Son 2 bytes más de payload. Se pagan a gusto: lo que va en el QR
  // dejó de ser una dirección permanente y pasó a ser un código de UN SOLO USO
  // que caduca en minutos.
  assert.ok(inv.length <= 21, `la corta son ${inv.length} caracteres`)
  assert.ok(inviteUrl(qr).length <= 52, 'el enlace entero cabe en un QR chico')
  assert.deepEqual(parseInvite(inviteUrl(qr)), qr)
  assert.deepEqual(parseInvite(inv), qr)
})

test('la corta distingue el modo y no acepta basura', () => {
  const adopt = { v: 2, conn: 'M2zZ9!', sn: 'ffffffffffffffff', m: 'adopt', proxy: 'wss://proxy.dotrino.com' }
  assert.deepEqual(parseInvite(encodeInvite(adopt)), adopt)
  for (const junk of ['t', 'tAAAA', 't' + 'A'.repeat(60)]) assert.equal(parseInvite(junk), null, junk)
})

/**
 * REGRESIÓN: el token de conexión solo existe EN SU PROXY. Si el QR corto no lleva la
 * URL cuando no es la del ecosistema, el aparato se conecta al proxy público y le habla
 * a un token de otro servidor: el mensaje no llega y el emparejamiento se queda
 * esperando. Lo cazó el E2E de secretos, que levanta un proxy local.
 */
test('la corta lleva el proxy cuando no es el del ecosistema', () => {
  const own = { v: 2, conn: 'K7aB3x', sn: '0123456789abcdef', m: 'join', proxy: 'ws://127.0.0.1:8787' }
  const inv = encodeInvite(own)
  assert.equal(inv[0], 't')
  assert.deepEqual(parseInvite(inv), own, 'el proxy propio tiene que volver')
  // Y el del ecosistema NO viaja: se sobreentiende y no gasta módulos.
  const eco = { v: 2, conn: 'K7aB3x', sn: '0123456789abcdef', m: 'join', proxy: 'wss://proxy.dotrino.com' }
  assert.ok(encodeInvite(eco).length < inv.length)
})
