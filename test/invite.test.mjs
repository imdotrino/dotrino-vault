/**
 * La invitación de emparejamiento y su MARCA DE FORMATO.
 *
 * El QR lleva JSON crudo (`j`) porque cada carácter son módulos; el código que se
 * copia y se pega lleva base64url (`b`) porque lo toca una persona. La marca dice
 * cuál es cuál: el lector no adivina.
 *
 * El caso que hay que blindar: el navegador PERCENT-CODIFICA el JSON del fragmento
 * (`{` `}` `"` no son legales en una URI), así que lo que llega a `location.hash`
 * no es lo que se emitió. Si eso no se deshace, emparejar muere con «ese código no
 * vale» — pasó de verdad, medido en un navegador (2026-07-28).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeInvite, parseInvite, FMT_JSON, FMT_B64 } from '../lib/src/invite.js'

const QR = {
  v: 2,
  iss: JSON.stringify({ key_ops: ['verify'], ext: true, kty: 'EC', x: 'AAA', y: 'BBB', crv: 'P-256' }),
  proxy: 'wss://proxy.dotrino.com',
  token: 'a'.repeat(32),
  sn: 'b'.repeat(32),
  m: 'join',
  acct: 'Perfil 1'
}
const URL_BASE = 'https://vault.dotrino.com/dispositivos#vault='

test('la marca dice el formato: `j` JSON crudo, `b` base64url', () => {
  assert.equal(encodeInvite(QR, FMT_JSON)[0], 'j')
  assert.equal(encodeInvite(QR, FMT_B64)[0], 'b')
  assert.match(encodeInvite(QR, FMT_B64).slice(1), /^[A-Za-z0-9_-]+$/, 'el pegable no lleva comillas ni llaves')
  assert.deepEqual(parseInvite(encodeInvite(QR, FMT_JSON)), QR)
  assert.deepEqual(parseInvite(encodeInvite(QR, FMT_B64)), QR)
})

test('el JSON crudo es más corto que el base64 (que es el punto del QR)', () => {
  assert.ok(encodeInvite(QR, FMT_JSON).length < encodeInvite(QR, FMT_B64).length)
})

test('sobrevive a lo que el NAVEGADOR le hace al fragmento', () => {
  const url = URL_BASE + encodeInvite(QR, FMT_JSON)
  // Así queda la URL tras pasar por el navegador: comillas y llaves percent-codificadas.
  const comoLoDaElNavegador = encodeURI(url)
  assert.notEqual(comoLoDaElNavegador, url, 'el navegador SÍ lo toca (si no, este test no prueba nada)')
  assert.deepEqual(parseInvite(comoLoDaElNavegador), QR)
  // Y también si solo llega el fragmento, ya codificado.
  assert.deepEqual(parseInvite('#vault=' + encodeURIComponent(encodeInvite(QR, FMT_JSON))), QR)
})

test('lee las dos formas dentro de una URL y sueltas', () => {
  for (const fmt of [FMT_JSON, FMT_B64]) {
    assert.deepEqual(parseInvite(URL_BASE + encodeInvite(QR, fmt)), QR, `URL con ${fmt}`)
    assert.deepEqual(parseInvite(encodeInvite(QR, fmt)), QR, `código suelto ${fmt}`)
    assert.deepEqual(parseInvite('  ' + encodeInvite(QR, fmt) + '  '), QR, `con espacios ${fmt}`)
  }
})

test('los formatos VIEJOS (sin marca) se siguen leyendo', () => {
  const json = JSON.stringify(QR)
  const b64 = Buffer.from(json, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  assert.deepEqual(parseInvite(URL_BASE + b64), QR, 'base64 sin marca (enlaces de 0.7.6 y antes)')
  assert.deepEqual(parseInvite(json), QR, 'JSON pegado a pelo')
  assert.deepEqual(parseInvite(URL_BASE + json), QR, 'JSON crudo sin marca (0.7.8/0.7.9)')
  assert.deepEqual(parseInvite(encodeURI(URL_BASE + json)), QR, 'ese mismo, tras el navegador')
})

test('lo que no es una invitación devuelve null, no explota', () => {
  for (const basura of ['', null, undefined, 'hola', '{roto', 'b###', 'j{no es json}', URL_BASE, '#vault=']) {
    assert.equal(parseInvite(basura), null, JSON.stringify(basura))
  }
})
