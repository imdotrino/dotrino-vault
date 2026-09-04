/**
 * ABRIR LA BÓVEDA DESDE EL ADMIN (`docs/abrir-a-distancia.md`).
 *
 * El modelo del dueño: *el admin abre la puerta en remoto, pero no tiene acceso a lo de
 * dentro*. Tú pones la contraseña, el admin pide, la bóveda hace el trabajo con su maestra.
 *
 * Lo que fija esta suite son los dos candados del sobre, que son DISTINTOS y hacen falta
 * los dos:
 *
 *   · el **nonce** hace que la bóveda se NIEGUE a atenderlo dos veces;
 *   · la **efímera** hace que no se PUEDA abrir dos veces — se tira al usarla, y ese sobre
 *     queda inabrible hasta para ella, incluso con el disco en la mano.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { makeEphemeralKey, seal, openSealed } from '../lib/src/sealed.js'
import { ADMIN_OPS, ADMIN_OPS_WHILE_LOCKED } from '../lib/src/admin.js'

const leer = (f) => fs.readFileSync(fileURLToPath(new URL('../' + f, import.meta.url)), 'utf8')

test('las dos operaciones existen y se atienden con el candado echado', () => {
  for (const op of ['unlock.begin', 'unlock']) {
    assert.ok(ADMIN_OPS.includes(op), `falta ${op} en la lista blanca`)
    assert.ok(ADMIN_OPS_WHILE_LOCKED.includes(op),
      `${op} tiene que atenderse cerrada: es lo único para lo que sirve`)
  }
})

test('el sobre va de ida: lo sella el admin, lo abre solo la bóveda', async () => {
  const eph = await makeEphemeralKey()               // la bóveda
  const enc = await seal({ ek: eph.ek, payload: { nonce: 'n-1', key: 'ZGVyaXZhZGE=' } })
  const dentro = await openSealed({ privateKey: eph.privateKey, enc })
  assert.equal(dentro.nonce, 'n-1')
  assert.equal(dentro.key, 'ZGVyaXZhZGE=')

  // Y otra efímera no lo abre: el sobre es para ESA bóveda y ese momento.
  const otra = await makeEphemeralKey()
  await assert.rejects(() => openSealed({ privateKey: otra.privateKey, enc }))
})

/**
 * EL NONCE VA DENTRO. Si fuera solo por fuera, un sobre capturado se reenvía con un nonce
 * nuevo y el candado del nonce no sirve de nada — lo único que quedaría es la efímera.
 */
test('el nonce se compara contra el de DENTRO del sobre', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('async open ({ nonce, enc, by })')
  assert.notEqual(i, -1, 'el mostrador de apertura tiene que existir')
  const cuerpo = src.slice(i, i + 2000)
  assert.match(cuerpo, /payload\.nonce !== nonce/, 'se compara con el de dentro')
  const abre = cuerpo.indexOf('openSealed(')
  const compara = cuerpo.indexOf('payload.nonce !== nonce')
  assert.ok(abre !== -1 && abre < compara, 'primero se abre el sobre, después se compara')
})

test('la efímera se tira ANTES de usarla: un segundo intento no tiene con qué', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('async open ({ nonce, enc, by })')
  const cuerpo = src.slice(i, i + 2000)
  const saca = cuerpo.indexOf("aperturas.get('pendiente')")
  const borra = cuerpo.indexOf("aperturas.delete('pendiente')")
  const abre = cuerpo.indexOf('openSealed(')
  assert.ok(saca < borra && borra < abre,
    'se borra antes de abrir: si se borrara después, un fallo dejaría la llave viva')
})

test('la derivada se borra de memoria pase lo que pase', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('async open ({ nonce, enc, by })')
  const cuerpo = src.slice(i, i + 2000)
  assert.match(cuerpo, /finally \{\s*derivada\.fill\(0\)/,
    'vale tanto como la contraseña: no se queda en memoria ni cuando falla')
})

/**
 * EL FRENO VIAJA CON EL RECHAZO. Sin él, el admin reintenta contra una puerta que ya no
 * responde y no sabe por qué — que es exactamente el silencio del que venimos.
 */
test('el rechazo lleva el freno', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('async open ({ nonce, enc, by })')
  const cuerpo = src.slice(i, i + 2000)
  assert.match(cuerpo, /tries: e\.tries/, 'cuántos intentos van')
  assert.match(cuerpo, /waitSec: e\.waitSec/, 'y cuánto hay que esperar')
})

/**
 * LA BÓVEDA NO VE LA CONTRASEÑA. El molino lo hace el admin y aquí llega la derivada. La
 * prueba concreta: este camino **no llama a `deriveAdminKey`**, que es la función que
 * recibiría una contraseña en claro. (El texto «admin password» sí aparece, en el mensaje
 * que se le da a quien no la tiene puesta — eso es copy, no un dato.)
 */
test('la bóveda nunca recibe la contraseña, solo lo que sale del molino', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('const unlockDesk =')
  const cuerpo = src.slice(i, i + 3200)
  assert.match(cuerpo, /payload\.key/, 'lo que llega es la derivada')
  assert.ok(!cuerpo.includes('deriveAdminKey'),
    'si apareciera, es que alguien mandó la contraseña en vez de derivarla fuera')
})

test('sin contraseña de admin no se puede abrir a distancia, y se dice', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('async begin ({ by })')
  const cuerpo = src.slice(i, i + 700)
  assert.match(cuerpo, /has no admin password/, 'se enciende a propósito, no viene puesto')
})
