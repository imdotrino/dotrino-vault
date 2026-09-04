/**
 * DOS MOSTRADORES QUE NO MIRABAN QUIÉN PREGUNTA (auditoría del 2026-09-04).
 *
 * Los dos tenían la misma forma, y por eso van juntos: la petición YA viajaba firmada y
 * con su papel —los manda el cliente en la misma llamada— y el que contestaba no los
 * miraba. No costaba un mensaje nuevo ni una llave más; costaba una línea en el orden
 * equivocado.
 *
 *   · `profileRecipients` (la bóveda) — contestado ANTES del control, así que cualquiera
 *     que supiera la llave de la cuenta, que es pública, se llevaba el inventario: cuántas
 *     máquinas tienes, sus llaves y la de recuperación.
 *   · `onSecrets` (el replicador) — sin ninguna comprobación, así que un extraño con una
 *     llave recién hecha se llevaba el sobre de un cajón ajeno y, dentro, el acta entera.
 *     Probado en vivo: `dotrino-test/smoke/replica.mjs`, «a un DESCONOCIDO…».
 *
 * El argumento que los dejó así es el mismo y suena razonable las dos veces: «lo que
 * entrego no se puede abrir / solo son llaves públicas». Es verdad y es la SEGUNDA línea.
 * No es una puerta: repartir a desconocidos regala el inventario y deja texto cifrado en
 * manos de cualquiera, para siempre y sin dejar rastro de quién se lo llevó.
 *
 * No se puede levantar aquí ni el proxio ni el navegador, así que se ata lo estable: el
 * ORDEN en que está escrito cada mostrador.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const raiz = fileURLToPath(new URL('..', import.meta.url))
const leer = (f) => fs.readFileSync(raiz + f, 'utf8')

/** El cuerpo de una función, desde su cabecera hasta la siguiente a ese nivel. */
const cuerpoDe = (src, cabecera) => {
  const i = src.indexOf(cabecera)
  assert.notEqual(i, -1, 'no existe «' + cabecera + '»')
  const resto = src.slice(i + cabecera.length)
  const fin = resto.search(/\n  (?:async function|function|const \w+ = async)/)
  return resto.slice(0, fin === -1 ? undefined : fin)
}

test('la bóveda no dice a quién envolver antes de saber quién pregunta', () => {
  const cuerpo = cuerpoDe(leer('src/vault.js'), 'async function handleProfile (')

  const control = cuerpo.indexOf('await verifyChain(')
  const acta = cuerpo.indexOf('actaAllows(')
  const rama = cuerpo.indexOf("d.method === 'profileRecipients'")
  assert.ok(control !== -1 && acta !== -1, 'handleProfile tiene que comprobar el papel y el acta')
  assert.ok(rama !== -1, 'handleProfile tiene que atender profileRecipients')
  assert.ok(control < rama, 'el inventario se entrega antes de comprobar el papel')
  assert.ok(acta < rama, 'el inventario se entrega antes de preguntarle al acta')

  // Lo PÚBLICO sí va delante, y tiene que seguir yendo: pedir un papel para leer lo que es
  // público sería contradecir lo que significa la palabra.
  const publico = cuerpo.indexOf("d.method === 'profilePublic'")
  assert.ok(publico !== -1 && publico < control, 'lo público no pide papel, y así se queda')
})

test('el replicador comprueba el papel, la frescura y el acta antes de entregar un cajón', () => {
  const cuerpo = cuerpoDe(leer('src/replica.js'), 'async function onSecrets (')

  const fresco = cuerpo.indexOf('FRESH_WINDOW_MS')
  const control = cuerpo.indexOf('await verifyChain(')
  const acta = cuerpo.indexOf('memberCanReadSecrets(')
  const entrega = cuerpo.indexOf('store.bundleFor(')
  for (const [q, i] of [['la frescura', fresco], ['el papel', control], ['el acta', acta]]) {
    assert.notEqual(i, -1, 'el replicador no comprueba ' + q)
    assert.ok(i < entrega, 'el replicador entrega el cajón antes de comprobar ' + q)
  }
})

test('un acta anunciada por un desconocido no entra en una bóveda sin acta propia', () => {
  const cuerpo = cuerpoDe(leer('src/vault.js'), 'async function handleAdminEvent (')
  assert.match(cuerpo, /profileActa/, 'hay que mirar si esta bóveda tiene acta propia')
  const mira = cuerpo.indexOf('profileActa')
  const adopta = cuerpo.indexOf('adoptActa')
  assert.ok(mira < adopta, 'se adopta antes de comprobar que hay con qué comparar')
})

/**
 * UNA RENUNCIA REPETIDA NO VUELVE A CONTAR.
 *
 * El registro va firmado por el propio miembro y solo puede QUITAR, así que honrarlo sin
 * papel es correcto. Lo que faltaba es que su `ts` no lo miraba nadie: quien lo viera pasar
 * por el proxio podía repetirlo cuando quisiera, y como absorberlo SELLA UN ACTA NUEVA,
 * cada repetición subía el `seq` y empujaba a todos los aparatos sin que cambiara nada —
 * dejando además en la bitácora una renuncia con el nombre de un aparato que no la hizo.
 *
 * Queda anotado lo que esto NO cierra: si el permiso se vuelve a conceder, el registro
 * viejo lo quita otra vez.
 */
test('una renuncia que no quita nada no se honra', () => {
  const cuerpo = cuerpoDe(leer('src/vault.js'), 'async function handleRenounce (')
  const mira = cuerpo.indexOf('effectiveCaps(')
  const absorbe = cuerpo.indexOf('absorbRenounce(')
  assert.notEqual(mira, -1, 'hay que mirar lo que el miembro tiene HOY')
  assert.ok(mira < absorbe, 'se absorbe antes de comprobar que hay algo que quitar')
  assert.match(cuerpo, /sin-acta/, 'y sin acta no se aplica nada')
})
