/**
 * QUÉ VERSIÓN CORRE CADA UNO, Y QUE SE VEA (CONVENCIONES §14, dueño 2026-09-04).
 *
 * El agujero: una incompatibilidad de versiones se manifestaba como SILENCIO. El que
 * llamaba no sabía si estábamos apagados, ocupados o hablando otro idioma, así que
 * reintentaba para siempre — el apagón del 1-2 de septiembre duró un día entero así.
 *
 * Esto **informa, no bloquea**: no puede haber ni un `if` que deje de atender por el
 * dictamen. Si algún día se decide bloquear, se decide arriba y se escribe a propósito.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { declare, check, annotate } from '@dotrino/compat'
import { loadManifest, brokenOf, currentOf } from '@dotrino/roadmap'
import { VAULT_PROTOCOL, VAULT_SPEAKS } from '../lib/src/protocol.js'
import { MY_VERSION } from '../lib/src/service.js'

const raiz = fileURLToPath(new URL('..', import.meta.url))
const leer = (f) => fs.readFileSync(raiz + f, 'utf8')

test('la bóveda y su cliente declaran lo mismo del cable', () => {
  assert.ok(Number.isInteger(VAULT_PROTOCOL))
  assert.ok(VAULT_SPEAKS.includes(VAULT_PROTOCOL), 'lo que hablas tiene que incluir lo tuyo')
  assert.equal(MY_VERSION.product, 'vault')
  assert.equal(MY_VERSION.protocol, VAULT_PROTOCOL)
  assert.match(MY_VERSION.version, /^\d+\.\d+\.\d+$/, 'sin versión no hay nada que enseñar')
})

test('el cliente mete su versión DENTRO de lo que firma, no en el envoltorio', () => {
  const src = leer('lib/src/service.js')
  const m = /const data = \{ op: 'secrets',[^\n]*\}/.exec(src)
  assert.ok(m, 'el cuerpo firmado de secrets tiene que existir')
  assert.match(m[0], /\bv: MY_VERSION\b/,
    'una versión que cualquiera puede escribir por fuera no es un inventario')
})

test('la bóveda apunta la versión donde YA comprueba la firma', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('const verifyChain = async (args)')
  assert.notEqual(i, -1, 'verifyChain va envuelto: una comprobación copiada ocho veces son siete olvidos')
  const cuerpo = src.slice(i, i + 400)
  assert.match(cuerpo, /chk\.ok && args\?\.data\?\.v/, 'solo se apunta lo verificado')
  assert.match(cuerpo, /apuntarVersion/)
})

test('la bóveda anuncia lo suyo en cada respuesta', () => {
  const src = leer('src/vault.js')
  const i = src.indexOf('const reply = (to, obj) => {')
  assert.match(src.slice(i, i + 900), /v: MI_VERSION/)
})

test('se ve en la lista de dispositivos: en el mensaje y en la CLI', () => {
  const vault = leer('src/vault.js')
  assert.match(vault, /running: x\.sub \? versionDe\(x\.sub\) : null/, 'DEVICES_RESULT lleva lo que corre cada uno')
  assert.match(vault, /members: \(r\?\.members \|\| \[\]\)\.map\(\(m\) => \(\{ \.\.\.m, running: versionDe\(m\.pub\) \}\)\)/,
    'y el volcado del que sale `members`')
  assert.match(leer('src/ctl.js'), /⚠ corre %s · %s/, 'y la CLI lo enseña')
})

/**
 * LA LÍNEA QUE NO SE CRUZA. Bloquear sería código nuevo decidiendo si algo funciona: una
 * errata en un manifiesto pasaría de aviso falso a caída real. Y en los tres incidentes que
 * originaron esto lo que faltó fue enterarse, no parar.
 */
test('el dictamen NO corta a nadie: informa', () => {
  const vault = leer('src/vault.js')
  const i = vault.indexOf('const apuntarVersion')
  const cuerpo = vault.slice(i, i + 600)
  assert.doesNotMatch(cuerpo, /return reply\(|MSG\.ERROR/,
    'apuntar una versión no puede contestar que no')
  assert.doesNotMatch(vault, /if \(!dictamen\.compatible\)\s*return/, 'ni cortar en ningún sitio')
})

test('la lista de rotas sale del registro común, que viaja con esta versión', () => {
  const vault = leer('src/vault.js')
  assert.match(vault, /brokenOf\(loadManifest\(\)\)/)
  const m = loadManifest()
  assert.ok(Array.isArray(brokenOf(m)))
  assert.ok(currentOf(m, 'vaultd'), 'el registro tiene que conocer a la bóveda')
})

test('el dictamen se le puede pegar a un error, que es donde se pierde la tarde', () => {
  const mia = declare({ product: 'vaultd', version: '0.107.0', protocol: VAULT_PROTOCOL, speaks: VAULT_SPEAKS })
  const suya = declare({ product: 'vault', version: '0.33.2', protocol: VAULT_PROTOCOL, speaks: VAULT_SPEAKS })
  const d = check({ mine: mia, theirs: suya, broken: brokenOf(loadManifest()) })
  assert.equal(d.compatible, false, 'la 0.33.2 está marcada rota en el registro')
  const msg = annotate('invalid cert: no-acta', d)
  assert.ok(msg.startsWith('invalid cert: no-acta'), 'el mensaje original no se toca')
  assert.match(msg, /heads up:/)
})
