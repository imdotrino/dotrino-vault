/**
 * LA CONSOLA NO CORRE UNA COPIA VIEJA DE SU PROPIO `lib/`.
 *
 * `web/` (vault.dotrino.com) consume `@dotrino/vault` desde npm aunque el paquete se
 * construya en este mismo repo, y tiene que ser así: `admin.js` importa
 * `@dotrino/identity/content` por su nombre, y ese nombre se resuelve desde donde vive el
 * archivo — en CI solo se instala `web/`, así que importarlo de `../../lib/src` deja el
 * build sin `node_modules` donde mirar. Se probó, y el deploy se cayó.
 *
 * El precio de eso es un número que hay que mover a mano, y los números que se mueven a
 * mano se quedan quietos: la consola corrió 0.50 con el `lib/` en 0.52 durante dos
 * versiones. Nadie lo vio porque el `package.json` no miente — dice exactamente lo viejo
 * que es, y justo por eso nadie lo lee.
 *
 * Esta prueba lo lee.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = join(dirname(fileURLToPath(import.meta.url)), '..')
const leer = async (p) => JSON.parse(await readFile(join(repo, p), 'utf8'))

test('web pinea el @dotrino/vault de este repo, no uno anterior', async () => {
  const lib = (await leer('lib/package.json')).version
  const pin = (await leer('web/package.json')).dependencies['@dotrino/vault']
  assert.equal(pin, lib,
    `web/package.json pinea @dotrino/vault ${pin} y lib/ va por ${lib}. ` +
    'Publica lib y sube el pin (o baja el de lib, si aún no salió).')
})

/**
 * Y el pin es EXACTO. Con `^` el build de CI se trae lo último que haya en npm, que puede
 * no ser lo que dice este repo — y entonces la comprobación de arriba pasa mientras la
 * consola corre otra cosa. Es además lo que manda CONVENCIONES §1.1 (`save-exact`).
 */
test('el pin es exacto, sin ^ ni ~', async () => {
  const pin = (await leer('web/package.json')).dependencies['@dotrino/vault']
  assert.match(pin, /^\d+\.\d+\.\d+$/, `el pin de @dotrino/vault no es exacto: ${pin}`)
})
