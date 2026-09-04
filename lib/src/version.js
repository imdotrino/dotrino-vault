/**
 * version.js — la versión de `@dotrino/vault` (el CLIENTE, no el daemon).
 *
 * Existe porque el cliente tiene que poder decir qué versión es (CONVENCIONES §14), y esta
 * es justo la pieza que se quedaba atrás sin que nadie se enterara: `@dotrino/env` pedía
 * `^0.33.2` con la librería en 0.60, y enrolar contestaba `invalid cert: no-acta` — verdad,
 * y no la causa.
 *
 * Se lee del `package.json` que viaja con el paquete. Si no se puede leer se dice `0.0.0`,
 * que es un número imposible y por tanto legible como «no lo sé» — no se inventa uno
 * plausible, que sería peor que no decir nada.
 */
import fs from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

function leer () {
  try {
    const aqui = dirname(fileURLToPath(import.meta.url))
    for (const p of [join(aqui, '..', 'package.json'), join(aqui, '..', '..', 'package.json')]) {
      try {
        const v = JSON.parse(fs.readFileSync(p, 'utf8'))
        if (v?.name === '@dotrino/vault' && typeof v.version === 'string') return v.version
      } catch (_) {}
    }
  } catch (_) {}
  return '0.0.0'
}

export const PKG_VERSION = leer()
